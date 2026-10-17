//! Bounded event-time correlation. Each scan creates a fresh session.
use crate::{Engine, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedSession {
    groups: Vec<SavedGroup>,
    last_time: Option<i64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedGroup {
    rule: String,
    values: Vec<String>,
    times: VecDeque<i64>,
    expires: i64,
}

pub struct Session {
    engine: Engine,
    groups: HashMap<(String, Vec<String>), (VecDeque<i64>, i64)>,
    last_time: Option<i64>,
}

impl Session {
    pub(crate) fn save(&self) -> SavedSession {
        SavedSession {
            last_time: self.last_time,
            groups: self
                .groups
                .iter()
                .map(|((rule, values), (times, expires))| SavedGroup {
                    rule: rule.clone(),
                    values: values.clone(),
                    times: times.clone(),
                    expires: *expires,
                })
                .collect(),
        }
    }

    pub(crate) fn restore(engine: Engine, saved: SavedSession) -> Result<Self> {
        if saved.groups.len() > 4096 {
            return Err("checkpoint has too many groups".into());
        }
        let mut session = Self::new(engine);
        session.last_time = saved.last_time;
        for g in saved.groups {
            let t = session
                .engine
                .rules()
                .find(|r| r.id == g.rule && r.enabled)
                .and_then(|r| r.threshold.as_ref())
                .ok_or("invalid checkpoint rule")?;
            let now = saved
                .last_time
                .ok_or("checkpoint groups require a timestamp")?;
            let window = i64::from(t.window_seconds) * 1000;
            if g.values.len() != t.group_by.len()
                || g.values.iter().any(|s| s.is_empty() || s.len() > 256)
                || g.times.is_empty()
                || g.times.len() > t.count
                || g.times.iter().any(|v| *v > now)
                || !g
                    .times
                    .iter()
                    .zip(g.times.iter().skip(1))
                    .all(|(a, b)| a <= b)
                || g.times.back().and_then(|v| v.checked_add(window)) != Some(g.expires)
                || g.expires < now
                || g.times
                    .front()
                    .is_some_and(|v| g.times.back().unwrap().saturating_sub(*v) > window)
            {
                return Err("invalid checkpoint correlation group".into());
            }
            if session
                .groups
                .insert((g.rule, g.values), (g.times, g.expires))
                .is_some()
            {
                return Err("duplicate checkpoint group".into());
            }
        }
        Ok(session)
    }
    pub fn new(engine: Engine) -> Self {
        Self {
            engine,
            groups: HashMap::new(),
            last_time: None,
        }
    }

    pub fn process(&mut self, event: &Value) -> Result<Vec<Value>> {
        let timed = self
            .engine
            .rules()
            .any(|r| r.enabled && r.threshold.is_some());
        let now = if timed {
            let text = event
                .get("timestamp")
                .and_then(Value::as_str)
                .ok_or("threshold scans require an RFC3339 timestamp on every event")?;
            let now = chrono::DateTime::parse_from_rfc3339(text)
                .map_err(|_| "invalid event timestamp")?
                .timestamp_millis();
            if self.last_time.is_some_and(|last| now < last) {
                return Err("out-of-order event timestamp; sort events before scanning".into());
            }
            Some(now)
        } else {
            None
        };
        // Prevalidate candidates so malformed grouping data cannot partially update state.
        let candidates = self.engine.candidates(event);
        let mut prepared = Vec::new();
        for alert in candidates {
            let rule = self.engine.rules().find(|r| r.id == alert.rule_id).unwrap();
            let mut group = Vec::new();
            if let Some(t) = &rule.threshold {
                for path in &t.group_by {
                    let mut value = event;
                    for part in path.split('.') {
                        value = value
                            .get(part)
                            .ok_or_else(|| format!("missing group field: {path}"))?;
                    }
                    let text = value
                        .as_str()
                        .filter(|s| !s.is_empty() && s.len() <= 256)
                        .ok_or_else(|| {
                            format!(
                                "group field {path} must be a nonempty string of at most 256 bytes"
                            )
                        })?;
                    group.push(text.to_owned());
                }
            }
            prepared.push((alert, rule, group));
        }
        if let Some(now) = now {
            self.groups.retain(|_, (_, expires)| *expires >= now);
        }
        let new_groups = prepared
            .iter()
            .filter(|(a, r, g)| {
                r.threshold.is_some()
                    && !self.groups.contains_key(&(a.rule_id.to_owned(), g.clone()))
            })
            .count();
        if self.groups.len() + new_groups > 4096 {
            return Err("correlation capacity exceeded (4096 active rule/group pairs)".into());
        }
        self.last_time = now;
        let mut alerts = Vec::new();
        for (alert, rule, group) in prepared {
            let mut output = serde_json::to_value(&alert).map_err(|e| e.to_string())?;
            if let Some(t) = &rule.threshold {
                let now = now.unwrap();
                let window = i64::from(t.window_seconds) * 1000;
                let (times, expires) = self
                    .groups
                    .entry((rule.id.clone(), group.clone()))
                    .or_default();
                while times.front().is_some_and(|v| *v < now - window) {
                    times.pop_front();
                }
                let previously_at_threshold = times.len() >= t.count;
                times.push_back(now);
                while times.len() > t.count {
                    times.pop_front();
                }
                *expires = now + window;
                if times.len() < t.count || previously_at_threshold {
                    continue;
                }
                output["correlation"] = json!({"count":t.count,"window_seconds":t.window_seconds,
                    "group_by":t.group_by,"group_values":group,"first_timestamp_ms":times[0]});
            }
            alerts.push(output);
        }
        Ok(alerts)
    }
}
