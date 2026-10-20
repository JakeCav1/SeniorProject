use std::{env, fs, path::PathBuf};
fn main() {
    println!("cargo:rerun-if-changed=rules");
    let mut files: Vec<_> = fs::read_dir("rules")
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| {
            e.file_type().unwrap().is_file()
                && e.path()
                    .extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.eq_ignore_ascii_case("yaml"))
        })
        .map(|e| e.path())
        .collect();
    files.sort();
    let mut generated = String::from("const BUNDLED_RULES: &[(&str, &str)] = &[\n");
    for path in files {
        let name = path.file_name().unwrap().to_str().unwrap();
        let yaml = fs::read_to_string(&path).unwrap();
        generated.push_str(&format!("({name:?}, {yaml:?}),\n"));
    }
    generated.push_str("];\n");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("bundled_rules.rs"),
        generated,
    )
    .unwrap();
}
