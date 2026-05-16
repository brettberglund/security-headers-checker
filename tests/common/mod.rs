use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

pub fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for &(name, value) in pairs {
        map.insert(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

/// Compare `json` to the golden file at `tests/golden/<golden_path>`.
/// Set env var `UPDATE_GOLDEN=1` to regenerate all golden files.
pub fn assert_golden(json: &serde_json::Value, golden_path: &str) {
    let path = format!(
        "{}/tests/golden/{}",
        env!("CARGO_MANIFEST_DIR"),
        golden_path
    );
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        let dir = std::path::Path::new(&path).parent().unwrap();
        std::fs::create_dir_all(dir).unwrap();
        let text = format!("{}\n", serde_json::to_string_pretty(json).unwrap());
        std::fs::write(&path, text).unwrap();
        return;
    }
    let content = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "golden file missing: {path}\nrun `UPDATE_GOLDEN=1 cargo test` to generate it"
        )
    });
    let expected: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(*json, expected, "golden mismatch for {path}");
}
