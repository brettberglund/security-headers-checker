use url::{Host, Url};

pub fn normalize_url(input: &str) -> Result<String, String> {
    let norm_url = if input.starts_with("https://") || input.starts_with("http://") {
        input.to_string()
    } else {
        format!("https://{}", input)
    };

    Url::parse(&norm_url)
        .map_err(|e| format!("Invalid URL '{}': {}", input, e))
        .and_then(|u| match u.host() {
            None => Err(format!("URL has no host: '{}'", input)),
            Some(Host::Domain(d)) => {
                if d != "localhost" && !d.contains('.') {
                    Err(format!(
                        "'{}' is not a valid domain — did you mean '{}.com'?",
                        input, d
                    ))
                } else {
                    Ok(u.to_string())
                }
            }
            Some(_) => Ok(u.to_string()),
        })
}
