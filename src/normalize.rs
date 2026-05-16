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

#[cfg(test)]
mod tests {
    use super::normalize_url;

    #[test]
    fn prepends_https_to_plain_domain() {
        let r = normalize_url("example.com").unwrap();
        assert!(r.starts_with("https://example.com"), "got: {r}");
    }

    #[test]
    fn passes_through_https_url() {
        let r = normalize_url("https://example.com").unwrap();
        assert!(r.starts_with("https://example.com"));
    }

    #[test]
    fn passes_through_http_url() {
        let r = normalize_url("http://example.com").unwrap();
        assert!(r.starts_with("http://example.com"));
    }

    #[test]
    fn rejects_bare_word_without_dot() {
        let e = normalize_url("notadomain").unwrap_err();
        assert!(e.contains("valid domain"), "got: {e}");
    }

    #[test]
    fn accepts_localhost() {
        assert!(normalize_url("localhost").is_ok());
    }

    #[test]
    fn accepts_ip_address() {
        assert!(normalize_url("192.168.1.1").is_ok());
    }

    #[test]
    fn rejects_empty_string() {
        assert!(normalize_url("").is_err());
    }

    #[test]
    fn preserves_path_and_query() {
        let r = normalize_url("example.com/path?q=1").unwrap();
        assert!(r.contains("/path"), "got: {r}");
        assert!(r.contains("q=1"), "got: {r}");
    }

    #[test]
    fn accepts_port() {
        assert!(normalize_url("example.com:8080").is_ok());
    }

    #[test]
    fn accepts_subdomain() {
        assert!(normalize_url("api.example.com").is_ok());
    }

    #[test]
    fn accepts_deep_subdomain() {
        assert!(normalize_url("a.b.c.example.com").is_ok());
    }

    #[test]
    fn rejects_no_scheme_no_dot() {
        assert!(normalize_url("justalabel").is_err());
    }
}
