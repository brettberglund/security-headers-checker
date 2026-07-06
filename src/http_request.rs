use reqwest::blocking::Client;
use reqwest::header::HeaderMap;
use reqwest::redirect::Policy;
use url::Url;

const MAX_REDIRECTS: usize = 10;

#[allow(dead_code)]
pub struct RedirectHop {
    pub url: String,
    pub status_code: u16,
    pub headers: HeaderMap,
}

pub struct RequestResult {
    pub final_url: String,
    pub final_status_code: u16,
    pub final_headers: HeaderMap,
    pub redirect_chain: Vec<RedirectHop>,
    pub http_to_https: bool,
}

pub fn fetch(url: &str) -> Result<RequestResult, String> {
    let client = Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
        .redirect(Policy::none())
        .build()
        .map_err(|e| e.to_string())?;

    // Always probe the http:// equivalent first so we can detect http->https redirection
    let http_probe_url = to_http(url);
    let http_to_https = probes_http_to_https(&client, &http_probe_url);

    let mut current_url = url.to_string();
    let mut redirect_chain: Vec<RedirectHop> = Vec::new();

    for _ in 0..MAX_REDIRECTS {
        let response = client
            .get(&current_url)
            .send()
            .map_err(|e| format!("Request to '{}' failed: {}", current_url, e))?;

        let status = response.status();
        let headers = response.headers().clone();

        if status.is_redirection() {
            let location = headers
                .get(reqwest::header::LOCATION)
                .ok_or_else(|| format!("Redirect at '{}' has no Location header", current_url))?
                .to_str()
                .map_err(|e| format!("Invalid Location header: {}", e))?;

            let next_url = resolve_url(&current_url, location)?;

            redirect_chain.push(RedirectHop {
                url: current_url,
                status_code: status.as_u16(),
                headers,
            });

            current_url = next_url;
        } else {
            return Ok(RequestResult {
                final_url: current_url,
                final_status_code: status.as_u16(),
                final_headers: headers,
                redirect_chain,
                http_to_https,
            });
        }
    }

    Err(format!("Too many redirects (max {})", MAX_REDIRECTS))
}

/// Replace the scheme with http:// so we can probe for http->https redirection.
fn to_http(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("https://") {
        format!("http://{}", rest)
    } else {
        url.to_string()
    }
}

/// Send a single request to the http:// URL and return true if it redirects to https://.
fn probes_http_to_https(client: &Client, http_url: &str) -> bool {
    client
        .get(http_url)
        .send()
        .ok()
        .and_then(|r| {
            if r.status().is_redirection() {
                r.headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(|loc| loc.starts_with("https://"))
            } else {
                None
            }
        })
        .unwrap_or(false)
}

fn resolve_url(base: &str, location: &str) -> Result<String, String> {
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(location.to_string());
    }
    let base_url = Url::parse(base).map_err(|e| e.to_string())?;
    base_url
        .join(location)
        .map(|u| u.to_string())
        .map_err(|e| format!("Could not resolve redirect '{}': {}", location, e))
}
