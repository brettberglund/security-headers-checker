use std::fs;

use crate::evaluation::{EvaluationResult, RedirectEntry};
use crate::header_checker::{CheckResult, CheckStatus, Severity};

pub fn html_report_filename(json_path: &str) -> String {
    json_path
        .strip_suffix(".json")
        .map(|s| format!("{s}.html"))
        .unwrap_or_else(|| format!("{json_path}.html"))
}

pub fn generate_html_report(json_path: &str) -> Result<String, String> {
    let json =
        fs::read_to_string(json_path).map_err(|e| format!("Failed to read '{json_path}': {e}"))?;
    let result: EvaluationResult =
        serde_json::from_str(&json).map_err(|e| format!("Failed to parse report JSON: {e}"))?;
    let html = render_html(&result);
    let html_path = html_report_filename(json_path);
    fs::write(&html_path, &html).map_err(|e| format!("Failed to write '{html_path}': {e}"))?;
    Ok(html_path)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn grade_color(grade: &str) -> &'static str {
    match grade {
        "A+" => "#00c853",
        "A" => "#4caf50",
        "B" => "#8bc34a",
        "C" => "#ffc107",
        "D" => "#ff9800",
        _ => "#f44336",
    }
}

fn severity_badge(severity: &Severity) -> String {
    let (bg, fg, label) = match severity {
        Severity::Critical => ("#b71c1c", "#fff", "Critical"),
        Severity::High => ("#e53935", "#fff", "High"),
        Severity::Medium => ("#fb8c00", "#fff", "Medium"),
        Severity::Low => ("#f9a825", "#333", "Low"),
        Severity::Info => ("#5c6bc0", "#fff", "Info"),
    };
    format!(r#"<span class="badge" style="background:{bg};color:{fg}">{label}</span>"#)
}

fn status_badge(status: &CheckStatus) -> String {
    let (bg, fg, label) = match status {
        CheckStatus::Present => ("#43a047", "#fff", "Present"),
        CheckStatus::Missing => ("#e53935", "#fff", "Missing"),
        CheckStatus::Misconfigured => ("#fb8c00", "#fff", "Misconfigured"),
        CheckStatus::Deprecated => ("#757575", "#fff", "Deprecated"),
    };
    format!(r#"<span class="badge" style="background:{bg};color:{fg}">{label}</span>"#)
}

fn render_redirect_chain(chain: &[RedirectEntry]) -> String {
    if chain.is_empty() {
        return String::new();
    }
    let rows: String = chain
        .iter()
        .enumerate()
        .map(|(i, hop)| {
            format!(
                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
                i + 1,
                html_escape(&hop.url),
                hop.status_code
            )
        })
        .collect();
    format!(
        r#"<section class="section">
      <h2>Redirect Chain</h2>
      <table>
        <thead><tr><th>#</th><th>URL</th><th>Status</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </section>"#
    )
}

fn render_result_row(r: &CheckResult) -> String {
    let value_cell = match &r.value {
        Some(v) => format!("<code class=\"value\">{}</code>", html_escape(v)),
        None => "<span class=\"none\">—</span>".to_string(),
    };
    let refs_cell = if r.references.is_empty() {
        "<span class=\"none\">—</span>".to_string()
    } else {
        r.references
            .iter()
            .map(|url| {
                format!(
                    r#"<a href="{}" target="_blank" rel="noopener">{}</a>"#,
                    html_escape(url),
                    html_escape(url)
                )
            })
            .collect::<Vec<_>>()
            .join("<br>")
    };
    format!(
        "<tr>\
          <td><strong>{header}</strong></td>\
          <td>{status}</td>\
          <td>{severity}</td>\
          <td>{value}</td>\
          <td>{message}</td>\
          <td>{remediation}</td>\
          <td class=\"refs-cell\">{refs}</td>\
        </tr>",
        header = html_escape(&r.header),
        status = status_badge(&r.status),
        severity = severity_badge(&r.severity),
        value = value_cell,
        message = html_escape(&r.message),
        remediation = html_escape(&r.remediation),
        refs = refs_cell,
    )
}

fn render_html(result: &EvaluationResult) -> String {
    let grade_color = grade_color(&result.grade);
    let http_to_https_html = if result.http_to_https {
        r#"<span class="badge" style="background:#43a047;color:#fff">Yes</span>"#
    } else {
        r#"<span class="badge" style="background:#e53935;color:#fff">No</span>"#
    };
    let redirect_chain_html = render_redirect_chain(&result.redirect_chain);
    let result_rows: String = result.results.iter().map(render_result_row).collect();
    let url_escaped = html_escape(&result.url);
    let scanned_at_escaped = html_escape(&result.scanned_at);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Headers Report &mdash; {url_escaped}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 14px;
      color: #212121;
      background: #f5f5f5;
    }}
    header {{
      background: #1a237e;
      color: #fff;
      padding: 24px 32px;
    }}
    header h1 {{
      margin: 0 0 4px;
      font-size: 22px;
      font-weight: 600;
    }}
    header .url {{
      margin: 0;
      font-size: 14px;
      opacity: 0.8;
      word-break: break-all;
    }}
    main {{
      max-width: 1400px;
      margin: 0 auto;
      padding: 24px 32px;
    }}
    .summary {{
      display: flex;
      align-items: center;
      gap: 32px;
      background: #fff;
      border-radius: 8px;
      padding: 24px 32px;
      margin-bottom: 24px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.12);
    }}
    .grade-block {{
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 4px;
    }}
    .grade {{
      font-size: 56px;
      font-weight: 700;
      line-height: 1;
      color: {grade_color};
    }}
    .score {{
      font-size: 16px;
      color: #555;
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      flex: 1;
    }}
    .meta-item {{
      display: flex;
      flex-direction: column;
      gap: 4px;
    }}
    .meta-label {{
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #757575;
    }}
    .meta-value {{
      font-size: 14px;
      color: #212121;
    }}
    .section {{
      background: #fff;
      border-radius: 8px;
      padding: 24px 32px;
      margin-bottom: 24px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.12);
    }}
    h2 {{
      margin: 0 0 16px;
      font-size: 16px;
      font-weight: 600;
      color: #1a237e;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    thead tr {{
      background: #e8eaf6;
    }}
    th {{
      text-align: left;
      padding: 10px 12px;
      font-weight: 600;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: #3949ab;
      white-space: nowrap;
    }}
    td {{
      padding: 10px 12px;
      border-bottom: 1px solid #eeeeee;
      vertical-align: top;
    }}
    tr:last-child td {{
      border-bottom: none;
    }}
    tr:hover td {{
      background: #fafafa;
    }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 600;
      white-space: nowrap;
    }}
    code.value {{
      display: block;
      max-width: 240px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-family: "SFMono-Regular", Consolas, monospace;
      font-size: 12px;
      color: #37474f;
      background: #eceff1;
      padding: 2px 6px;
      border-radius: 4px;
    }}
    .refs-cell a {{
      display: block;
      color: #1565c0;
      text-decoration: none;
      font-size: 12px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 220px;
    }}
    .refs-cell a:hover {{
      text-decoration: underline;
    }}
    .none {{
      color: #bdbdbd;
    }}
    footer {{
      text-align: center;
      padding: 16px;
      font-size: 12px;
      color: #9e9e9e;
    }}
  </style>
</head>
<body>
  <header>
    <h1>Security Headers Report</h1>
    <p class="url">{url_escaped}</p>
  </header>
  <main>
    <div class="summary">
      <div class="grade-block">
        <span class="grade">{grade}</span>
        <span class="score">{score} / 100</span>
      </div>
      <div class="meta-grid">
        <div class="meta-item">
          <span class="meta-label">Scanned</span>
          <span class="meta-value">{scanned_at}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">HTTP → HTTPS</span>
          <span class="meta-value">{http_to_https}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Headers Checked</span>
          <span class="meta-value">{header_count}</span>
        </div>
      </div>
    </div>
    {redirect_chain}
    <section class="section">
      <h2>Header Analysis</h2>
      <table>
        <thead>
          <tr>
            <th>Header</th>
            <th>Status</th>
            <th>Severity</th>
            <th>Value</th>
            <th>Finding</th>
            <th>Remediation</th>
            <th>References</th>
          </tr>
        </thead>
        <tbody>
          {rows}
        </tbody>
      </table>
    </section>
  </main>
  <footer>
    <p>Generated by security-headers-checker &mdash; {scanned_at}</p>
  </footer>
</body>
</html>"#,
        url_escaped = url_escaped,
        grade_color = grade_color,
        grade = html_escape(&result.grade),
        score = result.score,
        scanned_at = scanned_at_escaped,
        http_to_https = http_to_https_html,
        header_count = result.results.len(),
        redirect_chain = redirect_chain_html,
        rows = result_rows,
    )
}
