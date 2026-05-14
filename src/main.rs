use security_headers_checker::{generate_html_report, run};

fn main() {
    let url = parse_args();
    let json_path = match run(&url) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };
    match generate_html_report(&json_path) {
        Ok(html_path) => println!("HTML report written to {html_path}"),
        Err(e) => {
            eprintln!("Warning: could not write HTML report: {e}");
        }
    }
}

fn parse_args() -> String {
    let args: Vec<String> = std::env::args().collect();

    if args.len() == 2 && (args[1] == "-h" || args[1] == "--help") {
        println!("Usage: security-headers-checker <url>");
        std::process::exit(0);
    }

    if args.len() != 2 {
        eprintln!("Usage: security-headers-checker <url>");
        std::process::exit(1);
    }

    args[1].clone()
}
