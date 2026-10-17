//! Deployment files and documented operator commands stay consistent with this build.
use std::{fs, path::Path};

fn repository(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap()
}

/// Dotted three-part numbers that name a Hashstash release, such as
/// "Hashstash 0.42.0", "version=0.42.0" or "/opt/hashstash/0.42.0-". Other
/// products' versions (nginx, systemd) may appear; IPv4 addresses have four parts.
fn release_numbers(text: &str) -> Vec<&str> {
    const CONTEXTS: [&str; 5] = ["hashstash ", "hashstash/", "version ", "version=", "release "];
    let lower = text.to_ascii_lowercase();
    let mut found = Vec::new();
    let mut start = None;
    for (index, c) in text.char_indices().chain([(text.len(), ' ')]) {
        if c.is_ascii_digit() || c == '.' {
            start.get_or_insert(index);
            continue;
        }
        let Some(begin) = start.take() else { continue };
        let run = text[begin..index].trim_start_matches('.');
        let begin = index - run.len();
        let run = run.trim_end_matches('.');
        let parts: Vec<_> = run.split('.').collect();
        if parts.len() == 3
            && parts.iter().all(|part| !part.is_empty())
            && CONTEXTS.iter().any(|context| lower[..begin].ends_with(context))
        {
            found.push(run);
        }
    }
    found
}

#[test]
fn linux_installer_accepts_exactly_this_release() {
    assert_eq!(
        release_numbers("Hashstash 0.41.0 behind nginx 1.15.7 at 10.0.0.1, version=0.40.1."),
        ["0.41.0", "0.40.1"]
    );
    let version = env!("CARGO_PKG_VERSION");
    let installer = repository("deploy/linux/install.sh");
    assert!(
        installer.lines().any(|line| line == format!("version={version}")),
        "install.sh must pin the Cargo.toml version"
    );
    for path in ["deploy/linux/install.sh", "deploy/linux/README.md"] {
        let text = repository(path);
        let found = release_numbers(&text);
        assert!(!found.is_empty(), "{path} names no release");
        for release in found {
            assert_eq!(release, version, "{path} names another release");
        }
    }
}

#[test]
fn systemd_unit_confines_the_node() {
    let unit = repository("deploy/linux/hashstash.service");
    for directive in [
        "NoNewPrivileges=true",
        "CapabilityBoundingSet=",
        "SystemCallFilter=@system-service",
        "SystemCallArchitectures=native",
        "RestrictNamespaces=true",
        "MemoryDenyWriteExecute=true",
        "LockPersonality=true",
        "ProtectProc=invisible",
        "ProcSubset=pid",
        "LimitCORE=0",
    ] {
        assert!(unit.lines().any(|line| line == directive), "missing {directive}");
    }
}

#[test]
fn documented_stratum_advertisements_are_bare_endpoints() {
    let mut documents = vec![
        "README.md".to_owned(),
        "deploy/linux/README.md".to_owned(),
        "deploy/linux/node.env.example".to_owned(),
    ];
    for entry in fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs")).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if name.ends_with(".md") {
            documents.push(format!("docs/{name}"));
        }
    }
    let mut checked = 0;
    for path in documents {
        let text = repository(&path);
        for marker in ["--stratum-advertise ", "STRATUM_ADVERTISE="] {
            for (index, _) in text.match_indices(marker) {
                let value: String = text[index + marker.len()..]
                    .chars()
                    .take_while(|c| !c.is_whitespace() && *c != '`')
                    .collect();
                // The node rejects schemes and other URL syntax at startup.
                let endpoint = value.rsplit_once(':').filter(|(host, port)| {
                    !host.is_empty()
                        && !host.contains(['/', '\\', '?', '#', '@', '%'])
                        && port.parse::<u16>().is_ok_and(|port| port > 0)
                });
                assert!(endpoint.is_some(), "{path}: {value} must be HOST:PORT");
                checked += 1;
            }
        }
    }
    assert!(checked >= 2, "documented advertisements were not found");
}

#[test]
fn public_web_proxy_limits_json_rpc_per_client() {
    let template = repository("deploy/linux/public-web.nginx.template");
    let rate = template
        .lines()
        .find_map(|line| {
            line.strip_prefix("limit_req_zone $binary_remote_addr zone=hashstash_rpc:10m rate=")
        })
        .and_then(|rest| rest.strip_suffix("r/s;"))
        .and_then(|rate| rate.parse::<u32>().ok())
        .expect("per-client JSON-RPC rate");
    // All proxied visitors share one node work budget of about 30 transaction
    // preparations per second; one address must stay far below it.
    assert!((1..=2).contains(&rate), "rate {rate}r/s");
    let location = template
        .split("location = /rpc {")
        .nth(1)
        .and_then(|rest| rest.split('}').next())
        .expect("dedicated JSON-RPC location");
    assert!(location.contains("limit_req zone=hashstash_rpc "));
    assert!(location.contains("limit_conn hashstash_connections "));
    // `delay=` needs nginx 1.15.7, and the deployment guide must say so.
    if template.contains(" delay=") {
        assert!(repository("deploy/linux/README.md").contains("nginx 1.15.7 or later"));
    }
}

#[test]
fn public_web_proxy_names_each_visitor_and_stays_within_node_sessions() {
    use hashstash::network_guard::{PUBLIC_WEB_SESSIONS, PUBLIC_WEB_VISITOR_SESSIONS};
    let template = repository("deploy/linux/public-web.nginx.template");
    // The node keys visitor records on this header, so the proxy must
    // overwrite it. A location-level proxy_set_header would drop it.
    assert!(
        template
            .lines()
            .any(|line| line.trim() == "proxy_set_header X-Real-IP $remote_addr;")
    );
    for location in template.split("location ").skip(1) {
        let block = location.split('}').next().unwrap();
        assert!(!block.contains("proxy_set_header"), "location {block}");
    }
    let limits = |name: &str| -> Vec<usize> {
        let prefix = format!("limit_conn {name} ");
        template
            .lines()
            .filter_map(|line| line.trim().strip_prefix(&prefix))
            .map(|rest| rest.trim_end_matches(';').parse().unwrap())
            .collect()
    };
    // One client stays below the node's per-visitor cap, and all clients
    // together within its public session pool, in every proxied location.
    let per_client = limits("hashstash_connections");
    assert!(per_client.len() >= 2, "{per_client:?}");
    for limit in per_client {
        assert!(limit <= PUBLIC_WEB_VISITOR_SESSIONS && limit < PUBLIC_WEB_SESSIONS);
    }
    assert_eq!(limits("hashstash_upstream"), [PUBLIC_WEB_SESSIONS; 2]);
}

#[cfg(target_os = "linux")]
fn run_script(arguments: &[&str]) {
    let output = std::process::Command::new("bash")
        .args(arguments)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Stub-binary launcher admission tests; no service or network operations.
#[cfg(target_os = "linux")]
#[test]
fn linux_launcher_script_regressions() {
    run_script(&["deploy/linux/test-launcher.sh"]);
}

/// Read-only installer preflights against this build, from private input copies.
#[cfg(target_os = "linux")]
#[test]
fn linux_installer_checks_with_this_binary() {
    run_script(&["deploy/linux/test-install-check.sh", env!("CARGO_BIN_EXE_hashstash")]);
}
