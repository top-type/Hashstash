//! Deployment files and documented operator commands stay consistent with this build.
use std::{fs, path::Path};

fn repository(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap()
}

/// Dotted three-part numbers such as release versions; IPv4 addresses have four parts.
fn release_numbers(text: &str) -> Vec<&str> {
    text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .map(|run| run.trim_matches('.'))
        .filter(|run| {
            let parts: Vec<_> = run.split('.').collect();
            parts.len() == 3 && parts.iter().all(|part| !part.is_empty())
        })
        .collect()
}

#[test]
fn linux_installer_accepts_exactly_this_release() {
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
