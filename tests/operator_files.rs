//! Deployment files and documented operator commands stay consistent with this build.
use std::{fs, path::Path};

fn repository(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap()
}

/// Dotted three-part numbers that name a Hashstash release, such as
/// "Hashstash 0.43.0", "version=0.43.0" or "/opt/hashstash/0.43.0-". Other
/// products' versions (nginx, systemd) may appear; IPv4 addresses have four parts.
fn release_numbers(text: &str) -> Vec<&str> {
    const CONTEXTS: [&str; 5] = [
        "hashstash ",
        "hashstash/",
        "version ",
        "version=",
        "release ",
    ];
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
            && CONTEXTS
                .iter()
                .any(|context| lower[..begin].ends_with(context))
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
        installer
            .lines()
            .any(|line| line == format!("version={version}")),
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

/// The release script builds what the installer accepts: a normal locked
/// build of this version, with the toolchain continuous integration pins.
#[test]
fn release_script_builds_normally_with_the_validated_toolchain() {
    let script = repository("scripts/release.sh");
    let pinned = repository(".github/workflows/ci.yml")
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("RUST_TOOLCHAIN: '")
                .and_then(|rest| rest.strip_suffix('\''))
                .map(str::to_owned)
        })
        .expect("CI toolchain pin");
    assert!(
        script.contains(&format!("toolchain=${{RUST_TOOLCHAIN:-{pinned}}}")),
        "release.sh must default to the CI toolchain {pinned}"
    );
    assert!(script.contains("cargo build --locked --release --bins"));
    // test-fixtures changes the chain identity; releases never enable features.
    assert!(!script.contains("--features"));
    assert!(script.contains("grep -qx \"version=$version\" \"$root/deploy/linux/install.sh\""));
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
        assert!(
            unit.lines().any(|line| line == directive),
            "missing {directive}"
        );
    }
}

/// The faucet holds a spending key: it runs confined, reaches only loopback,
/// and launch-kit.sh pins its binary path by hash.
#[test]
fn faucet_unit_confines_the_faucet() {
    let unit = repository("deploy/linux/hashstash-faucet.service");
    for directive in [
        "User=hashstash-faucet",
        "NoNewPrivileges=true",
        "CapabilityBoundingSet=",
        "ProtectSystem=strict",
        "ReadWritePaths=/var/lib/hashstash-faucet",
        "IPAddressDeny=any",
        "IPAddressAllow=localhost",
        "SystemCallFilter=@system-service",
        "SystemCallArchitectures=native",
        "RestrictNamespaces=true",
        "MemoryDenyWriteExecute=true",
        "ProtectProc=invisible",
        "LimitCORE=0",
        "KillSignal=SIGINT",
        "Restart=on-failure",
    ] {
        assert!(
            unit.lines().any(|line| line == directive),
            "missing {directive}"
        );
    }
    assert!(unit.lines().any(|line| line
        == "ExecStart=/opt/hashstash-faucet/FAUCET_PIN/hashstash-faucet --config /etc/hashstash-faucet/config.json"));
    let kit = repository("scripts/launch-kit.sh");
    assert!(kit.contains("s|/opt/hashstash-faucet/FAUCET_PIN/|/opt/hashstash-faucet/$pin/|"));
}

#[test]
fn systemd_unit_backs_off_restarts_and_names_out_of_memory_kills() {
    let unit = repository("deploy/linux/hashstash.service");
    for directive in [
        "Type=simple",
        "Restart=on-failure",
        "RestartSteps=8",
        "RestartMaxDelaySec=2min",
        "StartLimitIntervalSec=0",
    ] {
        assert!(
            unit.lines().any(|line| line == directive),
            "missing {directive}"
        );
    }
    // A literal `$$` reaches the shell as `$`, which reads systemd's variable.
    let stop = unit
        .lines()
        .find(|line| line.starts_with("ExecStopPost="))
        .expect("missing ExecStopPost");
    assert!(stop.contains(r#""$$SERVICE_RESULT" = oom-kill"#), "{stop}");
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

/// Every documented `init` that creates the slow (shared-network) preset
/// calibrates it, as the command requires; the uncalibrated limit makes
/// blocks and proof-of-work-gated defences practically free.
#[test]
fn documented_shared_network_genesis_is_calibrated() {
    let mut checked = 0;
    for entry in fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs")).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if !name.ends_with(".md") {
            continue;
        }
        let text = repository(&format!("docs/{name}"));
        for line in text.lines() {
            for (index, _) in line.match_indices("init ") {
                let command: String = line[index..].chars().take_while(|c| *c != '`').collect();
                if command.contains("--preset slow") {
                    assert!(
                        command.contains("--hashrate ") || command.contains("--uncalibrated"),
                        "docs/{name}: {command}"
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(
        checked >= 2,
        "documented slow-preset genesis commands were not found"
    );
    let running = repository("docs/RUNNING.md");
    assert!(running.contains("hashstash init --config network.json --preset slow --hashrate "));
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
    // One client stays within the node's per-visitor cap in every proxied
    // location. The cap is below the pool, so one client never holds all of it.
    const { assert!(PUBLIC_WEB_VISITOR_SESSIONS < PUBLIC_WEB_SESSIONS) };
    let per_client = limits("hashstash_connections");
    assert!(per_client.len() >= 2, "{per_client:?}");
    for limit in per_client {
        assert!(limit <= PUBLIC_WEB_VISITOR_SESSIONS, "{limit}");
    }
    // No connection limit is shared by all clients: a few addresses sending
    // or reading slowly would hold every place of one shared counter and
    // shut everyone else out. Every connection-limit key is the client's.
    assert!(limits("hashstash_upstream").is_empty());
    for zone in template
        .lines()
        .filter_map(|line| line.trim().strip_prefix("limit_conn_zone "))
    {
        assert!(zone.starts_with("$binary_remote_addr "), "{zone}");
    }
    // Connections to the node are capped at the upstream instead, within the
    // node's public session pool and across all worker processes, and every
    // proxied location uses that upstream.
    let upstream = template
        .split("upstream hashstash_public {")
        .nth(1)
        .and_then(|rest| rest.split('}').next())
        .expect("capped public upstream");
    assert!(upstream.contains("zone hashstash_public "), "{upstream}");
    let max_conns: usize = upstream
        .split("max_conns=")
        .nth(1)
        .and_then(|rest| rest.split(';').next())
        .and_then(|value| value.parse().ok())
        .expect("upstream max_conns");
    assert!(
        (1..=PUBLIC_WEB_SESSIONS).contains(&max_conns),
        "{max_conns}"
    );
    let passes: Vec<_> = template
        .lines()
        .filter_map(|line| line.trim().strip_prefix("proxy_pass "))
        .collect();
    assert!(passes.len() >= 2, "{passes:?}");
    assert!(
        passes
            .iter()
            .all(|pass| *pass == "http://hashstash_public;")
    );
    // A request finding the upstream full (nginx's 502) is asked to retry.
    assert!(
        template
            .lines()
            .any(|line| line.trim() == "error_page 502 =503 @busy;")
    );
    // But nginx also answers 502 when the node closed the connection without
    // a reply, after it received and perhaps ran the request. 503 promises
    // that nothing ran, and the wallet would then sign a second transaction
    // while the first one may be pending: only a request that never reached
    // the node ($upstream_connect_time "-") may become a 503, and any other
    // 502 stays one.
    let busy = block(&template, "location @busy {").expect("busy answer");
    let guard = "if ($upstream_connect_time = \"-\") {";
    let unsent = block(busy, guard).expect("busy answer only for unsent requests");
    assert!(unsent.contains("add_header Retry-After "), "{unsent}");
    assert!(unsent.contains("return 503 "), "{unsent}");
    let (before, after) = busy.split_once(guard).unwrap();
    let rest = &after[unsent.len()..];
    assert!(
        !before.contains("return ") && !rest.contains("return 503"),
        "{busy}"
    );
    assert_eq!(
        rest.lines()
            .map(str::trim)
            .filter(|line| line.starts_with("return "))
            .collect::<Vec<_>>(),
        ["return 502;"],
        "{busy}"
    );
    // Buffering keeps slow clients off node sessions; it must stay on.
    for directive in ["proxy_request_buffering", "proxy_buffering"] {
        assert!(
            template.contains(&format!("{directive} on;")),
            "{directive}"
        );
        assert!(
            !template.contains(&format!("{directive} off;")),
            "{directive}"
        );
    }
}

/// The body of the first nginx block that `opening` (ending in `{`) starts,
/// up to its matching `}`. Braces in quoted strings and `#` comments do not
/// count.
fn block<'a>(config: &'a str, opening: &str) -> Option<&'a str> {
    let start = config.find(opening)? + opening.len();
    let (mut depth, mut quote, mut comment) = (1usize, None, false);
    for (index, c) in config[start..].char_indices() {
        match (comment, quote, c) {
            (true, _, '\n') => comment = false,
            (true, ..) => {}
            (false, Some(q), _) if c == q => quote = None,
            (false, Some(_), _) => {}
            (false, None, '#') => comment = true,
            (false, None, '\'' | '"') => quote = Some(c),
            (false, None, '{') => depth += 1,
            (false, None, '}') => {
                depth -= 1;
                if depth == 0 {
                    return Some(&config[start..start + index]);
                }
            }
            _ => {}
        }
    }
    None
}

/// A PowerShell script's `param(...)` block, if it has one. Parentheses after
/// a `#` on the same line are comment text.
fn parameter_block(script: &str) -> Option<&str> {
    let start = script.to_ascii_lowercase().find("param(")?;
    let mut depth = 0usize;
    let mut comment = false;
    for (index, c) in script[start..].char_indices() {
        match c {
            '\n' => comment = false,
            '#' => comment = true,
            '(' if !comment => depth += 1,
            ')' if !comment => {
                depth -= 1;
                if depth == 0 {
                    return Some(&script[start..=start + index]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Windows PowerShell 5.1, the version Windows ships, leaves `$PSScriptRoot`
/// empty while it evaluates the parameter defaults of a script started with
/// `powershell -File` (a shortcut, a scheduled task), so a default built from
/// it fails before the script runs. Such defaults are set in the body instead.
#[test]
fn powershell_parameter_defaults_never_use_the_script_folder() {
    assert_eq!(
        parameter_block(
            "[CmdletBinding()]\nParam(\n  # (note\n  [string]$A = (Join-Path $PSScriptRoot 'x')\n)\n$b = 1"
        ),
        Some("Param(\n  # (note\n  [string]$A = (Join-Path $PSScriptRoot 'x')\n)")
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0;
    for directory in [root.to_path_buf(), root.join("scripts")] {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if !path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("ps1"))
            {
                continue;
            }
            let script = fs::read_to_string(&path).unwrap();
            let Some(block) = parameter_block(&script) else {
                continue;
            };
            assert!(
                !block.to_ascii_lowercase().contains("$psscriptroot"),
                "{}: set $PSScriptRoot-based defaults in the script body",
                path.display()
            );
            checked += 1;
        }
    }
    assert!(checked >= 16, "only {checked} launcher scripts were found");
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

/// launch-kit.sh input validation and generated files (stub binary), then kits
/// from this build, unpinned and pinned, whose every server runs its rendered
/// INSTALL.md steps up to the installer's --check.
#[cfg(target_os = "linux")]
#[test]
fn launch_kit_regressions() {
    run_script(&[
        "scripts/test-launch-kit.sh",
        env!("CARGO_BIN_EXE_hashstash"),
        env!("CARGO_BIN_EXE_hashstash-faucet"),
    ]);
}

/// A shell script under pipefail never pipes into a grep that stops reading
/// at its first match (-q, -m): the writer, still writing, then dies of
/// SIGPIPE now and then, and the pipeline fails with status 141 or, as a
/// condition, reads as no match. launch_kit_regressions failed so in CI once
/// launch-kit.sh --help outgrew one 4096-byte write. Such a check reads the
/// whole output first, or counts the matches.
#[test]
fn pipefail_scripts_never_pipe_into_an_early_exiting_grep() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0;
    for directory in ["scripts", "deploy/linux"] {
        for entry in fs::read_dir(root.join(directory)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|extension| extension != "sh") {
                continue;
            }
            let script = fs::read_to_string(&path).unwrap();
            if !script.contains("pipefail") {
                continue;
            }
            checked += 1;
            for (number, line) in script.lines().enumerate() {
                if line.trim_start().starts_with('#') {
                    continue;
                }
                let bytes = line.as_bytes();
                // Each `|` or `|&` that is not part of `||`.
                let pipes = (0..bytes.len()).filter(|&i| {
                    bytes[i] == b'|'
                        && (i == 0 || bytes[i - 1] != b'|')
                        && bytes.get(i + 1) != Some(&b'|')
                });
                for pipe in pipes {
                    let reader = line[pipe + 1..].trim_start_matches('&');
                    let mut words = reader
                        .split_whitespace()
                        .skip_while(|word| word.contains('='));
                    if !matches!(words.next(), Some("grep" | "egrep" | "fgrep")) {
                        continue;
                    }
                    let early = words
                        .take_while(|word| word.starts_with('-') && *word != "--")
                        .any(|flag| match flag.strip_prefix("--") {
                            Some(long) => {
                                matches!(long, "quiet" | "silent") || long.starts_with("max-count")
                            }
                            None => flag.contains(['q', 'm']),
                        });
                    assert!(
                        !early,
                        "{}:{}: a pipe into a grep that stops at its first match: {line}",
                        path.display(),
                        number + 1
                    );
                }
            }
        }
    }
    assert!(checked >= 6, "only {checked} pipefail scripts were found");
}

/// Read-only installer preflights against this build, from private input copies.
#[cfg(target_os = "linux")]
#[test]
fn linux_installer_checks_with_this_binary() {
    run_script(&[
        "deploy/linux/test-install-check.sh",
        env!("CARGO_BIN_EXE_hashstash"),
    ]);
}
