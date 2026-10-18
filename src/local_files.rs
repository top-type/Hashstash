//! Files a node keeps beside its chain database, and owner-only protection
//! for the files that hold secrets.
use anyhow::{Context, Result, ensure};
use std::{
    ffi::OsString,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

/// The sidecar `suffix` of a chain database. `NAME.sqlite` keeps its
/// documented `NAME.<suffix>`; any other file name `F` gets `F-<suffix>`.
/// The two forms never coincide, so two chain databases never share a
/// sidecar (`net.db` and `net.sqlite` once both used `net.<suffix>`).
pub fn sidecar(chain: &Path, suffix: &str) -> PathBuf {
    if chain.extension().is_some_and(|extension| extension == "sqlite") {
        return chain.with_extension(suffix);
    }
    let mut name = chain.file_name().map(OsString::from).unwrap_or_default();
    name.push("-");
    name.push(suffix);
    chain.with_file_name(name)
}

/// The stem-based name earlier releases used, where it differs from `sidecar`.
pub fn legacy_sidecar(chain: &Path, suffix: &str) -> Option<PathBuf> {
    let legacy = chain.with_extension(suffix);
    (legacy != sidecar(chain, suffix)).then_some(legacy)
}

/// Copies a small secret sidecar from its earlier name when only that one
/// exists, so an upgrade keeps it. The original stays in place for any other
/// chain database that shared the name.
pub fn adopt_legacy_secret(chain: &Path, suffix: &str) -> Result<()> {
    let path = sidecar(chain, suffix);
    let Some(legacy) = legacy_sidecar(chain, suffix) else {
        return Ok(());
    };
    if fs::symlink_metadata(&path).is_ok() {
        return Ok(());
    }
    let Ok(metadata) = fs::symlink_metadata(&legacy) else {
        return Ok(());
    };
    if !metadata.is_file() || metadata.len() > 64 * 1024 {
        return Ok(());
    }
    let bytes = Zeroizing::new(fs::read(&legacy)?);
    write_private(&path, &bytes)?;
    eprintln!(
        "Copied {} to {}, its name for this chain database; remove the original once no node uses it.",
        legacy.display(),
        path.display()
    );
    Ok(())
}

/// Writes a new owner-only file, restricted before any secret byte enters it.
/// An existing file is never overwritten.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("create {} (existing files are not overwritten)", path.display()))?;
    restrict_to_owner(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Reads a small secret file of at most `limit` bytes through one handle. The
/// path must name a regular file, never a symbolic link, and the handle must
/// still be that file: on Unix it must have the inspected device and inode,
/// and on Windows the path is opened without following a symbolic link or
/// junction, which the handle check then refuses, so a path swapped for a
/// link in between fails. On Unix the file must also be owner-only. The bytes
/// land in one buffer allocated up front and wiped when dropped.
pub fn read_private(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let fits = |metadata: &fs::Metadata| {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() <= limit as u64
    };
    let inspected = fs::symlink_metadata(path)?;
    ensure!(
        fits(&inspected),
        "key file must be a regular file of at most {limit} bytes, not a link"
    );
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT opens a symbolic link or junction
        // itself rather than its target, so the handle check refuses it.
        options.custom_flags(0x0020_0000);
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    ensure!(
        fits(&opened),
        "key file must be a regular file of at most {limit} bytes, not a link"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            opened.dev() == inspected.dev() && opened.ino() == inspected.ino(),
            "key file changed while it was opened"
        );
        ensure!(
            opened.permissions().mode() & 0o077 == 0,
            "key file must be owner-only (mode 0600)"
        );
    }
    // Preallocated, so reading never leaves a reallocated copy of the secret.
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit.saturating_add(1)));
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "key file is too large");
    Ok(bytes)
}

/// Creates `path` if it is missing, without truncating it, and restricts it
/// to the current account before any secret is written into it.
pub fn create_private(path: &Path) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    restrict_to_owner(path)
}

/// Owner-only access to a file that holds secrets. On Unix: mode 0600, and an
/// existing, more permissive file is tightened. On Windows: a protected access
/// list granting only the current account, set with the system's `icacls`.
/// Where Windows cannot set one (for example on a FAT or exFAT volume) a
/// warning is printed, because other accounts may then read the file.
pub fn restrict_to_owner(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("cannot restrict {}", path.display()))?;
        }
    }
    #[cfg(windows)]
    {
        if let Err(error) = windows::owner_only(path) {
            eprintln!(
                "Warning: {} could not be restricted to this account ({error:#}); other accounts on this computer may be able to read it.",
                path.display()
            );
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = path;
    Ok(())
}

/// The current account's SID from `whoami /user /fo csv /nh`, whose last
/// quoted field is the SID.
#[cfg_attr(not(windows), allow(dead_code))]
fn account_sid(output: &str) -> Option<String> {
    let line = output.lines().map(str::trim).find(|line| !line.is_empty())?;
    let sid = line.rsplit(',').next()?.trim().trim_matches('"');
    let valid = sid.strip_prefix("S-1-").is_some_and(|rest| {
        !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-')
    });
    valid.then(|| sid.to_owned())
}

/// `icacls` arguments leaving `sid`'s full control as the only entry: the
/// inherited entries are removed and the grant replaces its explicit ones.
#[cfg_attr(not(windows), allow(dead_code))]
fn icacls_arguments(path: &Path, sid: &str) -> Vec<OsString> {
    vec![
        path.into(),
        "/inheritance:r".into(),
        "/grant:r".into(),
        format!("*{sid}:F").into(),
        "/q".into(),
    ]
}

#[cfg(windows)]
mod windows {
    use super::{Context, OsString, Path, PathBuf, Result, account_sid, icacls_arguments};
    use std::{os::windows::process::CommandExt, process::Command, sync::OnceLock};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    /// A system tool by its full path, so the search path cannot substitute it.
    fn system_tool(name: &str) -> PathBuf {
        std::env::var_os("SystemRoot").map_or_else(
            || PathBuf::from(name),
            |root| PathBuf::from(root).join("System32").join(name),
        )
    }

    fn run(tool: &str, arguments: &[OsString]) -> Result<String> {
        let output = Command::new(system_tool(tool))
            .args(arguments)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .with_context(|| format!("cannot run {tool}"))?;
        // icacls reports some failures on standard output.
        anyhow::ensure!(
            output.status.success(),
            "{tool} failed: {} {}",
            String::from_utf8_lossy(&output.stderr).trim(),
            String::from_utf8_lossy(&output.stdout).trim()
        );
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    pub(super) fn owner_only(path: &Path) -> Result<()> {
        static SID: OnceLock<Option<String>> = OnceLock::new();
        let sid = SID
            .get_or_init(|| {
                let arguments: [OsString; 4] =
                    ["/user".into(), "/fo".into(), "csv".into(), "/nh".into()];
                run("whoami.exe", &arguments)
                    .ok()
                    .and_then(|output| account_sid(&output))
            })
            .as_deref()
            .context("cannot identify the current account")?;
        let path = std::path::absolute(path)?;
        run("icacls.exe", &icacls_arguments(&path, sid)).map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecars_keep_documented_names_and_never_collide() {
        let directory = Path::new("data");
        assert_eq!(
            sidecar(&directory.join("chain.sqlite"), "explorer.sqlite"),
            directory.join("chain.explorer.sqlite")
        );
        assert_eq!(
            sidecar(&directory.join("net.db"), "wallets.sqlite"),
            directory.join("net.db-wallets.sqlite")
        );
        assert_eq!(legacy_sidecar(&directory.join("chain.sqlite"), "peer-key.json"), None);
        assert_eq!(
            legacy_sidecar(&directory.join("net.db"), "peer-key.json"),
            Some(directory.join("net.peer-key.json"))
        );
        let chains = [
            "net", "net.sqlite", "net.db", "net.SQLITE", "net.db.sqlite", "net-db", "net.testnet",
            "net.devnet", ".sqlite", "net.explorer",
        ];
        for suffix in ["explorer.sqlite", "wallets.sqlite", "peer-key.json", "session-token"] {
            let names: Vec<_> = chains.iter().map(|c| sidecar(&directory.join(c), suffix)).collect();
            let distinct: std::collections::BTreeSet<_> = names.iter().collect();
            assert_eq!(distinct.len(), chains.len(), "{suffix}: {names:?}");
            for name in &names {
                assert!(!chains.iter().any(|c| directory.join(c) == *name));
            }
        }
    }

    #[test]
    fn windows_access_lists_name_only_the_current_account() {
        assert_eq!(
            account_sid("\"desktop-1\\taata\",\"S-1-5-21-1004336348-1177238915-682003330-1001\"\r\n")
                .as_deref(),
            Some("S-1-5-21-1004336348-1177238915-682003330-1001")
        );
        assert_eq!(account_sid("\"nt authority\\system\",\"S-1-5-18\"").as_deref(), Some("S-1-5-18"));
        for invalid in ["", "\"user\",\"\"", "\"user\",\"S-1-\"", "\"user\",\"S-1-5 /grant\"", "S-1-5-18;x"] {
            assert_eq!(account_sid(invalid), None, "{invalid}");
        }
        let arguments = icacls_arguments(Path::new("C:\\data\\chain.wallets.sqlite"), "S-1-5-18");
        assert_eq!(
            arguments,
            ["C:\\data\\chain.wallets.sqlite", "/inheritance:r", "/grant:r", "*S-1-5-18:F", "/q"]
                .map(OsString::from)
        );
    }

    #[test]
    fn private_files_are_created_owner_only_and_never_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secret.json");
        write_private(&path, b"first").unwrap();
        assert!(write_private(&path, b"second").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"first");
        create_private(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first", "never truncated");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            restrict_to_owner(&path).unwrap();
            assert_eq!(mode(&path), 0o600, "a permissive file is tightened");
        }
        // A secret sidecar moves from its stem-based name once.
        let chain = directory.path().join("net.db");
        fs::write(directory.path().join("net.peer-key.json"), b"identity").unwrap();
        adopt_legacy_secret(&chain, "peer-key.json").unwrap();
        let adopted = directory.path().join("net.db-peer-key.json");
        assert_eq!(fs::read(&adopted).unwrap(), b"identity");
        fs::write(directory.path().join("net.peer-key.json"), b"changed").unwrap();
        adopt_legacy_secret(&chain, "peer-key.json").unwrap();
        assert_eq!(fs::read(&adopted).unwrap(), b"identity", "an existing sidecar wins");
        adopt_legacy_secret(&directory.path().join("chain.sqlite"), "peer-key.json").unwrap();
        assert!(!directory.path().join("chain.peer-key.json").exists());
    }

    #[test]
    fn private_reads_accept_only_small_owner_only_regular_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key.json");
        write_private(&path, b"secret").unwrap();
        assert_eq!(read_private(&path, 6).unwrap().as_slice(), b"secret");
        assert!(read_private(&path, 5).is_err(), "larger than the limit");
        assert!(read_private(directory.path(), 4096).is_err(), "a directory");
        assert!(read_private(&directory.path().join("missing"), 4096).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let link = directory.path().join("link.json");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(read_private(&link, 4096).is_err(), "a symbolic link");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            assert!(read_private(&path, 4096).is_err(), "readable by the group");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(read_private(&path, 4096).is_ok());
        }
        #[cfg(windows)]
        {
            // Creating a symbolic link needs a privilege or developer mode.
            let link = directory.path().join("link.json");
            if std::os::windows::fs::symlink_file(&path, &link).is_ok() {
                assert!(read_private(&link, 4096).is_err(), "a symbolic link");
            }
        }
    }
}
