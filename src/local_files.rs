//! Files a node keeps beside its chain database, and owner-only protection
//! for the files that hold secrets.
use anyhow::{Context, Result, ensure};
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
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
    if chain
        .extension()
        .is_some_and(|extension| extension == "sqlite")
    {
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

/// Writes a new owner-only file (`create_new_private`). An existing file is
/// never overwritten.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = create_new_private(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Creates a new file, never an existing one, that is owner-only from the
/// moment it exists, and returns it open for writing. On Unix it is created
/// with mode 0600. On Windows the system creates it with a protected access
/// list granting only the current account: setting the list afterwards would
/// leave a moment in which another account allowed by the folder's inherited
/// list could open a handle, and a handle keeps the access it was opened
/// with. Where the volume keeps access lists the result is read back and must
/// be owner-only (`owner_only_access_list`), or the new file is removed again
/// and this is an error; only a volume without them (FAT, exFAT) is a warning.
pub fn create_new_private(path: &Path) -> Result<fs::File> {
    let created = || {
        format!(
            "create {} (existing files are not overwritten)",
            path.display()
        )
    };
    #[cfg(windows)]
    {
        let (file, _) = windows::open_private(path, true).with_context(created)?;
        if let Err(error) = windows::confirm_private(&file, path, false) {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(error);
        }
        Ok(file)
    }
    #[cfg(not(windows))]
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(path).with_context(created)
    }
}

/// Creates a new directory that only the current account can open, so files
/// that another library or helper creates inside it are owner-only from the
/// start: on Unix mode 0700, on Windows a protected access list that grants
/// only the current account and is inherited by everything created inside.
/// Use it to stage a secret file that code outside this module creates; the
/// staged file keeps its own list when it is linked or renamed into place.
pub fn create_private_directory(path: &Path) -> Result<()> {
    let created = || format!("create directory {}", path.display());
    #[cfg(windows)]
    {
        windows::create_private_directory(path).with_context(created)?;
        let checked = fs::OpenOptions::new()
            .access_mode(windows::READ_CONTROL)
            .custom_flags(windows::FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .map_err(anyhow::Error::from)
            .and_then(|directory| windows::confirm_private(&directory, path, false));
        if let Err(error) = checked {
            let _ = fs::remove_dir(path);
            return Err(error);
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(path).with_context(created)
    }
}

/// Reads a small secret file of at most `limit` bytes through one handle. The
/// path must name a regular file, never a symbolic link, and the handle must
/// still be that file: on Unix it must have the inspected device and inode,
/// and on Windows the path is opened without following a symbolic link or
/// junction, which the handle check then refuses, so a path swapped for a
/// link in between fails. The file must also be owner-only: on Unix no group
/// or other permission bits, and on Windows an access list that lets in no
/// account but this one, SYSTEM and Administrators (see
/// `owner_only_access_list`). The bytes land in one buffer allocated up front
/// and wiped when dropped.
pub fn read_private(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let fits = |metadata: &fs::Metadata| {
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= limit as u64
    };
    let inspected = fs::symlink_metadata(path)?;
    ensure!(
        fits(&inspected),
        "key file must be a regular file of at most {limit} bytes, not a link"
    );
    let mut options = fs::OpenOptions::new();
    options.read(true);
    // FILE_FLAG_OPEN_REPARSE_POINT opens a symbolic link or junction itself
    // rather than its target, so the handle check refuses it.
    #[cfg(windows)]
    options.custom_flags(0x0020_0000);
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
    #[cfg(windows)]
    {
        // The list of the file this handle opened, after the checks above.
        ensure!(
            windows::keeps_access_lists(&file)?,
            "key file is on a volume without access lists (such as FAT or exFAT), so every account can read it"
        );
        let (_, list) = windows::security(&file)?;
        owner_only_access_list(&list, windows::current_sid()?)?;
    }
    // Preallocated, so reading never leaves a reallocated copy of the secret.
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit.saturating_add(1)));
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "key file is too large");
    Ok(bytes)
}

/// Reads a small secret file the operator names directly, such as a spending
/// key given on the command line, into one buffer allocated up front and
/// wiped when dropped. It must be a regular file (a link is followed) of at
/// most `limit` bytes. Unlike `read_private`, a file other accounts can read
/// is still read, and the second value says why it is not owner-only so the
/// caller can warn: refusing it would not make it any less exposed, and keys
/// are legitimately carried on FAT or exFAT media, which keep no access list.
pub fn read_operator_secret(
    path: &Path,
    limit: usize,
) -> Result<(Zeroizing<Vec<u8>>, Option<String>)> {
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit as u64,
        "key file must be a regular file of at most {limit} bytes"
    );
    #[cfg(unix)]
    let exposed = {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        (mode & 0o077 != 0).then(|| {
            format!("can be read or changed by other accounts on this computer (mode {mode:04o}; use 0600)")
        })
    };
    #[cfg(windows)]
    let exposed = match windows::keeps_access_lists(&file) {
        Ok(false) => Some(
            "is on a volume without access lists (such as FAT or exFAT), so every account on this computer can read it".to_owned(),
        ),
        Ok(true) => windows::current_sid()
            .and_then(|sid| {
                let (_, list) = windows::security(&file)?;
                owner_only_access_list(&list, sid)
            })
            .err()
            .map(|error| format!("may be readable by other accounts on this computer: {error:#}")),
        Err(error) => Some(format!("could not be checked for access by other accounts: {error:#}")),
    };
    #[cfg(not(any(unix, windows)))]
    let exposed = None;
    // Preallocated, so reading never leaves a reallocated copy of the secret.
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit.saturating_add(1)));
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "key file is too large");
    Ok((bytes, exposed))
}

/// Creates `path` if it is missing, without truncating it, and restricts it
/// to the current account before any secret is written into it. A new file
/// is owner-only from the moment it exists (`create_new_private`); an
/// existing one is restricted as `restrict_to_owner` does.
pub fn create_private(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        let (file, existed) = windows::open_private(path, false)
            .with_context(|| format!("cannot open {}", path.display()))?;
        windows::confirm_private(&file, path, existed)
    }
    #[cfg(not(windows))]
    {
        let mut options = fs::OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options
            .open(path)
            .with_context(|| format!("cannot open {}", path.display()))?;
        restrict_to_owner(path)
    }
}

/// Owner-only access to an existing file that holds secrets. On Unix: mode
/// 0600, and an existing, more permissive file is tightened. On Windows: the
/// whole access list is replaced with a protected one granting only the
/// current account, so explicit entries for other accounts go too. A file
/// another account owns is refused before anything changes (`trusted_owner`):
/// that account may have created it to keep a handle open, and an owner may
/// always change the list again. The result is read back and must pass
/// `owner_only_access_list`; on a volume that keeps access lists (NTFS, ReFS)
/// any failure is an error. Only on a volume without them (for example FAT or
/// exFAT) is a warning printed instead, because other accounts may then read
/// the file. This cannot close a handle another account opened before;
/// create secret files with `create_new_private` or `create_private`.
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
        // Only the list changes, so this handle needs no access to the data
        // and does not conflict with any open for reading or writing.
        let file = fs::OpenOptions::new()
            .access_mode(windows::READ_CONTROL | windows::WRITE_DAC)
            .share_mode(windows::FILE_SHARE_ALL)
            .open(path)
            .with_context(|| format!("cannot restrict {} to this account", path.display()))?;
        windows::confirm_private(&file, path, true)?;
    }
    #[cfg(not(any(unix, windows)))]
    let _ = path;
    Ok(())
}

/// The protected access list, in SDDL, granting only `sid` full control: what
/// a secret file gets on Windows. For a directory (`inherited`) the entry also
/// passes to the files and folders created inside it.
#[cfg_attr(not(windows), allow(dead_code))]
fn owner_only_sddl(sid: &str, inherited: bool) -> String {
    format!("D:P(A;{};FA;;;{sid})", if inherited { "OICI" } else { "" })
}

/// Checks a secret file's owner, in the SDDL form `O:` and an account. It must
/// be `sid`, the current account, or SYSTEM, the Administrators group (which
/// owns what an elevated administrator creates) or its built-in Administrator
/// account, which can read any file anyway: any other owner may have created
/// the file to keep a handle open, and may change its access list at any
/// time, whatever it now says.
#[cfg_attr(not(windows), allow(dead_code))]
fn trusted_owner(sddl: &str, sid: &str) -> Result<()> {
    let owner = sddl
        .trim()
        .strip_prefix("O:")
        .context("unrecognized file owner")?;
    ensure!(
        owner.eq_ignore_ascii_case(sid)
            || matches!(owner, "SY" | "BA" | "LA" | "S-1-5-18" | "S-1-5-32-544"),
        "another account ({owner}) owns this file, so it may hold the file open and could change its access list; check the file, then take ownership of it (takeown) or move it aside"
    );
    Ok(())
}

/// The current account's SID from `whoami /user /fo csv /nh`, whose last
/// quoted field is the SID.
#[cfg_attr(not(windows), allow(dead_code))]
fn account_sid(output: &str) -> Option<String> {
    let line = output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())?;
    let sid = line.rsplit(',').next()?.trim().trim_matches('"');
    let valid = sid.strip_prefix("S-1-").is_some_and(|rest| {
        !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-')
    });
    valid.then(|| sid.to_owned())
}

/// Checks a secret file's access list, in the SDDL form the system and
/// `icacls /save` write (`D:` flags, then one parenthesized entry per grant or
/// denial). Every entry
/// that grants access must name `sid`, the current account, or SYSTEM, the
/// Administrators group or its built-in Administrator account, which can read
/// any file anyway; this mirrors the Unix rule of no group or other permission
/// bits. Deny entries only take access away. A null list, which lets every
/// account in, is refused, and so is anything unrecognized. Inherited entries
/// count like explicit ones, so a key in a profile folder passes and one in a
/// folder that lets Users read does not.
#[cfg_attr(not(windows), allow(dead_code))]
fn owner_only_access_list(sddl: &str, sid: &str) -> Result<()> {
    let list = sddl
        .trim()
        .strip_prefix("D:")
        .context("unrecognized key file access list")?;
    let (flags, mut entries) = list.split_at(list.find('(').unwrap_or(list.len()));
    // P (protected), AI and AR (inheritance); NO_ACCESS_CONTROL is a null list.
    ensure!(
        flags.chars().all(|c| matches!(c, 'P' | 'A' | 'I' | 'R')),
        "key file has no access list, so every account can read it"
    );
    while let Some(rest) = entries.strip_prefix('(') {
        // A conditional entry nests parentheses of its own.
        let mut depth = 1usize;
        let end = rest
            .char_indices()
            .find_map(|(at, c)| {
                match c {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                (depth == 0).then_some(at)
            })
            .context("unrecognized key file access list")?;
        // type;flags;rights;object;inherited object;account[;condition]
        let fields: Vec<&str> = rest[..end].splitn(7, ';').collect();
        entries = &rest[end + 1..];
        ensure!(fields.len() >= 6, "unrecognized key file access list");
        if matches!(fields[0], "D" | "OD" | "XD") {
            continue;
        }
        let account = fields[5];
        ensure!(
            account.eq_ignore_ascii_case(sid)
                || matches!(account, "SY" | "BA" | "LA" | "S-1-5-18" | "S-1-5-32-544"),
            "key file must be owner-only: its access list lets in another account ({account})"
        );
    }
    // Anything after the list is another section, such as the system list.
    ensure!(
        entries.is_empty() || entries.starts_with("S:"),
        "unrecognized key file access list"
    );
    Ok(())
}

#[cfg(windows)]
mod windows {
    use super::{Context, OsString, Path, PathBuf, Result, account_sid};
    use std::{
        ffi::{OsStr, c_void},
        fs, io,
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle, RawHandle},
            process::CommandExt,
        },
        process::Command,
        ptr,
        sync::OnceLock,
    };

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    /// The volume keeps a file's access list (FILE_PERSISTENT_ACLS).
    const FILE_PERSISTENT_ACLS: u32 = 0x0000_0008;
    pub(super) const READ_CONTROL: u32 = 0x0002_0000;
    pub(super) const WRITE_DAC: u32 = 0x0004_0000;
    #[cfg(test)]
    pub(super) const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    /// Read, write and delete sharing, as the standard library opens files.
    pub(super) const FILE_SHARE_ALL: u32 = 0x0000_0007;
    /// Opens a directory's handle.
    pub(super) const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const CREATE_NEW: u32 = 1;
    const OPEN_ALWAYS: u32 = 4;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x0080;
    const ERROR_ALREADY_EXISTS: i32 = 183;
    const SDDL_REVISION_1: u32 = 1;
    const SE_FILE_OBJECT: u32 = 1;
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        descriptor: *mut c_void,
        inherit_handle: i32,
    }

    /// BY_HANDLE_FILE_INFORMATION.
    #[cfg(test)]
    #[repr(C)]
    #[derive(Default)]
    struct FileInformation {
        attributes: u32,
        times: [u32; 6],
        volume_serial: u32,
        size: [u32; 2],
        links: u32,
        index_high: u32,
        index_low: u32,
    }

    /// Every file `open_private` created in this process, by volume and file
    /// index, so tests can tell a secret file this module created owner-only
    /// from one SQLite or another library created with the folder's inherited
    /// list and something restricted afterwards. NTFS never gives a later
    /// file the same index, while it does carry a deleted file's creation
    /// time over to a new one of the same name.
    #[cfg(test)]
    pub(super) static CREATED: std::sync::Mutex<Vec<(u32, u64)>> =
        std::sync::Mutex::new(Vec::new());

    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[cfg(test)]
        fn GetFileInformationByHandle(file: RawHandle, information: *mut FileInformation) -> i32;
        fn GetVolumeInformationByHandleW(
            file: RawHandle,
            volume_name: *mut u16,
            volume_name_size: u32,
            serial_number: *mut u32,
            maximum_component_length: *mut u32,
            file_system_flags: *mut u32,
            file_system_name: *mut u16,
            file_system_name_size: u32,
        ) -> i32;
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *const SecurityAttributes,
            disposition: u32,
            flags: u32,
            template: RawHandle,
        ) -> RawHandle;
        fn CreateDirectoryW(name: *const u16, security: *const SecurityAttributes) -> i32;
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text: *const u16,
            revision: u32,
            descriptor: *mut *mut c_void,
            size: *mut u32,
        ) -> i32;
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor: *mut c_void,
            revision: u32,
            information: u32,
            text: *mut *mut u16,
            length: *mut u32,
        ) -> i32;
        fn GetSecurityDescriptorDacl(
            descriptor: *mut c_void,
            present: *mut i32,
            dacl: *mut *mut c_void,
            defaulted: *mut i32,
        ) -> i32;
        fn GetSecurityInfo(
            handle: RawHandle,
            object: u32,
            information: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut c_void,
            sacl: *mut *mut c_void,
            descriptor: *mut *mut c_void,
        ) -> u32;
        fn SetSecurityInfo(
            handle: RawHandle,
            object: u32,
            information: u32,
            owner: *mut c_void,
            group: *mut c_void,
            dacl: *mut c_void,
            sacl: *mut c_void,
        ) -> u32;
    }

    /// Memory the system allocated with LocalAlloc, freed when dropped.
    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from the system's LocalAlloc and
                // is freed once, here.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    fn wide(text: &OsStr) -> Vec<u16> {
        text.encode_wide().chain(Some(0)).collect()
    }

    fn failed(status: u32) -> io::Error {
        io::Error::from_raw_os_error(status as i32)
    }

    /// A security descriptor parsed from SDDL.
    fn descriptor(sddl: &str) -> Result<Local> {
        let text = wide(OsStr::new(sddl));
        let mut descriptor = ptr::null_mut();
        // SAFETY: `text` is NUL-terminated and outlives the call; the system
        // allocates the output, which `Local` frees.
        let built = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if built == 0 {
            return Err(io::Error::last_os_error()).context("cannot build an access list");
        }
        Ok(Local(descriptor))
    }

    /// The owner-only descriptor and the attributes that hand it to the
    /// system when it creates a file or directory; both must stay alive
    /// while the attributes are used.
    fn creation(sid: &str, inherited: bool) -> Result<(Local, SecurityAttributes)> {
        let descriptor = descriptor(&super::owner_only_sddl(sid, inherited))?;
        let attributes = SecurityAttributes {
            length: size_of::<SecurityAttributes>() as u32,
            descriptor: descriptor.0,
            inherit_handle: 0,
        };
        Ok((descriptor, attributes))
    }

    /// Whether the volume holding this open file keeps access lists, asked of
    /// the file itself, so mount points and network shares answer for their
    /// own file system.
    pub(super) fn keeps_access_lists(file: &fs::File) -> Result<bool> {
        let mut flags = 0u32;
        // SAFETY: the handle stays open for the call, the one output pointer
        // is a live u32, and every other buffer is null with a zero size.
        let succeeded = unsafe {
            GetVolumeInformationByHandleW(
                file.as_raw_handle(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut flags,
                ptr::null_mut(),
                0,
            )
        };
        if succeeded == 0 {
            return Err(io::Error::last_os_error()).context("cannot inspect the file's volume");
        }
        Ok(flags & FILE_PERSISTENT_ACLS != 0)
    }

    /// An open file's owner (`O:`) and access list (`D:`) as SDDL, which
    /// names accounts by SID and so reads the same in every display language.
    /// The handle needs READ_CONTROL, which reading access includes.
    pub(super) fn security(file: &fs::File) -> Result<(String, String)> {
        let mut descriptor = ptr::null_mut();
        // SAFETY: the handle stays open for the call; the only output is the
        // descriptor the system allocates, which `Local` frees.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(failed(status)).context("cannot read the file's access list");
        }
        let descriptor = Local(descriptor);
        Ok((
            sddl(&descriptor, OWNER_SECURITY_INFORMATION)?,
            sddl(&descriptor, DACL_SECURITY_INFORMATION)?,
        ))
    }

    fn sddl(descriptor: &Local, information: u32) -> Result<String> {
        let mut text: *mut u16 = ptr::null_mut();
        // SAFETY: `descriptor` is a valid descriptor; the system allocates a
        // NUL-terminated string, which `Local` frees.
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.0,
                SDDL_REVISION_1,
                information,
                &mut text,
                ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err(io::Error::last_os_error()).context("cannot read the file's access list");
        }
        let text = Local(text.cast());
        let start = text.0.cast::<u16>();
        let mut length = 0;
        // SAFETY: the string is NUL-terminated, so every unit read up to and
        // including that terminator lies inside it.
        while unsafe { *start.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: `length` units precede the terminator, inside the string.
        let units = unsafe { std::slice::from_raw_parts(start, length) };
        Ok(String::from_utf16(units)?)
    }

    /// Opens `path` with a protected access list granting only the current
    /// account, which the system applies as it creates the file. `new_only`
    /// refuses an existing file and opens the new one for writing; otherwise
    /// an existing file is opened too, only to change its list. Returns the
    /// file and whether it already existed, its list then unchanged so far.
    pub(super) fn open_private(path: &Path, new_only: bool) -> Result<(fs::File, bool)> {
        let (_descriptor, attributes) = creation(current_sid()?, false)?;
        let name = wide(path.as_os_str());
        let data = if new_only { GENERIC_WRITE } else { 0 };
        // SAFETY: `name` is NUL-terminated, and `attributes` and the
        // descriptor it points to outlive the call.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                data | READ_CONTROL | WRITE_DAC,
                FILE_SHARE_ALL,
                &attributes,
                if new_only { CREATE_NEW } else { OPEN_ALWAYS },
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        // Read at once: OPEN_ALWAYS reports an existing file this way.
        let status = io::Error::last_os_error();
        if handle as isize == -1 {
            return Err(status.into());
        }
        // SAFETY: a valid handle that nothing else owns.
        let file = unsafe { fs::File::from_raw_handle(handle) };
        let existed = status.raw_os_error() == Some(ERROR_ALREADY_EXISTS);
        #[cfg(test)]
        if !existed {
            use std::os::windows::fs::OpenOptionsExt;
            // The creating handle may lack FILE_READ_ATTRIBUTES.
            let created = fs::OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_ALL)
                .open(path)?;
            CREATED.lock().unwrap().push(identity(&created)?);
        }
        Ok((file, existed))
    }

    /// An open file's volume serial number and file index. The handle needs
    /// FILE_READ_ATTRIBUTES.
    #[cfg(test)]
    pub(super) fn identity(file: &fs::File) -> Result<(u32, u64)> {
        let mut information = FileInformation::default();
        // SAFETY: the handle stays open for the call, and the output is a
        // live structure of the size the system writes.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
            return Err(io::Error::last_os_error()).context("cannot identify the file");
        }
        Ok((
            information.volume_serial,
            (u64::from(information.index_high) << 32) | u64::from(information.index_low),
        ))
    }

    /// Creates a directory whose protected list grants only the current
    /// account, and passes that entry to everything created inside.
    pub(super) fn create_private_directory(path: &Path) -> Result<()> {
        let (_descriptor, attributes) = creation(current_sid()?, true)?;
        let name = wide(path.as_os_str());
        // SAFETY: `name` is NUL-terminated, and `attributes` and the
        // descriptor it points to outlive the call.
        if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    /// Makes an open file owner-only where its volume keeps access lists, and
    /// checks that it is. The owner must be trusted (`trusted_owner`), before
    /// anything changes: another account that owns a secret file may have
    /// created it to keep a handle open, which no new list closes, and may
    /// change the list again. `replace` then sets the whole list, for a file
    /// that existed before (the handle needs WRITE_DAC). Either way the list
    /// is read back and must be owner-only (`owner_only_access_list`). On a
    /// volume without access lists only a warning is printed.
    pub(super) fn confirm_private(file: &fs::File, path: &Path, replace: bool) -> Result<()> {
        let restricted = || format!("cannot restrict {} to this account", path.display());
        if !keeps_access_lists(file).with_context(restricted)? {
            eprintln!(
                "Warning: {} is on a volume without access lists (such as FAT or exFAT); other accounts on this computer may be able to read it.",
                path.display()
            );
            return Ok(());
        }
        let sid = current_sid()?;
        let (owner, _) = security(file).with_context(restricted)?;
        super::trusted_owner(&owner, sid).with_context(restricted)?;
        if replace {
            replace_list(file, sid).with_context(restricted)?;
        }
        let (_, list) = security(file).with_context(restricted)?;
        super::owner_only_access_list(&list, sid).with_context(restricted)
    }

    /// Replaces an existing file's whole access list with the protected
    /// owner-only one, so inherited entries and other accounts' explicit
    /// ones both go.
    fn replace_list(file: &fs::File, sid: &str) -> Result<()> {
        let owner_only = descriptor(&super::owner_only_sddl(sid, false))?;
        let (mut present, mut defaulted, mut dacl) = (0, 0, ptr::null_mut());
        // SAFETY: a valid descriptor; the list it returns points inside it.
        if unsafe {
            GetSecurityDescriptorDacl(owner_only.0, &mut present, &mut dacl, &mut defaulted)
        } == 0
            || present == 0
        {
            return Err(io::Error::last_os_error()).context("cannot build an access list");
        }
        // SAFETY: the handle is open with WRITE_DAC, and `dacl` lives inside
        // `owner_only`, which outlives the call.
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(failed(status)).context("cannot set the access list");
        }
        Ok(())
    }

    /// A system tool by its full path, so the search path cannot substitute it.
    fn system_tool(name: &str) -> PathBuf {
        std::env::var_os("SystemRoot").map_or_else(
            || PathBuf::from(name),
            |root| PathBuf::from(root).join("System32").join(name),
        )
    }

    pub(super) fn run(tool: &str, arguments: &[OsString]) -> Result<String> {
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

    /// The current account, as the system writes it in an access list.
    pub(super) fn current_sid() -> Result<&'static str> {
        static SID: OnceLock<Option<String>> = OnceLock::new();
        SID.get_or_init(|| {
            let arguments: [OsString; 4] =
                ["/user".into(), "/fo".into(), "csv".into(), "/nh".into()];
            let sid = run("whoami.exe", &arguments)
                .ok()
                .and_then(|output| account_sid(&output))?;
            spelled(&sid).ok()
        })
        .as_deref()
        .context("cannot identify the current account")
    }

    /// `sid` as the system writes it in SDDL, which names some accounts by a
    /// short alias, such as NS for NETWORK SERVICE, so that access lists the
    /// system reports compare equal to it.
    pub(super) fn spelled(sid: &str) -> Result<String> {
        let owner = descriptor(&format!("O:{sid}"))?;
        let text = sddl(&owner, OWNER_SECURITY_INFORMATION)?;
        text.strip_prefix("O:")
            .filter(|account| !account.is_empty())
            .map(str::to_owned)
            .context("unrecognized account")
    }

    /// A file's access list as `icacls /save` reports it, in SDDL: a second
    /// reader, independent of `security`, for tests to check results with.
    /// It writes the list to a file in UTF-16: the file's name, then its list.
    #[cfg(test)]
    pub(super) fn access_list(path: &Path) -> Result<String> {
        let path = std::path::absolute(path)?;
        let mut name = [0u8; 16];
        getrandom::fill(&mut name).map_err(|error| anyhow::anyhow!("OS randomness: {error}"))?;
        let saved = std::env::temp_dir().join(format!("hashstash-acl-{}", hex::encode(name)));
        let arguments: [OsString; 4] = [
            path.into(),
            "/save".into(),
            saved.clone().into(),
            "/q".into(),
        ];
        let read = run("icacls.exe", &arguments)
            .and_then(|_| std::fs::read(&saved).context("cannot read the saved access list"));
        let _ = std::fs::remove_file(&saved);
        let units: Vec<u16> = read?
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units)?
            .lines()
            .map(|line| line.trim_matches('\u{feff}').trim())
            .find(|line| line.starts_with("D:"))
            .map(str::to_owned)
            .context("icacls reported no access list")
    }
}

#[cfg(test)]
pub(crate) mod tests {
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
        assert_eq!(
            legacy_sidecar(&directory.join("chain.sqlite"), "peer-key.json"),
            None
        );
        assert_eq!(
            legacy_sidecar(&directory.join("net.db"), "peer-key.json"),
            Some(directory.join("net.peer-key.json"))
        );
        let chains = [
            "net",
            "net.sqlite",
            "net.db",
            "net.SQLITE",
            "net.db.sqlite",
            "net-db",
            "net.testnet",
            "net.devnet",
            ".sqlite",
            "net.explorer",
        ];
        for suffix in [
            "explorer.sqlite",
            "wallets.sqlite",
            "peer-key.json",
            "session-token",
        ] {
            let names: Vec<_> = chains
                .iter()
                .map(|c| sidecar(&directory.join(c), suffix))
                .collect();
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
            account_sid(
                "\"desktop-1\\taata\",\"S-1-5-21-1004336348-1177238915-682003330-1001\"\r\n"
            )
            .as_deref(),
            Some("S-1-5-21-1004336348-1177238915-682003330-1001")
        );
        assert_eq!(
            account_sid("\"nt authority\\system\",\"S-1-5-18\"").as_deref(),
            Some("S-1-5-18")
        );
        for invalid in [
            "",
            "\"user\",\"\"",
            "\"user\",\"S-1-\"",
            "\"user\",\"S-1-5 /grant\"",
            "S-1-5-18;x",
        ] {
            assert_eq!(account_sid(invalid), None, "{invalid}");
        }
        // The whole list a secret file gets, not a grant added to its own.
        assert_eq!(owner_only_sddl("S-1-5-18", false), "D:P(A;;FA;;;S-1-5-18)");
        assert_eq!(
            owner_only_sddl("S-1-5-18", true),
            "D:P(A;OICI;FA;;;S-1-5-18)"
        );
        for sid in ["S-1-5-18", "S-1-5-21-1004336348-1177238915-682003330-1001"] {
            for inherited in [false, true] {
                owner_only_access_list(&owner_only_sddl(sid, inherited), sid).unwrap();
            }
        }
    }

    /// Runs everywhere; Windows checks secret files' owners this way. Any
    /// other owner could change the file's list again at any time.
    #[test]
    fn windows_secret_files_must_be_owned_by_this_account_or_administrators() {
        let me = "S-1-5-21-1004336348-1177238915-682003330-1001";
        for trusted in [
            format!("O:{me}"),
            format!("O:{}", me.to_lowercase()),
            "O:BA".to_owned(),
            "O:SY".to_owned(),
            "O:LA".to_owned(),
            "O:S-1-5-18".to_owned(),
            "O:S-1-5-32-544".to_owned(),
        ] {
            trusted_owner(&trusted, me).unwrap_or_else(|e| panic!("{trusted}: {e}"));
        }
        for other in [
            "O:S-1-5-21-1004336348-1177238915-682003330-1002",
            "O:BU",
            "O:AU",
            "O:WD",
            "O:",
            "",
            "S-1-5-18",
            "D:P(A;;FA;;;SY)",
        ] {
            assert!(trusted_owner(other, me).is_err(), "{other}");
        }
    }

    /// Runs everywhere; Windows reads key files' lists this way.
    #[test]
    fn windows_key_access_lists_let_in_only_this_account_system_and_administrators() {
        let me = "S-1-5-21-1004336348-1177238915-682003330-1001";
        for private in [
            // What write_private and keygen set.
            format!("D:P(A;;FA;;;{me})"),
            format!("D:PAI(A;;FA;;;{me})"),
            // Inherited from a profile folder.
            format!("D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{me})"),
            format!(
                "D:P(A;;FA;;;LA)(A;;FR;;;S-1-5-18)(A;;FA;;;{})",
                me.to_lowercase()
            ),
            // Denials only take access away, here with a condition of its own.
            format!("D:P(D;;FA;;;WD)(XD;;FX;;;WD;(@User.Title==\"x\"))(A;;FA;;;{me})"),
            format!("D:P(A;;FA;;;{me})S:(ML;;NW;;;LW)"),
            "D:P".to_owned(),
        ] {
            owner_only_access_list(&private, me).unwrap_or_else(|e| panic!("{private}: {e}"));
        }
        for shared in [
            // A folder that lets Users read, or Authenticated Users change.
            format!("D:AI(A;ID;FA;;;SY)(A;ID;0x1200a9;;;BU)(A;ID;FA;;;{me})"),
            format!("D:AI(A;ID;0x1301bf;;;AU)(A;ID;FA;;;{me})"),
            format!("D:P(A;;FA;;;{me})(A;;FR;;;S-1-5-21-1004336348-1177238915-682003330-1002)"),
            format!("D:P(A;;FA;;;{me})(XA;;FR;;;WD;(@User.Title==\"x\"))"),
            // A null list lets every account in.
            "D:NO_ACCESS_CONTROL".to_owned(),
            // Anything unrecognized.
            String::new(),
            format!("O:BAD:P(A;;FA;;;{me})"),
            format!("D:P(A;;FA;;;{me}"),
            "D:P(A;;FA)".to_owned(),
            format!("D:P(A;;FA;;;{me})x"),
        ] {
            assert!(owner_only_access_list(&shared, me).is_err(), "{shared}");
        }
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
        assert_eq!(
            fs::read(&adopted).unwrap(),
            b"identity",
            "an existing sidecar wins"
        );
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

    /// A key another account can read is refused, as group or other
    /// permission bits are on Unix, until that access is removed again.
    #[cfg(windows)]
    #[test]
    fn windows_key_files_other_accounts_can_read_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key.json");
        write_private(&path, b"secret").unwrap();
        assert_eq!(read_private(&path, 64).unwrap().as_slice(), b"secret");
        let users = |change: &str, entry: &str| {
            let arguments: [OsString; 4] = [
                path.as_path().into(),
                change.into(),
                entry.into(),
                "/q".into(),
            ];
            windows::run("icacls.exe", &arguments).unwrap();
        };
        users("/grant", "*S-1-5-32-545:R");
        let error = read_private(&path, 64).unwrap_err();
        assert!(
            format!("{error:#}").contains("another account"),
            "{error:#}"
        );
        users("/remove:g", "*S-1-5-32-545");
        assert_eq!(read_private(&path, 64).unwrap().as_slice(), b"secret");
    }

    /// A path that cannot be protected is an error, never a warning.
    #[test]
    fn restricting_a_missing_file_fails() {
        let directory = tempfile::tempdir().unwrap();
        assert!(restrict_to_owner(&directory.path().join("missing.json")).is_err());
    }

    /// `path`'s access list as SDDL.
    #[cfg(windows)]
    fn dacl(path: &Path) -> String {
        windows::access_list(path).unwrap()
    }

    /// One protected entry granting this account full control, nothing else.
    #[cfg(windows)]
    pub(crate) fn assert_owner_only(path: &Path) {
        let sid = windows::current_sid().unwrap();
        let list = dacl(path);
        let (flags, entries) = list.split_at(list.find('(').unwrap());
        assert!(flags.starts_with("D:P"), "{}: {list}", path.display());
        assert_eq!(entries, format!("(A;;FA;;;{sid})"), "{}", path.display());
    }

    /// On NTFS, where an access list can be set, it is, so this reads the
    /// list back. Every secret file path, new or existing, ends with one
    /// protected entry granting this account full control and nothing
    /// inherited from its directory.
    #[cfg(windows)]
    #[test]
    fn windows_secret_files_list_only_the_current_account() {
        let directory = tempfile::tempdir().unwrap();
        let written = directory.path().join("written.json");
        write_private(&written, b"secret").unwrap();
        let created = directory.path().join("created.json");
        create_private(&created).unwrap();
        let existing = directory.path().join("existing.json");
        fs::write(&existing, b"secret").unwrap();
        assert!(
            dacl(&existing).contains("(A;ID;"),
            "temporary files inherit entries"
        );
        restrict_to_owner(&existing).unwrap();
        for path in [&written, &created, &existing] {
            assert_owner_only(path);
        }
    }

    /// Where the volume keeps access lists, failing to set one is an error,
    /// not a warning. This file's list leaves its owner, this account, only
    /// read access (an OWNER RIGHTS entry replaces the owner's implicit right
    /// to change the list), so icacls cannot restrict it; an account whose
    /// privileges still let it may succeed, and then the file is owner-only.
    #[cfg(windows)]
    #[test]
    fn windows_access_list_failures_are_errors_on_ntfs() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("locked.json");
        fs::write(&path, b"secret").unwrap();
        assert!(
            windows::keeps_access_lists(&fs::File::open(&path).unwrap()).unwrap(),
            "the temporary directory keeps access lists"
        );
        let arguments: [OsString; 5] = [
            path.as_path().into(),
            "/inheritance:r".into(),
            "/grant:r".into(),
            "*S-1-3-4:R".into(),
            "/q".into(),
        ];
        windows::run("icacls.exe", &arguments).unwrap();
        let locked = dacl(&path);
        assert!(
            locked.starts_with("D:P")
                && locked.ends_with(";;;OW)")
                && locked.matches('(').count() == 1,
            "{locked}"
        );
        match restrict_to_owner(&path) {
            Ok(()) => assert_owner_only(&path),
            Err(error) => assert!(
                format!("{error:#}").contains("cannot restrict"),
                "{error:#}"
            ),
        }
    }

    /// Grants BUILTIN\Users (S-1-5-32-545) `rights` on `path` with icacls, as
    /// an operator's folder or a restored copy may.
    #[cfg(windows)]
    fn grant_users(path: &Path, rights: &str) {
        let arguments: [OsString; 4] = [
            path.into(),
            "/grant".into(),
            format!("*S-1-5-32-545:{rights}").into(),
            "/q".into(),
        ];
        windows::run("icacls.exe", &arguments).unwrap();
    }

    /// Whether `path` is a file `create_private` or `create_new_private`
    /// created in this process, owner-only from its first moment, rather than
    /// one SQLite or another library created with the folder's inherited list
    /// and something restricted afterwards.
    #[cfg(windows)]
    pub(crate) fn created_owner_only(path: &Path) -> bool {
        let file = fs::OpenOptions::new()
            .access_mode(windows::FILE_READ_ATTRIBUTES)
            .share_mode(windows::FILE_SHARE_ALL)
            .open(path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let identity = windows::identity(&file).unwrap();
        windows::CREATED.lock().unwrap().contains(&identity)
    }

    /// A directory that lets Users read everything created inside it, as one
    /// under C:\ or ProgramData does.
    #[cfg(windows)]
    pub(crate) fn shared_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        grant_users(directory.path(), "(OI)(CI)R");
        let probe = directory.path().join("probe");
        fs::write(&probe, b"").unwrap();
        assert!(
            dacl(&probe).contains(";;;BU)"),
            "files created here let Users read them: {}",
            dacl(&probe)
        );
        fs::remove_file(&probe).unwrap();
        directory
    }

    /// The system gives a new secret file its owner-only list as it creates
    /// it, so no other account can open a handle first: one opened in the
    /// moment before a later restriction would keep its access. The list is
    /// checked while the creating handle is still open, before anything else
    /// could restrict it, in a folder whose inherited list lets Users read.
    #[cfg(windows)]
    #[test]
    fn windows_secret_files_are_owner_only_from_creation_in_shared_folders() {
        let directory = shared_directory();
        for new_only in [true, false] {
            let path = directory.path().join(format!("created-{new_only}.json"));
            let (file, existed) = windows::open_private(&path, new_only).unwrap();
            assert!(!existed);
            assert_owner_only(&path);
            drop(file);
        }
        let token = directory.path().join("session-token");
        let mut file = create_new_private(&token).unwrap();
        assert_owner_only(&token);
        file.write_all(b"token").unwrap();
        drop(file);
        write_private(&directory.path().join("written"), b"secret").unwrap();
        create_private(&directory.path().join("journal")).unwrap();
        for name in ["session-token", "written", "journal"] {
            assert_owner_only(&directory.path().join(name));
            assert!(created_owner_only(&directory.path().join(name)), "{name}");
        }
        // A file created otherwise and restricted afterwards is told apart.
        let restricted = directory.path().join("restricted");
        fs::write(&restricted, b"secret").unwrap();
        create_private(&restricted).unwrap();
        assert_owner_only(&restricted);
        assert!(!created_owner_only(&restricted));
        // A file a helper creates inside a private directory inherits only
        // this account's entry, before anything restricts it.
        let staging = directory.path().join("staging");
        create_private_directory(&staging).unwrap();
        let list = dacl(&staging);
        assert!(list.starts_with("D:P"), "{list}");
        assert!(
            create_private_directory(&staging).is_err(),
            "only a new one"
        );
        let staged = staging.join("key.json");
        fs::write(&staged, b"secret").unwrap();
        let sid = windows::current_sid().unwrap();
        let list = dacl(&staged);
        assert!(
            list.ends_with(&format!("(A;ID;FA;;;{sid})")) && list.matches('(').count() == 1,
            "only this account's inherited entry: {list}"
        );
        owner_only_access_list(&list, sid).unwrap();
    }

    /// The current account is compared as the system writes it in access
    /// lists, where service accounts have short aliases: compared by SID, a
    /// node running as NETWORK SERVICE would refuse its own files.
    #[cfg(windows)]
    #[test]
    fn windows_accounts_compare_as_the_system_writes_them() {
        for (sid, alias) in [
            ("S-1-5-18", "SY"),
            ("S-1-5-19", "LS"),
            ("S-1-5-20", "NS"),
            ("S-1-5-32-544", "BA"),
            (
                "S-1-5-21-1004336348-1177238915-682003330-1001",
                "S-1-5-21-1004336348-1177238915-682003330-1001",
            ),
        ] {
            assert_eq!(windows::spelled(sid).unwrap(), alias);
        }
        let me = windows::current_sid().unwrap();
        assert_eq!(windows::spelled(me).unwrap(), me);
        let alias = windows::spelled("S-1-5-20").unwrap();
        owner_only_access_list(&format!("D:P(A;;FA;;;{alias})"), &alias).unwrap();
        trusted_owner(&format!("O:{alias}"), &alias).unwrap();
    }

    /// Restricting an existing secret file replaces its whole list: entries
    /// granted explicitly to other accounts go too, not only inherited ones,
    /// and the result is read back. icacls's /inheritance:r with /grant:r kept
    /// such an entry, so the wallet database a restore or an operator had
    /// shared stayed readable.
    #[cfg(windows)]
    #[test]
    fn windows_restriction_removes_other_accounts_explicit_entries() {
        let directory = tempfile::tempdir().unwrap();
        let restricted = directory.path().join("chain.wallets.sqlite");
        let reopened = directory.path().join("chain.wallets.sqlite-journal");
        for path in [&restricted, &reopened] {
            fs::write(path, b"secret").unwrap();
            grant_users(path, "R");
            let list = dacl(path);
            assert!(
                list.contains("(A;;") && list.contains(";;;BU)"),
                "an explicit entry for Users: {list}"
            );
        }
        restrict_to_owner(&restricted).unwrap();
        create_private(&reopened).unwrap();
        for path in [&restricted, &reopened] {
            assert_owner_only(path);
            assert_eq!(fs::read(path).unwrap(), b"secret", "contents kept");
        }
    }

    /// Spending keys the operator names are read even when other accounts
    /// can read them, but the reader says so; the size and file type are
    /// still enforced.
    #[test]
    fn operator_secrets_are_read_with_a_warning_when_others_can_read_them() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("miner.key");
        write_private(&path, b"secret").unwrap();
        let (bytes, warning) = read_operator_secret(&path, 6).unwrap();
        assert_eq!((bytes.as_slice(), warning), (&b"secret"[..], None));
        assert!(
            read_operator_secret(&path, 5).is_err(),
            "larger than the limit"
        );
        assert!(
            read_operator_secret(directory.path(), 4096).is_err(),
            "a directory"
        );
        assert!(read_operator_secret(&directory.path().join("missing"), 4096).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            let link = directory.path().join("link.key");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            for read in [&path, &link] {
                let (bytes, warning) = read_operator_secret(read, 4096).unwrap();
                assert_eq!(bytes.as_slice(), b"secret");
                assert!(warning.unwrap().contains("mode 0644"));
            }
        }
        #[cfg(windows)]
        {
            grant_users(&path, "R");
            let (bytes, warning) = read_operator_secret(&path, 4096).unwrap();
            assert_eq!(bytes.as_slice(), b"secret");
            let warning = warning.unwrap();
            assert!(warning.contains("another account"), "{warning}");
        }
    }
}
