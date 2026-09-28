use crate::config::Config;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::SystemTime;

pub type ImageKey = (PathBuf, SystemTime, u64);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trust {
    Valid(String),
    Invalid,
    Unsigned,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct ImageRecord {
    pub key: ImageKey,
    pub trust: Trust,
    pub sha256: Option<String>,
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UnsignedMode {
    Warn,
    Critical,
    Off,
}

impl UnsignedMode {
    pub fn label(self) -> &'static str {
        match self {
            UnsignedMode::Warn => "warn",
            UnsignedMode::Critical => "critical",
            UnsignedMode::Off => "off",
        }
    }
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct UnsignedUserWritablePolicy {
    pub mode: UnsignedMode,
    pub trusted_sha256: Vec<String>,
}

impl Default for UnsignedUserWritablePolicy {
    fn default() -> Self {
        Self { mode: UnsignedMode::Warn, trusted_sha256: Vec::new() }
    }
}

pub fn default_trusted_publishers() -> Vec<String> {
    [
        "Microsoft Corporation",
        "Microsoft Windows",
        "Microsoft Windows Publisher",
        "Google LLC",
        "Mozilla Corporation",
        "Discord Inc.",
        "GitHub, Inc.",
        "Rust Foundation",
        "Node.js Foundation",
        "OpenJS Foundation",
        "Python Software Foundation",
        "Anthropic, PBC",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

pub const fn verification_available() -> bool {
    cfg!(windows)
}

pub fn publisher_is_trusted(publisher: &str, trusted: &[String]) -> bool {
    let publisher = publisher.trim().to_lowercase();
    trusted.iter().any(|entry| {
        let entry = entry.trim().to_lowercase();
        match entry.strip_suffix('*') {
            Some(prefix) => publisher.starts_with(prefix),
            None => publisher == entry,
        }
    })
}

pub fn hash_is_pinned(record: &ImageRecord, policy: &UnsignedUserWritablePolicy) -> bool {
    record
        .sha256
        .as_deref()
        .is_some_and(|hash| policy.trusted_sha256.iter().any(|pinned| pinned.trim().eq_ignore_ascii_case(hash)))
}

fn path_is_under(path_lower: &str, root: &Path) -> bool {
    let root_lower = root.to_string_lossy().to_lowercase();
    let root_lower = root_lower.trim_end_matches(['\\', '/']);
    if root_lower.is_empty() || !path_lower.starts_with(root_lower) {
        return false;
    }
    matches!(path_lower[root_lower.len()..].chars().next(), None | Some('\\') | Some('/'))
}

fn root_is_admin_only(root: &Path) -> bool {
    !root
        .file_name()
        .is_some_and(|name| name.to_string_lossy().to_lowercase().starts_with("python"))
}

pub fn is_under_admin_only_root(cfg: &Config, exe_path: &str) -> bool {
    let path_lower = exe_path.to_lowercase();
    cfg.os_vendor_roots
        .iter()
        .filter(|root| root_is_admin_only(root))
        .any(|root| path_is_under(&path_lower, root))
}

pub fn is_public_ip(ip: &str) -> bool {
    let Ok(addr) = ip.trim_matches(['[', ']']).parse::<std::net::IpAddr>() else {
        return false;
    };
    match addr {
        std::net::IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || (a == 100 && (64..=127).contains(&b)))
        }
        std::net::IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            !(v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80)
        }
    }
}

const CACHE_CAPACITY: usize = 2048;
const REQUEST_QUEUE_CAPACITY: usize = 512;
const WORKER_COUNT: usize = 2;

struct Store {
    records: HashMap<ImageKey, ImageRecord>,
    insertion_order: VecDeque<ImageKey>,
    in_flight: HashSet<ImageKey>,
}

struct Service {
    store: Arc<Mutex<Store>>,
    requests: SyncSender<ImageKey>,
}

fn service() -> &'static Service {
    static SERVICE: OnceLock<Service> = OnceLock::new();
    SERVICE.get_or_init(|| {
        let store = Arc::new(Mutex::new(Store {
            records: HashMap::new(),
            insertion_order: VecDeque::new(),
            in_flight: HashSet::new(),
        }));
        let (requests, receiver) = sync_channel::<ImageKey>(REQUEST_QUEUE_CAPACITY);
        let receiver = Arc::new(Mutex::new(receiver));
        for _ in 0..WORKER_COUNT {
            let store = store.clone();
            let receiver = receiver.clone();
            std::thread::spawn(move || worker_loop(store, receiver));
        }
        Service { store, requests }
    })
}

fn worker_loop(store: Arc<Mutex<Store>>, receiver: Arc<Mutex<Receiver<ImageKey>>>) {
    loop {
        let next = receiver.lock().unwrap_or_else(PoisonError::into_inner).recv();
        let Ok(key) = next else { return };
        let record = evaluate(&key);
        let mut store = store.lock().unwrap_or_else(PoisonError::into_inner);
        store.in_flight.remove(&key);
        if store.records.insert(key.clone(), record).is_none() {
            store.insertion_order.push_back(key);
        }
        while store.insertion_order.len() > CACHE_CAPACITY {
            if let Some(oldest) = store.insertion_order.pop_front() {
                store.records.remove(&oldest);
            }
        }
    }
}

fn evaluate(key: &ImageKey) -> ImageRecord {
    let trust = verify_signature(&key.0);
    let sha256 = match trust {
        Trust::Unsigned | Trust::Invalid => sha256_hex(&key.0),
        _ => None,
    };
    ImageRecord { key: key.clone(), trust, sha256 }
}

fn sha256_hex(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Some(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn key_for(path: &Path) -> Option<ImageKey> {
    let meta = std::fs::metadata(path).ok()?;
    Some((path.to_path_buf(), meta.modified().ok()?, meta.len()))
}

pub fn lookup(path: &Path) -> Option<ImageRecord> {
    let Some(key) = key_for(path) else {
        return Some(ImageRecord { key: (path.to_path_buf(), SystemTime::UNIX_EPOCH, 0), trust: Trust::Unknown, sha256: None });
    };
    if !verification_available() {
        return Some(ImageRecord { key, trust: Trust::Unknown, sha256: None });
    }
    let service = service();
    let mut store = service.store.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(record) = store.records.get(&key) {
        return Some(record.clone());
    }
    if store.in_flight.insert(key.clone()) && service.requests.try_send(key.clone()).is_err() {
        store.in_flight.remove(&key);
    }
    None
}

#[cfg(not(windows))]
fn verify_signature(_path: &Path) -> Trust {
    Trust::Unknown
}

#[cfg(windows)]
fn verify_signature(path: &Path) -> Trust {
    windows_impl::verify(path)
}

#[cfg(windows)]
mod windows_impl {
    use super::Trust;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::{BOOL, HANDLE, HWND};
    use windows::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash,
        CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
    };
    use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
    use windows::Win32::Security::WinTrust::{
        WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_FILE_INFO,
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800B0001u32 as i32;
    const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B0003u32 as i32;
    const TRUST_E_NOSIGNATURE: i32 = 0x800B0100u32 as i32;
    const CRYPT_E_FILE_ERROR: i32 = 0x80092003u32 as i32;
    const ERROR_FILE_NOT_FOUND: i32 = 0x80070002u32 as i32;
    const ERROR_ACCESS_DENIED: i32 = 0x80070005u32 as i32;
    const ERROR_SHARING_VIOLATION: i32 = 0x80070020u32 as i32;

    enum Outcome {
        Signed(String),
        NotSigned,
        Rejected,
        Unreadable,
    }

    fn classify(code: i32, publisher: Option<String>) -> Outcome {
        match code {
            0 => Outcome::Signed(publisher.unwrap_or_else(|| "unknown publisher".to_string())),
            TRUST_E_NOSIGNATURE | TRUST_E_PROVIDER_UNKNOWN | TRUST_E_SUBJECT_FORM_UNKNOWN => Outcome::NotSigned,
            CRYPT_E_FILE_ERROR | ERROR_FILE_NOT_FOUND | ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION => Outcome::Unreadable,
            _ => Outcome::Rejected,
        }
    }

    pub fn verify(path: &Path) -> Trust {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        match verify_embedded(&wide) {
            Outcome::Signed(publisher) => Trust::Valid(publisher),
            Outcome::Rejected => Trust::Invalid,
            Outcome::Unreadable => Trust::Unknown,
            Outcome::NotSigned => match verify_catalog(path, &wide) {
                Some(Outcome::Signed(publisher)) => Trust::Valid(publisher),
                Some(Outcome::Rejected) => Trust::Invalid,
                Some(Outcome::Unreadable) => Trust::Unknown,
                Some(Outcome::NotSigned) | None => Trust::Unsigned,
            },
        }
    }

    fn provider_flags() -> windows::Win32::Security::WinTrust::WINTRUST_DATA_PROVIDER_FLAGS {
        WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
    }

    fn verify_embedded(wide: &[u16]) -> Outcome {
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide.as_ptr()),
            ..Default::default()
        };
        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: provider_flags(),
            ..Default::default()
        };
        data.Anonymous.pFile = &mut file_info;
        let (code, publisher) = run_wintrust(&mut data);
        classify(code, publisher)
    }

    struct CatalogAdmin(isize);

    impl Drop for CatalogAdmin {
        fn drop(&mut self) {
            unsafe {
                let _ = CryptCATAdminReleaseContext(self.0, 0);
            }
        }
    }

    struct CatalogContext<'a> {
        admin: &'a CatalogAdmin,
        handle: isize,
    }

    impl Drop for CatalogContext<'_> {
        fn drop(&mut self) {
            unsafe {
                let _ = CryptCATAdminReleaseCatalogContext(self.admin.0, self.handle, 0);
            }
        }
    }

    fn verify_catalog(path: &Path, wide: &[u16]) -> Option<Outcome> {
        let file = std::fs::File::open(path).ok()?;
        for algorithm in [w!("SHA256"), w!("SHA1")] {
            let mut admin_handle = 0isize;
            if unsafe { CryptCATAdminAcquireContext2(&mut admin_handle, None, algorithm, None, 0) }.is_err() {
                continue;
            }
            let admin = CatalogAdmin(admin_handle);
            let file_handle = HANDLE(file.as_raw_handle());
            let mut hash_len = 0u32;
            unsafe {
                let _ = CryptCATAdminCalcHashFromFileHandle2(admin.0, file_handle, &mut hash_len, None, 0);
            }
            if hash_len == 0 {
                continue;
            }
            let mut hash = vec![0u8; hash_len as usize];
            if unsafe { CryptCATAdminCalcHashFromFileHandle2(admin.0, file_handle, &mut hash_len, Some(hash.as_mut_ptr()), 0) }
                .is_err()
            {
                continue;
            }
            let catalog_handle = unsafe { CryptCATAdminEnumCatalogFromHash(admin.0, &hash, 0, None) };
            if catalog_handle == 0 {
                continue;
            }
            let catalog = CatalogContext { admin: &admin, handle: catalog_handle };
            let mut catalog_info = CATALOG_INFO { cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32, ..Default::default() };
            if unsafe { CryptCATCatalogInfoFromContext(catalog.handle, &mut catalog_info, 0) }.is_err() {
                continue;
            }
            let member_tag: Vec<u16> = hash
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut catalog_wintrust = WINTRUST_CATALOG_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                pcwszCatalogFilePath: PCWSTR(catalog_info.wszCatalogFile.as_ptr()),
                pcwszMemberTag: PCWSTR(member_tag.as_ptr()),
                pcwszMemberFilePath: PCWSTR(wide.as_ptr()),
                pbCalculatedFileHash: hash.as_mut_ptr(),
                cbCalculatedFileHash: hash_len,
                hCatAdmin: admin.0,
                ..Default::default()
            };
            let mut data = WINTRUST_DATA {
                cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: WTD_REVOKE_NONE,
                dwUnionChoice: WTD_CHOICE_CATALOG,
                dwStateAction: WTD_STATEACTION_VERIFY,
                dwProvFlags: provider_flags(),
                ..Default::default()
            };
            data.Anonymous.pCatalog = &mut catalog_wintrust;
            let (code, publisher) = run_wintrust(&mut data);
            return Some(classify(code, publisher));
        }
        None
    }

    fn run_wintrust(data: &mut WINTRUST_DATA) -> (i32, Option<String>) {
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let no_window = HWND(-1isize as *mut c_void);
        let code = unsafe { WinVerifyTrust(no_window, &mut action, data as *mut WINTRUST_DATA as *mut c_void) };
        let publisher = if code == 0 { unsafe { signer_name(data) } } else { None };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe {
            WinVerifyTrust(no_window, &mut action, data as *mut WINTRUST_DATA as *mut c_void);
        }
        (code, publisher)
    }

    unsafe fn signer_name(data: &WINTRUST_DATA) -> Option<String> {
        let provider = WTHelperProvDataFromStateData(data.hWVTStateData);
        if provider.is_null() {
            return None;
        }
        let signer = WTHelperGetProvSignerFromChain(provider, 0, BOOL(0), 0);
        if signer.is_null() {
            return None;
        }
        let cert = WTHelperGetProvCertFromChain(signer, 0);
        if cert.is_null() || (*cert).pCert.is_null() {
            return None;
        }
        let mut buffer = [0u16; 256];
        let written = CertGetNameStringW((*cert).pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut buffer));
        let length = (written as usize).saturating_sub(1).min(buffer.len());
        (length > 0).then(|| String::from_utf16_lossy(&buffer[..length]))
    }
}
