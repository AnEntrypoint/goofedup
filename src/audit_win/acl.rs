use std::collections::BTreeMap;
use std::ffi::c_void;
use std::path::Path;
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, LookupAccountSidW, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SID_NAME_USE,
};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 10;
const INHERIT_ONLY_ACE: u8 = 0x08;

const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_DELETE_CHILD: u32 = 0x0000_0040;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;

#[derive(Clone, Debug)]
pub enum Exposure {
    Protected,
    Writable { via: &'static str, writers: Vec<String> },
    Plantable { writers: Vec<String> },
    Missing,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    File,
    DirReplace,
    DirAdd,
}

fn write_mask(target: Target) -> u32 {
    let common = GENERIC_ALL | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER;
    match target {
        Target::File => common | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE,
        Target::DirReplace => common | FILE_DELETE_CHILD,
        Target::DirAdd => common | FILE_WRITE_DATA | FILE_DELETE_CHILD,
    }
}

fn is_trusted_principal(sid: &str) -> bool {
    matches!(
        sid,
        "S-1-5-18" | "S-1-5-32-544" | "S-1-3-0" | "S-1-3-1" | "S-1-5-19" | "S-1-5-20" | "S-1-5-32-548" | "S-1-5-32-549" | "S-1-5-32-551"
    ) || sid.starts_with("S-1-5-80-")
        || sid.starts_with("S-1-5-83-")
        || sid.starts_with("S-1-15-2-")
        || sid.starts_with("S-1-15-3-")
        || (sid.starts_with("S-1-5-21-") && (sid.ends_with("-500") || sid.ends_with("-512") || sid.ends_with("-519")))
}

unsafe fn sid_to_string(sid: PSID) -> Option<String> {
    let mut text = PWSTR::null();
    ConvertSidToStringSidW(sid, &mut text).ok()?;
    let converted = text.to_string().ok();
    let _ = LocalFree(HLOCAL(text.0 as *mut c_void));
    converted
}

pub unsafe fn account_name(sid: PSID) -> Option<String> {
    let mut name = [0u16; 256];
    let mut domain = [0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain_len = domain.len() as u32;
    let mut usage = SID_NAME_USE::default();
    LookupAccountSidW(
        PCWSTR::null(),
        sid,
        PWSTR(name.as_mut_ptr()),
        &mut name_len,
        PWSTR(domain.as_mut_ptr()),
        &mut domain_len,
        &mut usage,
    )
    .ok()?;
    let name = String::from_utf16_lossy(&name[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
    Some(if domain.is_empty() { name } else { format!("{domain}\\{name}") })
}

#[derive(Default)]
struct PrincipalRights {
    allowed: u32,
    denied: u32,
    display: String,
}

unsafe fn untrusted_writers(owner: PSID, dacl: *mut ACL, target: Target) -> Vec<String> {
    if dacl.is_null() {
        return vec!["Everyone (NULL DACL)".to_string()];
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    let queried = GetAclInformation(
        dacl,
        &mut info as *mut ACL_SIZE_INFORMATION as *mut c_void,
        std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
        AclSizeInformation,
    );
    if queried.is_err() {
        return Vec::new();
    }
    let mask = write_mask(target);
    let mut principals: BTreeMap<String, PrincipalRights> = BTreeMap::new();
    for index in 0..info.AceCount {
        let mut ace_ptr: *mut c_void = std::ptr::null_mut();
        if GetAce(dacl, index, &mut ace_ptr).is_err() || ace_ptr.is_null() {
            continue;
        }
        let header = &*(ace_ptr as *const ACE_HEADER);
        if header.AceFlags & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        let is_allow = matches!(header.AceType, ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE);
        let is_deny = matches!(header.AceType, ACCESS_DENIED_ACE_TYPE | ACCESS_DENIED_CALLBACK_ACE_TYPE);
        if !is_allow && !is_deny {
            continue;
        }
        let ace = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);
        let sid = PSID(&ace.SidStart as *const u32 as *mut c_void);
        let Some(sid_text) = sid_to_string(sid) else { continue };
        if is_trusted_principal(&sid_text) {
            continue;
        }
        let entry = principals.entry(sid_text.clone()).or_insert_with(|| PrincipalRights {
            display: account_name(sid).unwrap_or(sid_text.clone()),
            ..Default::default()
        });
        if is_allow {
            entry.allowed |= ace.Mask;
        } else {
            entry.denied |= ace.Mask;
        }
    }
    let mut writers: Vec<String> = principals
        .values()
        .filter(|p| (p.allowed & !p.denied) & mask != 0)
        .map(|p| p.display.clone())
        .collect();
    if !owner.0.is_null() {
        if let Some(owner_text) = sid_to_string(owner) {
            if !is_trusted_principal(&owner_text) && !principals.contains_key(&owner_text) {
                writers.push(format!("{} (owner)", account_name(owner).unwrap_or(owner_text)));
            }
        }
    }
    writers
}

fn writers_of(path: &Path, target: Target) -> Option<Vec<String>> {
    let wide = HSTRING::from(path.to_string_lossy().as_ref());
    unsafe {
        let mut owner = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let status = GetNamedSecurityInfoW(
            &wide,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            &mut descriptor,
        );
        if status.0 != 0 {
            return None;
        }
        let writers = untrusted_writers(owner, dacl, target);
        let _ = LocalFree(HLOCAL(descriptor.0));
        Some(writers)
    }
}

pub fn exposure(path: &Path) -> Exposure {
    if path.exists() {
        match writers_of(path, if path.is_dir() { Target::DirAdd } else { Target::File }) {
            None => return Exposure::Unknown,
            Some(writers) if !writers.is_empty() => return Exposure::Writable { via: "the target itself", writers },
            Some(_) => {}
        }
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if let Some(writers) = writers_of(parent, Target::DirReplace) {
                if !writers.is_empty() {
                    return Exposure::Writable { via: "its parent directory", writers };
                }
            }
        }
        return Exposure::Protected;
    }
    let existing_ancestor = path.ancestors().skip(1).find(|a| !a.as_os_str().is_empty() && a.exists());
    match existing_ancestor.and_then(|a| writers_of(a, Target::DirAdd)) {
        Some(writers) if !writers.is_empty() => Exposure::Plantable { writers },
        _ => Exposure::Missing,
    }
}
