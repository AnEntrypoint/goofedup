use super::acl::account_name;
use super::pathing::Context;
use super::Finding;
use crate::alert::Level;
use std::collections::HashSet;
use std::ffi::c_void;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetLocalGroupGetMembers, NetUserEnum, FILTER_NORMAL_ACCOUNT, LOCALGROUP_MEMBERS_INFO_1,
    MAX_PREFERRED_LENGTH, USER_INFO_1,
};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::PSID;

const CATEGORY: &str = "tamper-account";
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
const UF_ACCOUNTDISABLE: u32 = 0x0002;
const UF_PASSWD_NOTREQD: u32 = 0x0020;

fn administrators_group_name() -> Option<String> {
    unsafe {
        let mut sid = PSID::default();
        ConvertStringSidToSidW(&HSTRING::from(ADMINISTRATORS_SID), &mut sid).ok()?;
        let name = account_name(sid).and_then(|full| full.rsplit('\\').next().map(str::to_string));
        let _ = LocalFree(HLOCAL(sid.0));
        name
    }
}

fn local_admin_members() -> Option<Vec<String>> {
    let group = administrators_group_name()?;
    unsafe {
        let mut buffer: *mut u8 = std::ptr::null_mut();
        let mut read = 0u32;
        let mut total = 0u32;
        let status = NetLocalGroupGetMembers(
            PCWSTR::null(),
            &HSTRING::from(group),
            1,
            &mut buffer,
            MAX_PREFERRED_LENGTH,
            &mut read,
            &mut total,
            None,
        );
        if status != 0 || buffer.is_null() {
            return None;
        }
        let members = std::slice::from_raw_parts(buffer as *const LOCALGROUP_MEMBERS_INFO_1, read as usize);
        let names = members.iter().filter_map(|m| m.lgrmi1_name.to_string().ok()).collect();
        let _ = NetApiBufferFree(Some(buffer as *const c_void));
        Some(names)
    }
}

struct LocalUser {
    name: String,
    disabled: bool,
    password_not_required: bool,
}

fn local_users() -> Option<Vec<LocalUser>> {
    unsafe {
        let mut buffer: *mut u8 = std::ptr::null_mut();
        let mut read = 0u32;
        let mut total = 0u32;
        let status = NetUserEnum(PCWSTR::null(), 1, FILTER_NORMAL_ACCOUNT, &mut buffer, MAX_PREFERRED_LENGTH, &mut read, &mut total, None);
        if status != 0 || buffer.is_null() {
            return None;
        }
        let entries = std::slice::from_raw_parts(buffer as *const USER_INFO_1, read as usize);
        let users = entries
            .iter()
            .filter_map(|u| {
                Some(LocalUser {
                    name: u.usri1_name.to_string().ok()?,
                    disabled: u.usri1_flags.0 & UF_ACCOUNTDISABLE != 0,
                    password_not_required: u.usri1_flags.0 & UF_PASSWD_NOTREQD != 0,
                })
            })
            .collect();
        let _ = NetApiBufferFree(Some(buffer as *const c_void));
        Some(users)
    }
}

pub fn local_accounts(_ctx: &Context) -> Vec<Finding> {
    let admins = local_admin_members().unwrap_or_default();
    let admin_user_names: HashSet<String> =
        admins.iter().map(|m| m.rsplit('\\').next().unwrap_or(m).to_lowercase()).collect();
    let mut findings: Vec<Finding> = admins
        .iter()
        .map(|member| {
            Finding::new(
                Level::Info,
                CATEGORY,
                format!("account:admin:{}", member.to_lowercase()),
                format!("'{member}' is a member of the local Administrators group"),
                String::new(),
            )
            .tracked()
        })
        .collect();
    for user in local_users().unwrap_or_default() {
        if user.disabled || !user.password_not_required {
            continue;
        }
        let is_admin = admin_user_names.contains(&user.name.to_lowercase());
        findings.push(
            Finding::new(
                if is_admin { Level::Critical } else { Level::Warn },
                CATEGORY,
                format!("account:no-password:{}", user.name.to_lowercase()),
                format!(
                    "enabled local account '{}' does not require a password{}",
                    user.name,
                    if is_admin { " and is a local administrator" } else { "" }
                ),
                "UF_PASSWD_NOTREQD is set".to_string(),
            )
            .tracked(),
        );
    }
    findings
}
