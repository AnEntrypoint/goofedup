use std::ffi::c_void;
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, BOOL, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows::Win32::Security::{
    CheckTokenMembership, GetTokenInformation, LookupAccountSidW, TokenElevation, TokenUser, PSID, SID_NAME_USE,
    TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub const SID_SYSTEM: &str = "S-1-5-18";
pub const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
pub const SID_USERS: &str = "S-1-5-32-545";
pub const SID_EVERYONE: &str = "S-1-1-0";
pub const SID_AUTHENTICATED_USERS: &str = "S-1-5-11";
pub const SID_CREATOR_OWNER: &str = "S-1-3-0";
pub const SID_TRUSTED_INSTALLER: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

pub fn sid_to_string(sid: PSID) -> Option<String> {
    unsafe {
        let mut out = PWSTR::null();
        ConvertSidToStringSidW(sid, &mut out).ok()?;
        let text = out.to_string().ok();
        let _ = LocalFree(HLOCAL(out.0 as *mut c_void));
        text
    }
}

pub fn account_name(sid: &str) -> Option<String> {
    unsafe {
        let mut psid = PSID::default();
        ConvertStringSidToSidW(&HSTRING::from(sid), &mut psid).ok()?;
        let mut name = vec![0u16; 256];
        let mut domain = vec![0u16; 256];
        let mut name_len = 256u32;
        let mut domain_len = 256u32;
        let mut usage = SID_NAME_USE::default();
        let looked_up = LookupAccountSidW(
            PCWSTR::null(),
            psid,
            PWSTR(name.as_mut_ptr()),
            &mut name_len,
            PWSTR(domain.as_mut_ptr()),
            &mut domain_len,
            &mut usage,
        );
        let _ = LocalFree(HLOCAL(psid.0));
        looked_up.ok()?;
        Some(format!(
            "{}\\{}",
            String::from_utf16_lossy(&domain[..domain_len as usize]),
            String::from_utf16_lossy(&name[..name_len as usize])
        ))
    }
}

fn with_process_token<T>(read: impl FnOnce(HANDLE) -> Option<T>) -> Option<T> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
        let result = read(token);
        let _ = CloseHandle(token);
        result
    }
}

fn enabled_administrator() -> bool {
    unsafe {
        let mut admins = PSID::default();
        if ConvertStringSidToSidW(&HSTRING::from(SID_ADMINISTRATORS), &mut admins).is_err() {
            return false;
        }
        let mut member = BOOL::default();
        let checked = CheckTokenMembership(HANDLE::default(), admins, &mut member);
        let _ = LocalFree(HLOCAL(admins.0));
        checked.is_ok() && member.as_bool()
    }
}

pub fn is_elevated() -> bool {
    enabled_administrator() && token_is_elevated()
}

fn token_is_elevated() -> bool {
    with_process_token(|token| unsafe {
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .ok()?;
        Some(elevation.TokenIsElevated != 0)
    })
    .unwrap_or(false)
}

pub fn current_user_sid() -> Option<String> {
    with_process_token(|token| unsafe {
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        let mut buffer = vec![0u8; needed as usize];
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut c_void),
            needed,
            &mut needed,
        )
        .ok()?;
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        sid_to_string(user.User.Sid)
    })
}
