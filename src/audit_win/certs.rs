use super::pathing::Context;
use super::registry::{self, OpenError, Value};
use super::Finding;
use crate::alert::Level;
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

const CATEGORY: &str = "tamper-cert";
const ROOT_STORE: &str = "SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates";
const PROP_KEY_PROVIDER_INFO: u32 = 2;
const PROP_CERT_DER: u32 = 0x20;

struct ParsedCertificate {
    subject: String,
    issuer: String,
    subject_raw: Vec<u8>,
    issuer_raw: Vec<u8>,
}

fn read_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *buf.first()?;
    let first_len = *buf.get(1)? as usize;
    let (len, header) = if first_len & 0x80 == 0 {
        (first_len, 2)
    } else {
        let count = first_len & 0x7f;
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | *buf.get(2 + i)? as usize;
        }
        (len, 2 + count)
    };
    let end = header.checked_add(len)?;
    Some((tag, buf.get(header..end)?, buf.get(end..)?))
}

fn decode_string(tag: u8, bytes: &[u8]) -> String {
    if tag == 0x1E {
        let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

fn describe_name(name_seq: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut rdns = name_seq;
    while let Some((_, rdn, rest)) = read_tlv(rdns) {
        rdns = rest;
        let mut attrs = rdn;
        while let Some((_, attr, more)) = read_tlv(attrs) {
            attrs = more;
            let Some((_, oid, value_part)) = read_tlv(attr) else { continue };
            let Some((value_tag, value, _)) = read_tlv(value_part) else { continue };
            let label = match oid {
                [0x55, 0x04, 0x03] => "CN",
                [0x55, 0x04, 0x0A] => "O",
                [0x55, 0x04, 0x0B] => "OU",
                [0x55, 0x04, 0x06] => "C",
                _ => continue,
            };
            parts.push(format!("{label}={}", decode_string(value_tag, value)));
        }
    }
    parts.join(", ")
}

fn parse_certificate(der: &[u8]) -> Option<ParsedCertificate> {
    let (_, certificate, _) = read_tlv(der)?;
    let (_, tbs, _) = read_tlv(certificate)?;
    let (tag, _, after_first) = read_tlv(tbs)?;
    let after_version = if tag == 0xA0 { after_first } else { tbs };
    let (_, _serial, after_serial) = read_tlv(after_version)?;
    let (_, _algorithm, after_algorithm) = read_tlv(after_serial)?;
    let (_, issuer, after_issuer) = read_tlv(after_algorithm)?;
    let (_, _validity, after_validity) = read_tlv(after_issuer)?;
    let (_, subject, _) = read_tlv(after_validity)?;
    Some(ParsedCertificate {
        subject: describe_name(subject),
        issuer: describe_name(issuer),
        subject_raw: subject.to_vec(),
        issuer_raw: issuer.to_vec(),
    })
}

struct StoredCertificate {
    parsed: Option<ParsedCertificate>,
    has_private_key_link: bool,
}

fn parse_property_blob(blob: &[u8]) -> StoredCertificate {
    let mut cursor = blob;
    let mut der: Option<&[u8]> = None;
    let mut has_key = false;
    while cursor.len() >= 12 {
        let id = u32::from_le_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        let size = u32::from_le_bytes([cursor[8], cursor[9], cursor[10], cursor[11]]) as usize;
        let Some(data) = cursor.get(12..12 + size) else { break };
        match id {
            PROP_CERT_DER => der = Some(data),
            PROP_KEY_PROVIDER_INFO => has_key = true,
            _ => {}
        }
        cursor = &cursor[12 + size..];
    }
    StoredCertificate { parsed: der.and_then(parse_certificate), has_private_key_link: has_key }
}

fn organisation_is_trusted(ctx: &Context, description: &str) -> bool {
    let lowered = description.to_lowercase();
    ctx.cfg.trusted_root_cert_orgs.iter().any(|org| lowered.contains(&org.to_lowercase()))
}

fn store_findings(ctx: &Context, hive: HKEY, store_label: &str, is_user_store: bool) -> Vec<Finding> {
    let store = match registry::open(hive, ROOT_STORE) {
        Ok(store) => store,
        Err(OpenError::Denied) => {
            return vec![Finding::limited_visibility(CATEGORY, format!("{store_label} root store registry key is not readable"))]
        }
        Err(OpenError::Missing) => return Vec::new(),
    };
    let mut findings = Vec::new();
    for thumbprint in store.subkeys() {
        let Ok(entry) = store.open_child(&thumbprint) else { continue };
        let Some(Value::Bytes(blob)) = entry.value("Blob") else { continue };
        let stored = parse_property_blob(&blob);
        let (subject, issuer, self_signed) = match &stored.parsed {
            Some(c) => (c.subject.clone(), c.issuer.clone(), c.subject_raw == c.issuer_raw),
            None => ("<unparseable>".to_string(), "<unparseable>".to_string(), false),
        };
        let description = format!("{subject} {issuer}");
        let trusted_org = organisation_is_trusted(ctx, &description);
        let key_held_by_mkcert = subject.to_lowercase().contains("mkcert")
            && std::env::var("LOCALAPPDATA")
                .map(|d| std::path::Path::new(&d).join("mkcert").join("rootCA-key.pem").exists())
                .unwrap_or(false);
        let level = if is_user_store {
            if !stored.has_private_key_link && !key_held_by_mkcert {
                Level::Critical
            } else {
                Level::Warn
            }
        } else if stored.has_private_key_link {
            Level::Warn
        } else if trusted_org {
            Level::Info
        } else {
            Level::Warn
        };
        let provenance = if is_user_store {
            if stored.has_private_key_link || key_held_by_mkcert {
                "user-added root, private key is local (locally generated CA, can mint certs for any site)"
            } else {
                "user-added root with NO local private key (someone else can mint certs your browser will trust)"
            }
        } else if stored.has_private_key_link {
            "machine root with a local private key (locally generated CA)"
        } else if trusted_org {
            "machine root from a recognised CA organisation"
        } else {
            "machine root from an unrecognised organisation"
        };
        findings.push(
            Finding::new(
                level,
                CATEGORY,
                format!("cert:{store_label}:{}", thumbprint.to_lowercase()),
                format!("{store_label}\\Root certificate {subject}{}: {provenance}", if self_signed { " (self-signed)" } else { "" }),
                format!("thumbprint={thumbprint} issuer={issuer}"),
            )
            .tracked(),
        );
    }
    findings
}

pub fn root_stores(ctx: &Context) -> Vec<Finding> {
    let mut findings = store_findings(ctx, HKEY_CURRENT_USER, "CurrentUser", true);
    findings.extend(store_findings(ctx, HKEY_LOCAL_MACHINE, "LocalMachine", false));
    findings
}
