use crate::config::{ConfigRow, ConfigSection};
use serde::Deserialize;

#[derive(Clone, Debug)]
pub struct TamperConfig {
    pub enabled: bool,
    pub poll_multiplier: u64,
    pub shell_scan_every_polls: u32,
    pub critical_exposure_ports: Vec<u16>,
    pub admin_exposure_ports: Vec<u16>,
    pub user_writable_fragments: Vec<String>,
    pub trusted_root_cert_orgs: Vec<String>,
    pub ignored_finding_keys: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct TamperOverrides {
    pub enabled: Option<bool>,
    pub poll_multiplier: Option<u64>,
    pub shell_scan_every_polls: Option<u32>,
    pub critical_exposure_ports: Option<Vec<u16>>,
    pub admin_exposure_ports: Option<Vec<u16>>,
    pub user_writable_fragments: Option<Vec<String>>,
    pub trusted_root_cert_orgs: Option<Vec<String>>,
    pub ignored_finding_keys: Option<Vec<String>>,
}

impl Default for TamperConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_multiplier: 10,
            shell_scan_every_polls: 20,
            critical_exposure_ports: vec![
                9222, 9223, 9224, 9225, 9226, 9227, 9228, 9229, 5858, 2375, 2376, 4243, 6379, 27017, 9200, 11211, 5984,
            ],
            admin_exposure_ports: vec![3389, 5985, 5986, 445, 22, 23, 5900, 5901],
            user_writable_fragments: [
                "\\appdata\\",
                "\\downloads\\",
                "\\desktop\\",
                "\\temp\\",
                "\\node_modules\\",
                "\\users\\public\\",
                "\\$recycle.bin\\",
                "c:\\dev\\",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            trusted_root_cert_orgs: [
                "microsoft",
                "digicert",
                "globalsign",
                "verisign",
                "symantec",
                "comodo",
                "sectigo",
                "usertrust",
                "entrust",
                "geotrust",
                "thawte",
                "baltimore",
                "godaddy",
                "starfield",
                "internet security research group",
                "amazon",
                "google trust services",
                "certum",
                "quovadis",
                "identrust",
                "network solutions",
                "swisssign",
                "buypass",
                "actalis",
                "cybertrust",
                "t-systems",
                "d-trust",
                "harica",
                "isrg",
                "affirmtrust",
                "certigna",
                "e-tugra",
                "ssl.com",
                "telia",
                "trustwave",
                "secom",
                "izenpe",
                "camerfirma",
                "hongkong post",
                "chunghwa",
                "twca",
                "netlock",
                "microsec",
                "dhimyotis",
                "disig",
                "accv",
                "ec-acc",
                "fnmt",
                "xrampsecurity",
                "aaa certificate services",
                "sonera",
                "turktrust",
                "go daddy",
                "emsign",
                "sk id solutions",
                "krajowa izba",
                "asseco",
                "gdca",
                "tubitak",
                "e-szigno",
                "certsign",
                "keynectis",
                "opentrust",
                "staat der nederlanden",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            ignored_finding_keys: Vec::new(),
        }
    }
}

impl TamperConfig {
    pub fn with_overrides(mut self, o: &TamperOverrides) -> Self {
        if let Some(v) = o.enabled {
            self.enabled = v;
        }
        if let Some(v) = o.poll_multiplier {
            self.poll_multiplier = v.max(1);
        }
        if let Some(v) = o.shell_scan_every_polls {
            self.shell_scan_every_polls = v.max(1);
        }
        if let Some(v) = &o.critical_exposure_ports {
            self.critical_exposure_ports = v.clone();
        }
        if let Some(v) = &o.admin_exposure_ports {
            self.admin_exposure_ports = v.clone();
        }
        if let Some(v) = &o.user_writable_fragments {
            self.user_writable_fragments = v.clone();
        }
        if let Some(v) = &o.trusted_root_cert_orgs {
            self.trusted_root_cert_orgs = v.clone();
        }
        if let Some(v) = &o.ignored_finding_keys {
            self.ignored_finding_keys = v.clone();
        }
        self
    }

    pub fn section(&self, o: &TamperOverrides) -> ConfigSection {
        fn marked(value: String, overridden: bool) -> String {
            if overridden {
                format!("{value} (from config file)")
            } else {
                value
            }
        }
        fn ports(list: &[u16]) -> String {
            list.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
        }
        ConfigSection {
            title: "Tamper Watch",
            description: "Windows posture watcher: portproxy rules, exposed debugger/admin listeners, inbound firewall allows, SYSTEM tasks and services with weak binaries, Defender state, root certificates, hosts file, local admins, plaintext credential files and autoruns. Alerts only on NEW or CHANGED findings after the startup baseline; run `goofedup --audit` for the full report. Configured under the \"tamper\" object in the override file.",
            rows: vec![
                ConfigRow { label: "Enabled".to_string(), value: marked(self.enabled.to_string(), o.enabled.is_some()) },
                ConfigRow {
                    label: "Poll multiplier".to_string(),
                    value: marked(format!("{}x poll interval", self.poll_multiplier), o.poll_multiplier.is_some()),
                },
                ConfigRow {
                    label: "Shell-backed scan every".to_string(),
                    value: marked(format!("{} polls", self.shell_scan_every_polls), o.shell_scan_every_polls.is_some()),
                },
                ConfigRow {
                    label: "Critical exposure ports".to_string(),
                    value: marked(ports(&self.critical_exposure_ports), o.critical_exposure_ports.is_some()),
                },
                ConfigRow {
                    label: "Admin exposure ports".to_string(),
                    value: marked(ports(&self.admin_exposure_ports), o.admin_exposure_ports.is_some()),
                },
                ConfigRow {
                    label: "User-writable path fragments".to_string(),
                    value: marked(self.user_writable_fragments.join(", "), o.user_writable_fragments.is_some()),
                },
                ConfigRow {
                    label: "Trusted root cert organisations".to_string(),
                    value: marked(format!("{} names", self.trusted_root_cert_orgs.len()), o.trusted_root_cert_orgs.is_some()),
                },
                ConfigRow {
                    label: "Ignored finding keys".to_string(),
                    value: marked(self.ignored_finding_keys.join(", "), o.ignored_finding_keys.is_some()),
                },
            ],
        }
    }
}
