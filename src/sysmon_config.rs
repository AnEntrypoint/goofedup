use std::path::Path;

pub const RECOMMENDED_CONFIG: &str = include_str!("../sysmon/goofedup-sysmon.xml");

pub fn emit(target: Option<&Path>) -> std::io::Result<()> {
    match target {
        None => {
            print!("{RECOMMENDED_CONFIG}");
            Ok(())
        }
        Some(path) => {
            std::fs::write(path, RECOMMENDED_CONFIG)?;
            eprintln!("wrote {} ({} bytes)", path.display(), RECOMMENDED_CONFIG.len());
            eprintln!("nothing was applied; review it, then apply from an elevated prompt with: Sysmon64.exe -c \"{}\"", path.display());
            Ok(())
        }
    }
}
