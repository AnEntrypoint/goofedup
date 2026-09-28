use super::pathing::Context;
use super::shell::{json_items, powershell_json};
use super::Finding;
use crate::alert::Level;

const CATEGORY: &str = "tamper-wmi";

const QUERY: &str = "$ErrorActionPreference = 'Stop'; \
    try { \
      $rows = @(); \
      foreach ($class in 'CommandLineEventConsumer','ActiveScriptEventConsumer','NTEventLogEventConsumer','SMTPEventConsumer','__EventFilter') { \
        Get-CimInstance -Namespace root\\subscription -ClassName $class | ForEach-Object { \
          $detail = switch ($class) { \
            'CommandLineEventConsumer' { \"$($_.ExecutablePath) $($_.CommandLineTemplate)\" } \
            'ActiveScriptEventConsumer' { \"$($_.ScriptingEngine) script of $($_.ScriptText.Length) chars\" } \
            '__EventFilter' { $_.Query } \
            default { $_.Name } }; \
          $rows += [pscustomobject]@{ Kind = $class; Name = $_.Name; Detail = $detail } } }; \
      ConvertTo-Json -InputObject @($rows) -Compress \
    } catch { [pscustomobject]@{ Error = $_.Exception.Message } | ConvertTo-Json -Compress }";

pub fn event_subscriptions(_ctx: &Context) -> Vec<Finding> {
    let Some(root) = powershell_json(QUERY) else {
        return vec![Finding::limited_visibility(CATEGORY, "WMI root\\subscription could not be queried")];
    };
    if let Some(error) = root.get("Error").and_then(|e| e.as_str()) {
        return vec![Finding::limited_visibility(CATEGORY, format!("WMI root\\subscription query failed: {error}"))];
    }
    json_items(&root)
        .into_iter()
        .filter_map(|row| {
            let kind = row.get("Kind")?.as_str()?;
            let name = row.get("Name").and_then(|n| n.as_str()).unwrap_or("");
            let detail = row.get("Detail").and_then(|n| n.as_str()).unwrap_or("");
            let executes_code = matches!(kind, "CommandLineEventConsumer" | "ActiveScriptEventConsumer");
            Some(
                Finding::new(
                    if executes_code { Level::Critical } else { Level::Info },
                    CATEGORY,
                    format!("wmi:{}:{}", kind.to_lowercase(), name.to_lowercase()),
                    format!("WMI event subscription {kind} '{name}'{}", if executes_code { " executes code when its filter fires" } else { "" }),
                    detail.to_string(),
                )
                .tracked(),
            )
        })
        .collect()
}
