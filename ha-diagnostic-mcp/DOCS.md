# Diagnostic Tools

The server provides `search_entities`, `get_entity_state`, `list_unavailable_entities`, `get_entity_history`, registry/device/config-entry lookups, `diagnose_entity`, YAML configuration lookups, scoped configuration search, automation trace tools, `diagnose_automation`, error-log lookup, and safe system information.

Suggested questions:

- Why is `light.bedroom` unavailable? Inspect its diagnostic evidence and related integration entities.
- Look at `automation.hallway_lights`, its recent traces, and referenced-entity history. What evidence explains it not running last night?
- Is there configuration evidence that conflicts with `sensor.example`?
- Are unavailable entities related to one device or integration?

`diagnose_entity` and `diagnose_automation` aggregate evidence deterministically. They intentionally do not assert a root cause.

`get_homeassistant_logs` exposes only Home Assistant's supported current-session `/api/error_log` output. No host journal or arbitrary add-on logs are accessed. `check_configuration` is deliberately absent: the available REST API check endpoint is POST, and this server's v1 contract excludes all mutation-capable API methods.
