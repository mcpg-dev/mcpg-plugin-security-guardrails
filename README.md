# HTTP Guardrail Hooks — `dev.mcpg.guardrails`

> class `tool_gate` · `native` · package `mcpg-plugin-security-guardrails` · artifact `libmcpg_plugin_security_guardrails.so`

Calls external HTTP guardrail services before and/or after tool dispatch to
approve, deny, or mutate calls. Reach for it to integrate content scanners,
external PDPs, budget enforcers, or DLP services that can't be embedded as a
plugin.

## What it does
- Runs ordered chains of pre- and post-execution hooks. Each hook filters by
  tool-name glob (`tools` / `exclude_tools`, exclude wins) and an optional CEL
  `trigger_cel` (variables: `tool_name`, `trust_level`, `principal_id`,
  `auth_provider`).
- Active hooks POST a JSON envelope to the configured `url`; the service replies
  `{ "decision": "allow" | "deny", "reason"?, "modified_arguments"?, "modified_result"? }`.
- First `deny` short-circuits the chain (HTTP 403, code `-32050`). Mutations
  accumulate when `allow_mutation: true`.
- `on_error` decides behaviour when a service errors/times out: `deny`
  (fail-closed, default, HTTP 503) or `allow` (fail-open, continue).
- DNS-rebinding guard rejects responses from private/loopback IPs unless
  `allow_private_backends: true`.
- Requires capability `network_outbound`.

## Configuration
Loaded via the top-level `plugins:` list:

```yaml
plugins:
  - id: dev.mcpg.guardrails
    class: tool_gate
    source: { path: ./plugins/libmcpg_plugin_security_guardrails.so }
    config:
      apply_to_non_tool_surfaces: false
      allow_private_backends: false
      pre_execution:
        - name: pii-scanner             # used in metrics/logs
          url: https://scanner.svc/scan
          timeout_ms: 5000
          max_response_bytes: 65536
          on_error: deny                # "deny" (fail-closed) | "allow"
          allow_mutation: true
          tools: ["orders.*"]
          exclude_tools: ["orders.debug_*"]
          trigger_cel: 'trust_level == "verified"'
          headers: { Authorization: "Bearer ${env.SCANNER_TOKEN}" }
      post_execution: []
```

Top-level:

| Field | Type | Default | Description |
|---|---|---|---|
| `pre_execution` | hook[] | `[]` | Hooks run before tool dispatch. |
| `post_execution` | hook[] | `[]` | Hooks run after the tool returns. |
| `apply_to_non_tool_surfaces` | bool | `false` | Run hooks on non-tool surfaces too. |
| `allow_private_backends` | bool | `false` | Permit guardrail callouts to private/loopback IPs. |

Per hook (`pre_execution[]` / `post_execution[]`):

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | — | Hook identifier (metrics/logs/errors). |
| `url` | string | — | HTTP POST endpoint. |
| `timeout_ms` | u64 | `5000` | Per-call timeout. |
| `max_response_bytes` | usize | `65536` | Max response body size. |
| `on_error` | enum | `deny` | `deny` (fail-closed) or `allow` (fail-open). |
| `allow_mutation` | bool | `false` | Apply `modified_arguments` / `modified_result`. |
| `tools` | string[] | `[]` | Glob include patterns (empty = all tools). |
| `exclude_tools` | string[] | `[]` | Glob exclude patterns (take precedence). |
| `trigger_cel` | string? | `null` | CEL bool expression; `false` skips the hook. |
| `headers` | map | `{}` | Static headers sent to the service. |

A config that fails to parse or compile loads the plugin DISABLED (logs ERROR)
rather than silently using permissive defaults.

## Build
```bash
cargo build -p mcpg-plugin-security-guardrails --features cdylib-export --release   # → target/release/libmcpg_plugin_security_guardrails.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin system overview: `apps/gateway/docs/plugins.md`
- Full config reference: `apps/gateway/config.example.yaml`
