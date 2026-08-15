//! # mcpg-plugin-security-guardrails
//!
//! HTTP guardrail hooks plugin for the MCPG gateway.
//!
//! Guardrails are external HTTP services called before and/or after tool execution.
//! They are distinct from the local policy gate (trust-level + CEL) — guardrails
//! handle content scanning, human approval, budget enforcement, and external PDP
//! callouts.
//!
//! ## How it works
//!
//! 1. At construction, guardrail hook configs are compiled (CEL triggers, glob patterns)
//! 2. On pre-dispatch, the chain iterates hooks in order:
//!    - Tool pattern matching (include/exclude globs)
//!    - CEL trigger evaluation (conditional activation)
//!    - Async HTTP POST to the guardrail service
//!    - Decision handling (allow/deny/mutate)
//! 3. On post-dispatch, same chain for result inspection/redaction
//!
//! The first `deny` short-circuits the chain. `allow` continues. Mutations accumulate.

mod glob;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use anyhow::Result;
use mcpg_plugin_protocol::{GateDecision, PluginClass, PluginContext, PluginManifest};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncToolGate;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info, info_span, warn};

const PLUGIN_ID: &str = "dev.mcpg.guardrails";

fn record_gate_outcome(phase: &'static str, decision: &GateDecision, elapsed: std::time::Duration) {
    let outcome = match decision {
        GateDecision::Allow { .. } => "allow",
        GateDecision::Deny { .. } => "deny",
        GateDecision::Challenge { .. } => "challenge",
        GateDecision::PendingApproval { .. } => "pending_approval",
    };
    metrics::counter!(
        "mcpg_guardrails_gate_decisions_total",
        "phase" => phase,
        "outcome" => outcome,
    )
    .increment(1);
    metrics::histogram!(
        "mcpg_guardrails_gate_evaluate_ms",
        "phase" => phase,
    )
    .record(elapsed.as_millis() as f64);
    match decision {
        GateDecision::Allow { .. } => debug!(
            phase = phase,
            elapsed_ms = %elapsed.as_millis(),
            "guardrails: allow"
        ),
        GateDecision::Deny { message, .. } => warn!(
            phase = phase,
            reason = %message,
            elapsed_ms = %elapsed.as_millis(),
            "guardrails: deny"
        ),
        GateDecision::Challenge { message, .. } => debug!(
            phase = phase,
            reason = %message,
            elapsed_ms = %elapsed.as_millis(),
            "guardrails: challenge"
        ),
        GateDecision::PendingApproval { approval_id, .. } => debug!(
            phase = phase,
            approval_id = %approval_id,
            elapsed_ms = %elapsed.as_millis(),
            "guardrails: pending approval"
        ),
    }
}

/// Shared PluginManifest constructor used by both `from_config` and
/// `empty` so the cdylib's `manifest_json` never drifts between
/// configured and disabled states.
fn default_manifest() -> PluginManifest {
    PluginManifest {
        id: PLUGIN_ID.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        name: "HTTP Guardrail Hooks".into(),
        plugin_class: PluginClass::ToolGate,
        protocol_version: "1.0".into(),
        license: None,
        required_capabilities: Vec::new(),
        tags: Vec::new(),
        provides: Vec::new(),
        provides_schemes: Vec::new(),
        module_path_prefix: ::std::module_path!()
            .split("::")
            .next()
            .unwrap_or("")
            .to_owned(),
        backend_profile: None,
    }
}

// ---------------------------------------------------------------------------
// Config types (operator-facing)
// ---------------------------------------------------------------------------

/// How the gateway behaves when a guardrail service is unreachable or returns an error.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailOnError {
    /// Block the tool call (fail-closed). This is the default.
    #[default]
    Deny,
    /// Allow the tool call to proceed (fail-open). Use with caution.
    Allow,
}

/// Configuration for a single guardrail hook (pre- or post-execution).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardrailHookConfig {
    /// Unique name for this guardrail (used in metrics, logs, error messages).
    pub name: String,
    /// HTTP POST endpoint for the guardrail service.
    pub url: String,
    /// Per-call timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Maximum response body size in bytes.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    /// Behavior on guardrail service error.
    #[serde(default)]
    pub on_error: GuardrailOnError,
    /// Whether this guardrail can modify arguments (pre) or results (post).
    #[serde(default)]
    pub allow_mutation: bool,
    /// Glob patterns for tool names this guardrail applies to. Empty = all tools.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Glob patterns for tool names to exclude.
    #[serde(default)]
    pub exclude_tools: Vec<String>,
    /// Optional CEL expression for conditional activation.
    /// Has access to `tool_name`, `trust_level`, `principal_id`, `auth_provider`.
    /// Must evaluate to a boolean. When `false`, the guardrail is skipped.
    #[serde(default)]
    pub trigger_cel: Option<String>,
    /// Static headers sent to the guardrail service (e.g. for auth).
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

fn default_timeout_ms() -> u64 {
    5000
}

fn default_max_response_bytes() -> usize {
    65536
}

/// Top-level guardrails plugin configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardrailsPluginConfig {
    /// Pre-execution guardrails — evaluated before tool dispatch.
    #[serde(default)]
    pub pre_execution: Vec<GuardrailHookConfig>,
    /// Post-execution guardrails — evaluated after tool returns.
    #[serde(default)]
    pub post_execution: Vec<GuardrailHookConfig>,
    /// By default guardrails run only on tool calls. Operators who want
    /// to scan other MCP surfaces set this to `true`.
    #[serde(default = "default_false")]
    pub apply_to_non_tool_surfaces: bool,
    /// Allow guardrail callouts to private/loopback IPs. Default false;
    /// set true only for container-network deployments.
    #[serde(default = "default_false")]
    pub allow_private_backends: bool,
}

fn default_false() -> bool {
    false
}

impl Default for GuardrailsPluginConfig {
    fn default() -> Self {
        Self {
            pre_execution: Vec::new(),
            post_execution: Vec::new(),
            apply_to_non_tool_surfaces: default_false(),
            allow_private_backends: default_false(),
        }
    }
}

// ---------------------------------------------------------------------------
// Guardrail request/response contract  (wire protocol with external services)
// ---------------------------------------------------------------------------

/// The request body sent from the gateway to a guardrail service.
#[derive(Debug, Clone, Serialize)]
pub struct GuardrailRequest {
    pub version: &'static str,
    pub kind: GuardrailPhase,
    pub request_id: String,
    pub session_id: Option<String>,
    pub tool_name: String,
    pub arguments: Value,
    pub identity: GuardrailIdentity,
    /// Present only for post-execution guardrails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Present only for post-execution guardrails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailPhase {
    PreExecution,
    PostExecution,
}

/// Minimal identity context sent to guardrail services.
#[derive(Debug, Clone, Serialize)]
pub struct GuardrailIdentity {
    pub kind: String,
    pub trust_level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

impl GuardrailIdentity {
    fn from_plugin_context(ctx: &PluginContext) -> Self {
        Self {
            kind: ctx.identity.kind.clone(),
            trust_level: ctx.identity.trust_level.clone(),
            subject_id: ctx.identity.subject_id.clone(),
            auth_provider: ctx.identity.auth_provider.clone(),
            issuer: ctx.identity.issuer.clone(),
        }
    }
}

/// The response expected from a guardrail service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailServiceResponse {
    pub decision: GuardrailDecisionKind,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub modified_arguments: Option<Value>,
    #[serde(default)]
    pub modified_result: Option<Value>,
    #[serde(default)]
    #[allow(dead_code)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailDecisionKind {
    Allow,
    Deny,
}

// ---------------------------------------------------------------------------
// Compiled hook (config + pre-compiled CEL trigger)
// ---------------------------------------------------------------------------

/// A guardrail hook with pre-compiled CEL trigger and glob patterns for
/// zero per-request compilation overhead. The on_error policy determines
/// whether a guardrail service failure blocks (deny, default) or allows the call.
struct CompiledHook {
    config: GuardrailHookConfig,
    trigger_program: Option<cel::Program>,
    tool_patterns: Vec<String>,
    exclude_patterns: Vec<String>,
}

impl CompiledHook {
    fn compile(config: GuardrailHookConfig) -> Result<Self> {
        let trigger_program = match &config.trigger_cel {
            Some(expr) => Some(cel::Program::compile(expr)?),
            None => None,
        };
        let tool_patterns = config.tools.clone();
        let exclude_patterns = config.exclude_tools.clone();
        Ok(Self {
            config,
            trigger_program,
            tool_patterns,
            exclude_patterns,
        })
    }

    /// Check whether this hook applies to the given tool name.
    fn matches_tool(&self, tool_name: &str) -> bool {
        if self
            .exclude_patterns
            .iter()
            .any(|p| glob::glob_match(p, tool_name))
        {
            return false;
        }
        if self.tool_patterns.is_empty() {
            return true;
        }
        self.tool_patterns
            .iter()
            .any(|p| glob::glob_match(p, tool_name))
    }

    /// Evaluate the CEL trigger condition. Returns `true` if the hook should activate.
    fn evaluate_trigger(&self, ctx: &PluginContext) -> Result<bool> {
        let program = match &self.trigger_program {
            Some(p) => p,
            None => return Ok(true),
        };
        let mut cel_ctx = cel::Context::default();
        cel_ctx
            .add_variable("tool_name", ctx.tool_name.as_str())
            .map_err(|e| anyhow::anyhow!("CEL variable error: {e}"))?;
        cel_ctx
            .add_variable("trust_level", ctx.identity.trust_level.as_str())
            .map_err(|e| anyhow::anyhow!("CEL variable error: {e}"))?;
        cel_ctx
            .add_variable(
                "principal_id",
                ctx.identity.subject_id.as_deref().unwrap_or("").to_owned(),
            )
            .map_err(|e| anyhow::anyhow!("CEL variable error: {e}"))?;
        cel_ctx
            .add_variable(
                "auth_provider",
                ctx.identity
                    .auth_provider
                    .as_deref()
                    .unwrap_or("")
                    .to_owned(),
            )
            .map_err(|e| anyhow::anyhow!("CEL variable error: {e}"))?;
        match program.execute(&cel_ctx) {
            Ok(cel::Value::Bool(b)) => Ok(b),
            Ok(other) => Err(anyhow::anyhow!(
                "trigger_cel must evaluate to bool, got {other:?}"
            )),
            Err(e) => Err(anyhow::anyhow!("trigger_cel evaluation error: {e}")),
        }
    }
}

// ---------------------------------------------------------------------------
// GuardrailsGatePlugin — the ToolGatePlugin implementation
// ---------------------------------------------------------------------------

/// Guardrails tool-gate plugin.
///
/// Calls external HTTP guardrail services before and after tool dispatch.
/// Pre-compiled CEL triggers and glob patterns for zero per-request overhead
/// when hooks don't apply.
pub struct GuardrailsGatePlugin {
    manifest: PluginManifest,
    pre_execution: Vec<CompiledHook>,
    post_execution: Vec<CompiledHook>,
    /// Operator opt-in: run guardrails on non-tool surfaces too.
    apply_to_non_tool_surfaces: bool,
    allow_private_backends: bool,
    http_client: reqwest::blocking::Client,
}

impl std::fmt::Debug for GuardrailsGatePlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardrailsGatePlugin")
            .field("pre_execution_count", &self.pre_execution.len())
            .field("post_execution_count", &self.post_execution.len())
            .finish()
    }
}

impl GuardrailsGatePlugin {
    /// Build the plugin from configuration. Pre-compiles CEL triggers and glob patterns.
    pub fn from_config(config: &GuardrailsPluginConfig) -> Result<Self> {
        let pre_execution = config
            .pre_execution
            .iter()
            .map(|c| CompiledHook::compile(c.clone()))
            .collect::<Result<Vec<_>>>()?;
        let post_execution = config
            .post_execution
            .iter()
            .map(|c| CompiledHook::compile(c.clone()))
            .collect::<Result<Vec<_>>>()?;

        let http_client = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            // The hook receives the tool arguments in its request body, so a
            // redirect delivers them to a host the SSRF check never saw. The
            // check runs on the configured URL, not on wherever a 302 leads.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            manifest: default_manifest(),
            pre_execution,
            post_execution,
            apply_to_non_tool_surfaces: config.apply_to_non_tool_surfaces,
            allow_private_backends: config.allow_private_backends,
            http_client,
        })
    }

    /// SDK macro factory: parses operator config JSON. A security
    /// control FAILS CLOSED on bad config — it refuses to instantiate
    /// (panic, caught by the make slot's `catch_panic_to_null_handle`
    /// → null handle → boot Err) rather than silently loading disabled.
    /// This is the uniform tool-gate/policy convention (policy engines
    /// and slack-approval already panic-refuse): a misconfigured guardrail
    /// that silently disables itself is a policy gap, and a fail-open
    /// default for a security control is unacceptable. A valid config
    /// with zero hooks is still fine (loads an inert-by-design gate).
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg: GuardrailsPluginConfig = serde_json::from_str(config_json)
            .unwrap_or_else(|err| panic!("guardrails: config JSON failed to parse: {err}"));
        Self::from_config(&cfg)
            .unwrap_or_else(|err| panic!("guardrails: config compile failed: {err}"))
    }

    /// Create a disabled (empty) guardrails plugin.
    pub fn empty() -> Self {
        Self {
            manifest: default_manifest(),
            pre_execution: Vec::new(),
            post_execution: Vec::new(),
            apply_to_non_tool_surfaces: false,
            allow_private_backends: false,
            http_client: reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
        }
    }

    /// Returns true if any hooks are configured.
    pub fn has_hooks(&self) -> bool {
        !self.pre_execution.is_empty() || !self.post_execution.is_empty()
    }

    // -----------------------------------------------------------------------
    // HTTP callout
    // -----------------------------------------------------------------------

    fn call_guardrail_service(
        &self,
        hook: &CompiledHook,
        request: &GuardrailRequest,
    ) -> Result<GuardrailServiceResponse> {
        let timeout = Duration::from_millis(hook.config.timeout_ms);
        let max_bytes = hook.config.max_response_bytes;

        let mut builder = self
            .http_client
            .post(&hook.config.url)
            .timeout(timeout)
            .header("Content-Type", "application/json");

        // Add configured static headers
        for (key, value) in &hook.config.headers {
            builder = builder.header(key.as_str(), value.as_str());
        }

        let response = builder
            .json(request)
            .send()
            .map_err(|e| anyhow::anyhow!("HTTP request failed: {e}"))?;

        // Security: DNS rebinding guard — reject responses from private IPs.
        mcpg_plugin_protocol::security::check_response_remote_addr(
            response.remote_addr(),
            self.allow_private_backends,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;

        let status = response.status();
        if !status.is_success() {
            return Err(anyhow::anyhow!("guardrail service returned HTTP {status}"));
        }

        let bytes = response
            .bytes()
            .map_err(|e| anyhow::anyhow!("failed to read response body: {e}"))?;
        if bytes.len() > max_bytes {
            return Err(anyhow::anyhow!(
                "guardrail response exceeded max_response_bytes ({} > {max_bytes})",
                bytes.len()
            ));
        }

        let parsed: GuardrailServiceResponse = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("invalid guardrail response JSON: {e}"))?;

        Ok(parsed)
    }

    // -----------------------------------------------------------------------
    // Pre-dispatch evaluation
    // -----------------------------------------------------------------------

    fn evaluate_pre_hooks(&self, ctx: &PluginContext, arguments: &Value) -> GateDecision {
        if self.pre_execution.is_empty() {
            return GateDecision::allow();
        }
        // Skip non-tool surfaces unless explicitly opted in.
        if ctx.surface != "tool" && !self.apply_to_non_tool_surfaces {
            return GateDecision::allow();
        }

        let mut current_arguments = arguments.clone();
        let mut was_mutated = false;

        for hook in &self.pre_execution {
            // 1. Tool filter
            if !hook.matches_tool(&ctx.tool_name) {
                continue;
            }

            // 2. CEL trigger
            match hook.evaluate_trigger(ctx) {
                Ok(true) => {}
                Ok(false) => {
                    info!(
                        guardrail_name = %hook.config.name,
                        tool_name = %ctx.tool_name,
                        "guardrail skipped: trigger_cel evaluated to false"
                    );
                    continue;
                }
                Err(e) => {
                    warn!(
                        guardrail_name = %hook.config.name,
                        tool_name = %ctx.tool_name,
                        error = %e,
                        "guardrail trigger_cel evaluation error"
                    );
                    metrics::counter!(
                        "mcpg_guardrail_errors_total",
                        "guardrail_name" => hook.config.name.clone(),
                        "error_kind" => "trigger_error",
                    )
                    .increment(1);
                    if hook.config.on_error == GuardrailOnError::Deny {
                        return GateDecision::Deny {
                            http_status: 503,
                            code: -32050,
                            message: format!(
                                "Guardrail '{}' trigger evaluation failed: {e}",
                                hook.config.name
                            ),
                            error_data: None,
                        };
                    }
                    continue;
                }
            }

            // 3. Build request payload
            let guardrail_request = GuardrailRequest {
                version: "1",
                kind: GuardrailPhase::PreExecution,
                request_id: ctx.request_id.clone(),
                session_id: ctx.session_id.clone(),
                tool_name: ctx.tool_name.clone(),
                arguments: current_arguments.clone(),
                identity: GuardrailIdentity::from_plugin_context(ctx),
                result: None,
                execution_duration_ms: None,
            };

            // 4. HTTP callout
            let start = Instant::now();
            let decision = self.call_guardrail_service(hook, &guardrail_request);
            let elapsed_ms = start.elapsed().as_millis() as u64;
            let elapsed_secs = start.elapsed().as_secs_f64();

            match decision {
                Ok(response) => {
                    let decision_label = match response.decision {
                        GuardrailDecisionKind::Allow => "allow",
                        GuardrailDecisionKind::Deny => "deny",
                    };
                    metrics::counter!(
                        "mcpg_guardrail_evaluations_total",
                        "guardrail_name" => hook.config.name.clone(),
                        "phase" => "pre",
                        "decision" => decision_label,
                    )
                    .increment(1);
                    metrics::histogram!(
                        "mcpg_guardrail_evaluation_duration_seconds",
                        "guardrail_name" => hook.config.name.clone(),
                        "phase" => "pre",
                    )
                    .record(elapsed_secs);

                    match response.decision {
                        GuardrailDecisionKind::Allow => {
                            info!(
                                guardrail_name = %hook.config.name,
                                tool_name = %ctx.tool_name,
                                duration_ms = elapsed_ms,
                                decision = "allow",
                                "guardrail evaluated"
                            );
                            if hook.config.allow_mutation
                                && let Some(modified) = response.modified_arguments
                            {
                                info!(
                                    guardrail_name = %hook.config.name,
                                    tool_name = %ctx.tool_name,
                                    "guardrail mutation applied to arguments"
                                );
                                current_arguments = modified;
                                was_mutated = true;
                            }
                        }
                        GuardrailDecisionKind::Deny => {
                            let reason = response
                                .reason
                                .unwrap_or_else(|| "denied by guardrail".to_owned());
                            warn!(
                                guardrail_name = %hook.config.name,
                                tool_name = %ctx.tool_name,
                                duration_ms = elapsed_ms,
                                reason = %reason,
                                "guardrail denied tool call"
                            );
                            return GateDecision::Deny {
                                http_status: 403,
                                code: -32050,
                                message: format!(
                                    "Guardrail '{}' denied: {}",
                                    hook.config.name, reason
                                ),
                                error_data: None,
                            };
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        guardrail_name = %hook.config.name,
                        tool_name = %ctx.tool_name,
                        duration_ms = elapsed_ms,
                        error = %e,
                        on_error = ?hook.config.on_error,
                        "guardrail service error"
                    );
                    metrics::counter!(
                        "mcpg_guardrail_errors_total",
                        "guardrail_name" => hook.config.name.clone(),
                        "error_kind" => classify_error(&e),
                    )
                    .increment(1);

                    if hook.config.on_error == GuardrailOnError::Deny {
                        return GateDecision::Deny {
                            http_status: 503,
                            code: -32050,
                            message: format!("Guardrail '{}' service error: {e}", hook.config.name),
                            error_data: None,
                        };
                    }
                    // on_error == Allow → log and continue chain
                }
            }
        }

        if was_mutated {
            // Emit the canonical protocol field so the gateway applies the
            // rewrite to the backend arguments.
            GateDecision::Allow {
                modified_arguments: Some(current_arguments),
                modified_result: None,
                metadata: None,
            }
        } else {
            GateDecision::allow()
        }
    }

    // -----------------------------------------------------------------------
    // Post-dispatch evaluation
    // -----------------------------------------------------------------------

    fn evaluate_post_hooks(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        result: &Value,
        execution_duration_ms: u64,
    ) -> GateDecision {
        if self.post_execution.is_empty() {
            return GateDecision::allow();
        }
        // Skip non-tool surfaces unless explicitly opted in.
        if ctx.surface != "tool" && !self.apply_to_non_tool_surfaces {
            return GateDecision::allow();
        }

        // Thread the result through the hook chain so a mutating guardrail's
        // rewrite is visible to later hooks and surfaces in the terminal
        // Allow.modified_result the gateway applies.
        let mut current_result = result.clone();
        let mut result_modified = false;

        for hook in &self.post_execution {
            if !hook.matches_tool(&ctx.tool_name) {
                continue;
            }

            match hook.evaluate_trigger(ctx) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    warn!(
                        guardrail_name = %hook.config.name,
                        tool_name = %ctx.tool_name,
                        error = %e,
                        "guardrail trigger_cel evaluation error"
                    );
                    metrics::counter!(
                        "mcpg_guardrail_errors_total",
                        "guardrail_name" => hook.config.name.clone(),
                        "error_kind" => "trigger_error",
                    )
                    .increment(1);
                    if hook.config.on_error == GuardrailOnError::Deny {
                        return GateDecision::Deny {
                            http_status: 503,
                            code: -32050,
                            message: format!(
                                "Guardrail '{}' trigger evaluation failed: {e}",
                                hook.config.name
                            ),
                            error_data: None,
                        };
                    }
                    continue;
                }
            }

            let guardrail_request = GuardrailRequest {
                version: "1",
                kind: GuardrailPhase::PostExecution,
                request_id: ctx.request_id.clone(),
                session_id: ctx.session_id.clone(),
                tool_name: ctx.tool_name.clone(),
                arguments: arguments.clone(),
                identity: GuardrailIdentity::from_plugin_context(ctx),
                result: Some(current_result.clone()),
                execution_duration_ms: Some(execution_duration_ms),
            };

            let start = Instant::now();
            let decision = self.call_guardrail_service(hook, &guardrail_request);
            let elapsed_ms = start.elapsed().as_millis() as u64;
            let elapsed_secs = start.elapsed().as_secs_f64();

            match decision {
                Ok(response) => {
                    let decision_label = match response.decision {
                        GuardrailDecisionKind::Allow => "allow",
                        GuardrailDecisionKind::Deny => "deny",
                    };
                    metrics::counter!(
                        "mcpg_guardrail_evaluations_total",
                        "guardrail_name" => hook.config.name.clone(),
                        "phase" => "post",
                        "decision" => decision_label,
                    )
                    .increment(1);
                    metrics::histogram!(
                        "mcpg_guardrail_evaluation_duration_seconds",
                        "guardrail_name" => hook.config.name.clone(),
                        "phase" => "post",
                    )
                    .record(elapsed_secs);

                    match response.decision {
                        GuardrailDecisionKind::Allow => {
                            info!(
                                guardrail_name = %hook.config.name,
                                tool_name = %ctx.tool_name,
                                duration_ms = elapsed_ms,
                                decision = "allow",
                                "post-execution guardrail evaluated"
                            );
                            // A mutating post-execution guardrail (allow_mutation)
                            // may rewrite the result (e.g. output redaction). Carry
                            // it forward; the terminal Allow.modified_result is what
                            // the gateway applies before returning to the client.
                            if hook.config.allow_mutation
                                && let Some(modified) = response.modified_result
                            {
                                info!(
                                    guardrail_name = %hook.config.name,
                                    tool_name = %ctx.tool_name,
                                    "guardrail mutation applied to result"
                                );
                                current_result = modified;
                                result_modified = true;
                            }
                        }
                        GuardrailDecisionKind::Deny => {
                            let reason = response
                                .reason
                                .unwrap_or_else(|| "denied by post-execution guardrail".to_owned());
                            warn!(
                                guardrail_name = %hook.config.name,
                                tool_name = %ctx.tool_name,
                                duration_ms = elapsed_ms,
                                reason = %reason,
                                "post-execution guardrail denied response"
                            );
                            return GateDecision::Deny {
                                http_status: 403,
                                code: -32050,
                                message: format!(
                                    "Guardrail '{}' denied: {}",
                                    hook.config.name, reason
                                ),
                                error_data: None,
                            };
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        guardrail_name = %hook.config.name,
                        tool_name = %ctx.tool_name,
                        duration_ms = elapsed_ms,
                        error = %e,
                        on_error = ?hook.config.on_error,
                        "post-execution guardrail service error"
                    );
                    metrics::counter!(
                        "mcpg_guardrail_errors_total",
                        "guardrail_name" => hook.config.name.clone(),
                        "error_kind" => classify_error(&e),
                    )
                    .increment(1);

                    if hook.config.on_error == GuardrailOnError::Deny {
                        return GateDecision::Deny {
                            http_status: 503,
                            code: -32050,
                            message: format!("Guardrail '{}' service error: {e}", hook.config.name),
                            error_data: None,
                        };
                    }
                }
            }
        }

        if result_modified {
            GateDecision::Allow {
                modified_arguments: None,
                modified_result: Some(current_result),
                metadata: None,
            }
        } else {
            GateDecision::allow()
        }
    }
}

// ---------------------------------------------------------------------------
// SyncToolGate implementation + cdylib FFI registration
// ---------------------------------------------------------------------------

impl SyncToolGate for GuardrailsGatePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn evaluate_pre(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        _meta: Option<&Value>,
        _config: &Value,
    ) -> GateDecision {
        // Plugin-scoped span so traces from guardrails attribute
        // back to dev.mcpg.guardrails.
        let _span = info_span!(
            "guardrails_gate_evaluate_pre",
            plugin_id = PLUGIN_ID,
            tool = %ctx.tool_name,
        )
        .entered();
        let started = Instant::now();
        let decision = self.evaluate_pre_hooks(ctx, arguments);
        record_gate_outcome("pre", &decision, started.elapsed());
        decision
    }

    fn evaluate_post(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        result: &Value,
        execution_duration_ms: u64,
        _config: &Value,
    ) -> GateDecision {
        let _span = info_span!(
            "guardrails_gate_evaluate_post",
            plugin_id = PLUGIN_ID,
            tool = %ctx.tool_name,
        )
        .entered();
        let started = Instant::now();
        let decision = self.evaluate_post_hooks(ctx, arguments, result, execution_duration_ms);
        record_gate_outcome("post", &decision, started.elapsed());
        decision
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        tool_gate as gate {
            inner_name: "",
            plugin_type: GuardrailsGatePlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| GuardrailsGatePlugin::from_config_json(cfg),
        }
    ],
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Classify an error for the metrics label.
fn classify_error(e: &anyhow::Error) -> &'static str {
    let msg = e.to_string();
    if msg.contains("timed out") || msg.contains("timeout") {
        "timeout"
    } else if msg.contains("connect") || msg.contains("connection") {
        "connection"
    } else if msg.contains("invalid") || msg.contains("JSON") {
        "invalid_response"
    } else {
        "other"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::{PluginClass, PluginContext, PluginIdentity};

    fn test_ctx() -> PluginContext {
        PluginContext {
            surface: "tool".to_owned(),
            request_id: "req-1".into(),
            session_id: Some("sess-1".into()),
            tool_name: "orders.place_order".into(),
            identity: PluginIdentity {
                kind: "verified".into(),
                trust_level: "verified".into(),
                subject_id: Some("user-42".into()),
                auth_provider: Some("corporate-idp".into()),
                issuer: Some("https://idp.example.com".into()),
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: std::collections::BTreeMap::new(),
            },
            transport: "http".into(),
        }
    }

    fn anonymous_ctx() -> PluginContext {
        PluginContext {
            surface: "tool".to_owned(),
            request_id: "req-2".into(),
            session_id: None,
            tool_name: "public.list".into(),
            identity: PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: std::collections::BTreeMap::new(),
            },
            transport: "http".into(),
        }
    }

    // -- Config tests --------------------------------------------------------

    #[test]
    fn empty_config_creates_empty_plugin() {
        let config = GuardrailsPluginConfig::default();
        let plugin = GuardrailsGatePlugin::from_config(&config).unwrap();
        assert!(!plugin.has_hooks());
        assert_eq!(plugin.pre_execution.len(), 0);
        assert_eq!(plugin.post_execution.len(), 0);
    }

    #[test]
    fn manifest_is_correct() {
        let plugin = GuardrailsGatePlugin::empty();
        let m = plugin.manifest();
        assert_eq!(m.id, "dev.mcpg.guardrails");
        assert_eq!(m.plugin_class, PluginClass::ToolGate);
        assert_eq!(m.protocol_version, "1.0");
    }

    #[test]
    fn config_with_hooks_is_detected() {
        let config = GuardrailsPluginConfig {
            pre_execution: vec![GuardrailHookConfig {
                name: "scanner".into(),
                url: "http://localhost:8080/scan".into(),
                timeout_ms: 1000,
                max_response_bytes: 65536,
                on_error: GuardrailOnError::Deny,
                allow_mutation: false,
                tools: vec![],
                exclude_tools: vec![],
                trigger_cel: None,
                headers: BTreeMap::new(),
            }],
            post_execution: vec![],
            apply_to_non_tool_surfaces: false,
            allow_private_backends: true,
        };
        let plugin = GuardrailsGatePlugin::from_config(&config).unwrap();
        assert!(plugin.has_hooks());
    }

    // -- Tool matching tests -------------------------------------------------

    #[test]
    fn tool_matching_glob_patterns() {
        let hook = CompiledHook::compile(GuardrailHookConfig {
            name: "test".into(),
            url: "http://localhost:8080/scan".into(),
            timeout_ms: 1000,
            max_response_bytes: 65536,
            on_error: GuardrailOnError::Deny,
            allow_mutation: false,
            tools: vec!["orders.*".into(), "finance.*".into()],
            exclude_tools: vec!["orders.debug_*".into()],
            trigger_cel: None,
            headers: BTreeMap::new(),
        })
        .unwrap();

        assert!(hook.matches_tool("orders.place_order"));
        assert!(hook.matches_tool("finance.transfer"));
        assert!(!hook.matches_tool("orders.debug_dump"));
        assert!(!hook.matches_tool("users.list"));
    }

    #[test]
    fn tool_matching_empty_patterns_matches_all() {
        let hook = CompiledHook::compile(GuardrailHookConfig {
            name: "test".into(),
            url: "http://localhost:8080/scan".into(),
            timeout_ms: 1000,
            max_response_bytes: 65536,
            on_error: GuardrailOnError::Deny,
            allow_mutation: false,
            tools: vec![],
            exclude_tools: vec![],
            trigger_cel: None,
            headers: BTreeMap::new(),
        })
        .unwrap();

        assert!(hook.matches_tool("anything"));
        assert!(hook.matches_tool("orders.place_order"));
    }

    #[test]
    fn exclude_takes_precedence() {
        let hook = CompiledHook::compile(GuardrailHookConfig {
            name: "test".into(),
            url: "http://localhost:8080/scan".into(),
            timeout_ms: 1000,
            max_response_bytes: 65536,
            on_error: GuardrailOnError::Deny,
            allow_mutation: false,
            tools: vec!["*".into()],
            exclude_tools: vec!["mcpg.*".into()],
            trigger_cel: None,
            headers: BTreeMap::new(),
        })
        .unwrap();

        assert!(hook.matches_tool("orders.place_order"));
        assert!(!hook.matches_tool("mcpg.runtime_snapshot"));
    }

    // -- CEL trigger tests ---------------------------------------------------

    #[test]
    fn cel_trigger_matches_verified() {
        let hook = CompiledHook::compile(GuardrailHookConfig {
            name: "test".into(),
            url: "http://localhost:8080/scan".into(),
            timeout_ms: 1000,
            max_response_bytes: 65536,
            on_error: GuardrailOnError::Deny,
            allow_mutation: false,
            tools: vec![],
            exclude_tools: vec![],
            trigger_cel: Some(r#"trust_level == "verified""#.into()),
            headers: BTreeMap::new(),
        })
        .unwrap();

        assert!(hook.evaluate_trigger(&test_ctx()).unwrap());
        assert!(!hook.evaluate_trigger(&anonymous_ctx()).unwrap());
    }

    #[test]
    fn cel_trigger_none_always_activates() {
        let hook = CompiledHook::compile(GuardrailHookConfig {
            name: "test".into(),
            url: "http://localhost:8080/scan".into(),
            timeout_ms: 1000,
            max_response_bytes: 65536,
            on_error: GuardrailOnError::Deny,
            allow_mutation: false,
            tools: vec![],
            exclude_tools: vec![],
            trigger_cel: None,
            headers: BTreeMap::new(),
        })
        .unwrap();

        assert!(hook.evaluate_trigger(&test_ctx()).unwrap());
        assert!(hook.evaluate_trigger(&anonymous_ctx()).unwrap());
    }

    // -- Identity mapping ---------------------------------------------------

    #[test]
    fn identity_from_verified_context() {
        let gi = GuardrailIdentity::from_plugin_context(&test_ctx());
        assert_eq!(gi.kind, "verified");
        assert_eq!(gi.trust_level, "verified");
        assert_eq!(gi.subject_id.as_deref(), Some("user-42"));
        assert_eq!(gi.auth_provider.as_deref(), Some("corporate-idp"));
        assert_eq!(gi.issuer.as_deref(), Some("https://idp.example.com"));
    }

    #[test]
    fn identity_from_anonymous_context() {
        let gi = GuardrailIdentity::from_plugin_context(&anonymous_ctx());
        assert_eq!(gi.kind, "anonymous");
        assert_eq!(gi.trust_level, "unauthenticated");
        assert!(gi.subject_id.is_none());
        assert!(gi.auth_provider.is_none());
    }

    // -- Serialization tests -------------------------------------------------

    #[test]
    fn guardrail_request_serializes_pre_execution() {
        let req = GuardrailRequest {
            version: "1",
            kind: GuardrailPhase::PreExecution,
            request_id: "req-123".into(),
            session_id: Some("sess-abc".into()),
            tool_name: "orders.place_order".into(),
            arguments: serde_json::json!({"item": "Widget A", "quantity": 5}),
            identity: GuardrailIdentity::from_plugin_context(&test_ctx()),
            result: None,
            execution_duration_ms: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["version"], "1");
        assert_eq!(json["kind"], "pre_execution");
        assert_eq!(json["tool_name"], "orders.place_order");
        assert!(json.get("result").is_none());
        assert!(json.get("execution_duration_ms").is_none());
    }

    #[test]
    fn guardrail_request_serializes_post_execution() {
        let req = GuardrailRequest {
            version: "1",
            kind: GuardrailPhase::PostExecution,
            request_id: "req-123".into(),
            session_id: Some("sess-abc".into()),
            tool_name: "orders.place_order".into(),
            arguments: serde_json::json!({"item": "Widget A"}),
            identity: GuardrailIdentity::from_plugin_context(&test_ctx()),
            result: Some(serde_json::json!({"content": [{"type": "text", "text": "ok"}]})),
            execution_duration_ms: Some(234),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["kind"], "post_execution");
        assert!(json["result"].is_object());
        assert_eq!(json["execution_duration_ms"], 234);
    }

    #[test]
    fn guardrail_response_deserialization_allow() {
        let json = r#"{"decision": "allow", "reason": "content scan passed"}"#;
        let resp: GuardrailServiceResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.decision, GuardrailDecisionKind::Allow);
        assert_eq!(resp.reason.as_deref(), Some("content scan passed"));
    }

    #[test]
    fn guardrail_response_deserialization_deny() {
        let json = r#"{"decision": "deny", "reason": "PII detected"}"#;
        let resp: GuardrailServiceResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.decision, GuardrailDecisionKind::Deny);
        assert_eq!(resp.reason.as_deref(), Some("PII detected"));
    }

    #[test]
    fn guardrail_response_deserialization_with_mutation() {
        let json = r#"{"decision": "allow", "modified_arguments": {"item": "REDACTED"}}"#;
        let resp: GuardrailServiceResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.decision, GuardrailDecisionKind::Allow);
        assert!(resp.modified_arguments.is_some());
        assert_eq!(resp.modified_arguments.unwrap()["item"], "REDACTED");
    }

    // -- Error classification ------------------------------------------------

    #[test]
    fn classify_error_kinds() {
        assert_eq!(
            classify_error(&anyhow::anyhow!("request timed out")),
            "timeout"
        );
        assert_eq!(
            classify_error(&anyhow::anyhow!("connection refused")),
            "connection"
        );
        assert_eq!(
            classify_error(&anyhow::anyhow!("invalid JSON response")),
            "invalid_response"
        );
        assert_eq!(classify_error(&anyhow::anyhow!("something else")), "other");
    }

    // -- Async plugin chain tests (with mock HTTP server) --------------------

    #[test]
    fn empty_plugin_allows_pre_dispatch() {
        let plugin = GuardrailsGatePlugin::empty();
        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(decision.is_allow());
    }

    #[test]
    fn empty_plugin_allows_post_dispatch() {
        let plugin = GuardrailsGatePlugin::empty();
        let decision = plugin.evaluate_post(
            &test_ctx(),
            &serde_json::json!({}),
            &serde_json::json!({"content": []}),
            100,
            &serde_json::json!({}),
        );
        assert!(decision.is_allow());
    }

    #[test]
    fn pre_dispatch_skips_when_tool_not_matched() {
        let config = GuardrailsPluginConfig {
            pre_execution: vec![GuardrailHookConfig {
                name: "scanner".into(),
                url: "http://localhost:19999/will-not-be-called".into(),
                timeout_ms: 100,
                max_response_bytes: 65536,
                on_error: GuardrailOnError::Deny,
                allow_mutation: false,
                tools: vec!["finance.*".into()],
                exclude_tools: vec![],
                trigger_cel: None,
                headers: BTreeMap::new(),
            }],
            post_execution: vec![],
            apply_to_non_tool_surfaces: false,
            allow_private_backends: true,
        };
        let plugin = GuardrailsGatePlugin::from_config(&config).unwrap();
        // "orders.place_order" doesn't match "finance.*", so hook is skipped
        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(decision.is_allow());
    }

    #[test]
    fn pre_dispatch_skips_when_trigger_cel_false() {
        let config = GuardrailsPluginConfig {
            pre_execution: vec![GuardrailHookConfig {
                name: "scanner".into(),
                url: "http://localhost:19999/will-not-be-called".into(),
                timeout_ms: 100,
                max_response_bytes: 65536,
                on_error: GuardrailOnError::Deny,
                allow_mutation: false,
                tools: vec![],
                exclude_tools: vec![],
                trigger_cel: Some(r#"trust_level == "header_asserted""#.into()),
                headers: BTreeMap::new(),
            }],
            post_execution: vec![],
            apply_to_non_tool_surfaces: false,
            allow_private_backends: true,
        };
        let plugin = GuardrailsGatePlugin::from_config(&config).unwrap();
        // test_ctx() has trust_level = "verified", not "header_asserted"
        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(decision.is_allow());
    }

    #[test]
    fn on_error_deny_blocks_on_connection_failure() {
        let config = GuardrailsPluginConfig {
            pre_execution: vec![GuardrailHookConfig {
                name: "strict".into(),
                url: "http://192.0.2.1:1/unreachable".into(),
                timeout_ms: 200,
                max_response_bytes: 65536,
                on_error: GuardrailOnError::Deny,
                allow_mutation: false,
                tools: vec![],
                exclude_tools: vec![],
                trigger_cel: None,
                headers: BTreeMap::new(),
            }],
            post_execution: vec![],
            apply_to_non_tool_surfaces: false,
            allow_private_backends: true,
        };
        let plugin = GuardrailsGatePlugin::from_config(&config).unwrap();
        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(!decision.is_allow());
    }

    #[test]
    fn on_error_allow_continues_on_connection_failure() {
        let config = GuardrailsPluginConfig {
            pre_execution: vec![GuardrailHookConfig {
                name: "optional".into(),
                url: "http://192.0.2.1:1/unreachable".into(),
                timeout_ms: 200,
                max_response_bytes: 65536,
                on_error: GuardrailOnError::Allow,
                allow_mutation: false,
                tools: vec![],
                exclude_tools: vec![],
                trigger_cel: None,
                headers: BTreeMap::new(),
            }],
            post_execution: vec![],
            apply_to_non_tool_surfaces: false,
            allow_private_backends: true,
        };
        let plugin = GuardrailsGatePlugin::from_config(&config).unwrap();
        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(decision.is_allow());
    }

    // -- mutation-emit tests -------------------------------------------------
    //
    // These drive a *successful* callout (a tiny blocking HTTP stub) so the
    // emit path runs end to end: a mutating guardrail surfaces its rewrite
    // through the canonical protocol fields
    // (`GateDecision::Allow.modified_arguments` / `.modified_result`) the
    // gateway actually applies.

    /// Spawn a one-shot-per-connection HTTP/1.1 stub that always replies with
    /// `body`. Returns the `http://host:port/scan` URL to point a hook at.
    /// The listener thread is detached and dies with the test process.
    fn spawn_guardrail_stub(body: &'static str) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                // Drain whatever of the (small) request is buffered; we don't
                // inspect it — we only need to send a canned response.
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{addr}/scan")
    }

    fn mutating_hook(name: &str, url: String, allow_mutation: bool) -> GuardrailHookConfig {
        GuardrailHookConfig {
            name: name.into(),
            url,
            timeout_ms: 2000,
            max_response_bytes: 65536,
            on_error: GuardrailOnError::Deny,
            allow_mutation,
            tools: vec![],
            exclude_tools: vec![],
            trigger_cel: None,
            headers: BTreeMap::new(),
        }
    }

    #[test]
    fn pre_emits_modified_arguments_as_protocol_field() {
        let url =
            spawn_guardrail_stub(r#"{"decision":"allow","modified_arguments":{"redacted":true}}"#);
        let config = GuardrailsPluginConfig {
            pre_execution: vec![mutating_hook("redactor", url, true)],
            post_execution: vec![],
            apply_to_non_tool_surfaces: false,
            allow_private_backends: true,
        };
        let plugin = GuardrailsGatePlugin::from_config(&config).unwrap();
        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({"orig": 1}),
            None,
            &serde_json::json!({}),
        );
        match decision {
            GateDecision::Allow {
                modified_arguments,
                modified_result,
                ..
            } => {
                assert_eq!(
                    modified_arguments,
                    Some(serde_json::json!({"redacted": true})),
                    "pre rewrite must surface in Allow.modified_arguments"
                );
                assert_eq!(modified_result, None);
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn pre_suppresses_mutation_when_allow_mutation_false() {
        // The service offers a rewrite, but the hook is not authorized to
        // mutate — the plugin must NOT surface modified_arguments.
        let url =
            spawn_guardrail_stub(r#"{"decision":"allow","modified_arguments":{"redacted":true}}"#);
        let config = GuardrailsPluginConfig {
            pre_execution: vec![mutating_hook("scanner", url, false)],
            post_execution: vec![],
            apply_to_non_tool_surfaces: false,
            allow_private_backends: true,
        };
        let plugin = GuardrailsGatePlugin::from_config(&config).unwrap();
        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({"orig": 1}),
            None,
            &serde_json::json!({}),
        );
        match decision {
            GateDecision::Allow {
                modified_arguments, ..
            } => assert_eq!(
                modified_arguments, None,
                "must not mutate when allow_mutation is false"
            ),
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn post_emits_modified_result_as_protocol_field() {
        let url = spawn_guardrail_stub(
            r#"{"decision":"allow","modified_result":{"content":[],"masked":true}}"#,
        );
        let config = GuardrailsPluginConfig {
            pre_execution: vec![],
            post_execution: vec![mutating_hook("masker", url, true)],
            apply_to_non_tool_surfaces: false,
            allow_private_backends: true,
        };
        let plugin = GuardrailsGatePlugin::from_config(&config).unwrap();
        let decision = plugin.evaluate_post(
            &test_ctx(),
            &serde_json::json!({}),
            &serde_json::json!({"content": []}),
            5,
            &serde_json::json!({}),
        );
        match decision {
            GateDecision::Allow {
                modified_result,
                modified_arguments,
                ..
            } => {
                assert_eq!(
                    modified_result,
                    Some(serde_json::json!({"content": [], "masked": true})),
                    "post rewrite must surface in Allow.modified_result"
                );
                assert_eq!(modified_arguments, None);
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    // -- fail-closed config tests --------------------------------------------

    #[test]
    #[should_panic(expected = "config JSON failed to parse")]
    fn malformed_config_json_panics_fail_closed() {
        // A security control must refuse to instantiate on bad config
        // (panic → null handle → boot Err), not silently load disabled.
        let _ = GuardrailsGatePlugin::from_config_json("{ not valid json");
    }

    #[test]
    fn valid_empty_config_loads_inert_gate() {
        // A well-formed config with no hooks is legitimate (gate present
        // but does nothing) — must NOT panic.
        let plugin = GuardrailsGatePlugin::from_config_json("{}");
        assert!(!plugin.has_hooks());
    }

    #[test]
    #[should_panic(expected = "config JSON failed to parse")]
    fn unknown_top_level_config_key_rejected_fail_closed() {
        // `deny_unknown_fields`: a typo'd / stray / renamed top-level key
        // (here `allow_priv_backends` instead of `allow_private_backends`)
        // must be a parse error so the security control refuses to load
        // rather than silently ignoring the misconfiguration.
        let _ = GuardrailsGatePlugin::from_config_json(r#"{"allow_priv_backends": true}"#);
    }

    #[test]
    #[should_panic(expected = "config JSON failed to parse")]
    fn unknown_hook_config_key_rejected_fail_closed() {
        // A typo'd key inside a nested hook config must also fail-closed.
        let _ = GuardrailsGatePlugin::from_config_json(
            r#"{"pre_execution":[{"name":"x","url":"http://h/s","timeoutms":10}]}"#,
        );
    }
}
