import { useState } from "react";

export function RoleBadge({ role }) {
  return <span className={`role-badge role-${role || "viewer"}`}>{role || "viewer"}</span>;
}

function formatPercent(value) {
  return `${Number((value || 0) * 100).toFixed(1)}%`;
}

function buildRuntimeHint({ enabled, enabledText, disabledText, lastLabel, lastValue }) {
  const baseText = enabled ? enabledText : disabledText;
  if (!lastValue) {
    return baseText;
  }
  return `${baseText} ${lastLabel}: ${new Date(lastValue).toLocaleString()}.`;
}

function buildEndpointPolicyHighlights(builtInPolicies) {
  const policies = builtInPolicies || [];
  const findPolicy = (policyIds) => policyIds.map((policyId) => policies.find((policy) => policy.policy_id === policyId)).find(Boolean);
  const exactAuthLogin = findPolicy(["builtin-auth-login"]);

  const highlightRows = [
    {
      key: "login",
      title: "/login",
      policy: findPolicy(["builtin-login-surface"]),
      note:
        exactAuthLogin
          ? `Exact auth API ${exactAuthLogin.path_pattern} stays stricter at ${exactAuthLogin.settings?.requests_per_min || 0} req/min.`
          : "",
    },
    {
      key: "search",
      title: "/search",
      policy: findPolicy(["builtin-search-surface"]),
      note: "Search gets its own scrape-aware rate profile instead of sharing the default gateway bucket.",
    },
    {
      key: "admin",
      title: "/admin",
      policy: findPolicy(["builtin-admin-surface"]),
      note: "Administrative routes keep the strongest static protection outside the exact login endpoint.",
    },
    {
      key: "public-api",
      title: "/api/public",
      policy: findPolicy(["builtin-public-api-surface"]),
      note: "Public API traffic stays isolated with a more open budget so login and admin paths are not penalized by normal public usage.",
    },
  ];

  return highlightRows.filter((item) => item.policy);
}

const RUNTIME_FIELD_GROUP_DEFINITIONS = [
  {
    key: "gateway",
    title: "Gateway & Backend",
    description: "Core gateway endpoints, proxy mode, and shared backend connectivity.",
    matcher: (fieldKey) =>
      [
        "backend_base_url",
        "request_timeout_seconds",
        "transparent_proxy",
        "redis_url",
        "rate_limit_backend",
        "redis_key_prefix",
        "analytics_window_seconds",
        "dashboard_window_seconds",
        "recent_event_limit",
        "security_scope_window_seconds",
      ].includes(fieldKey),
  },
  {
    key: "preapp",
    title: "Pre-App Filtering",
    description: "Volumetric filtering before requests reach the Flask inspection pipeline.",
    matcher: (fieldKey) => fieldKey.startsWith("pre_app_filter_"),
  },
  {
    key: "proxy",
    title: "Proxy Transport",
    description: "Upstream timeout, pooling, and keep-alive transport controls.",
    matcher: (fieldKey) => fieldKey.startsWith("proxy_"),
  },
  {
    key: "connection",
    title: "Connection Guard",
    description: "Connection tracking, concurrency, sessions, and per-source limits.",
    matcher: (fieldKey) => fieldKey.startsWith("connection_"),
  },
  {
    key: "transport",
    title: "Transport Awareness",
    description: "Layer 4 anomaly tuning for SYN-like floods, churn, resets, and malformed transport.",
    matcher: (fieldKey) => fieldKey.startsWith("transport_"),
  },
  {
    key: "traffic",
    title: "Traffic Control",
    description: "Shared thresholds, token buckets, DDoS control, and blocking behavior.",
    matcher: (fieldKey) =>
      fieldKey === "block_threshold" ||
      fieldKey === "monitor_threshold" ||
      fieldKey.startsWith("rate_limit_") ||
      fieldKey.startsWith("token_bucket_") ||
      fieldKey.startsWith("ddos_") ||
      [
        "temporary_blacklist_seconds",
        "targeted_block_ttl_seconds",
        "blacklist_repeat_offense_threshold",
        "max_body_length",
        "max_payload_preview_chars",
      ].includes(fieldKey),
  },
  {
    key: "botDetection",
    title: "Bot Detection",
    description: "Automation fingerprints, browser integrity checks, and scraping-aware bot controls.",
    matcher: (fieldKey) =>
      fieldKey === "bot_detection_enabled" ||
      fieldKey.startsWith("bot_") ||
      fieldKey === "browser_user_agent_markers" ||
      fieldKey === "automation_fingerprint_tokens" ||
      fieldKey === "headless_browser_tokens" ||
      fieldKey === "scraping_path_tokens",
  },
  {
    key: "adaptivity",
    title: "Adaptivity & Auto-Tuning",
    description: "Self-adjustment, drift response, and automatic tuning strategies.",
    matcher: (fieldKey) => fieldKey.startsWith("auto_tuning_"),
  },
  {
    key: "dynamic",
    title: "Dynamic Thresholds",
    description: "Threshold movement from live score distributions.",
    matcher: (fieldKey) => fieldKey.startsWith("dynamic_thresholds_"),
  },
  {
    key: "adaptiveRate",
    title: "Adaptive Rate Limiting",
    description: "Risk-based throttling profiles and suspicion scoring.",
    matcher: (fieldKey) => fieldKey.startsWith("adaptive_rate_") || fieldKey === "adaptive_rate_limiting_enabled",
  },
  {
    key: "feedback",
    title: "Feedback Loop",
    description: "Sensitivity adjustment from analyst review outcomes.",
    matcher: (fieldKey) => fieldKey.startsWith("feedback_loop_"),
  },
  {
    key: "mlLogs",
    title: "ML + Logs",
    description: "Continuous supervised retraining from reviewed request history.",
    matcher: (fieldKey) => fieldKey.startsWith("ml_log_training_"),
  },
  {
    key: "modelAuth",
    title: "Model & Auth",
    description: "Model blending and authentication/session controls.",
    matcher: (fieldKey) => ["heuristic_weight", "ml_weight", "auth_token_ttl_seconds"].includes(fieldKey),
  },
];

const RUNTIME_LABEL_ACRONYMS = new Set(["api", "ip", "ttl", "ml", "ddos", "waf", "url", "cors", "json", "udp", "tcp", "syn"]);

function formatRuntimeFieldLabel(fieldKey) {
  return String(fieldKey || "")
    .split("_")
    .filter(Boolean)
    .map((part) => {
      const lower = part.toLowerCase();
      if (RUNTIME_LABEL_ACRONYMS.has(lower)) {
        return lower.toUpperCase();
      }
      return lower.charAt(0).toUpperCase() + lower.slice(1);
    })
    .join(" ");
}

function groupRuntimeEntries(entries) {
  const groups = RUNTIME_FIELD_GROUP_DEFINITIONS.map((group) => ({ ...group, items: [] }));
  const fallback = {
    key: "other",
    title: "Other Settings",
    description: "Runtime settings that do not belong to a named strategy group.",
    items: [],
  };

  entries.forEach(([fieldKey, value]) => {
    const matchedGroup = groups.find((group) => group.matcher(fieldKey));
    if (matchedGroup) {
      matchedGroup.items.push([fieldKey, value]);
      return;
    }
    fallback.items.push([fieldKey, value]);
  });

  return [...groups.filter((group) => group.items.length), ...(fallback.items.length ? [fallback] : [])];
}

function RuntimeStrategySection({ sectionKey, title, description, open, onToggle, children }) {
  return (
    <section className={`strategy-section ${open ? "is-open" : "is-closed"}`} data-section={sectionKey}>
      <button
        type="button"
        className="strategy-section-header"
        onClick={() => onToggle(sectionKey)}
        aria-expanded={open}
      >
        <div className="strategy-section-copy">
          <strong>{title}</strong>
          {description ? <span>{description}</span> : null}
        </div>
        <span className="strategy-section-toggle">{open ? "Hide" : "Show"}</span>
      </button>
      {open ? <div className="strategy-section-body">{children}</div> : null}
    </section>
  );
}

function MetricCard({ label, value, hint }) {
  return (
    <div className="meta-card">
      <span>{label}</span>
      <strong>{value}</strong>
      {hint ? <small>{hint}</small> : null}
    </div>
  );
}

function AdaptivityPanel({ report, onRefresh, onApply, busyAction, canAdmin, canReview }) {
  if (!canReview) {
    return null;
  }

  if (!report) {
    return <div className="empty-state small">Adaptivity analysis has not loaded yet.</div>;
  }

  const recommendation = report.recommendation || {};
  const dynamic = report.dynamic_thresholds || {};
  const strategyStatus = report.strategies || {};
  const manualChanges = Object.entries(recommendation.changes || {});
  const automaticChanges = Object.entries(recommendation.automatic_changes || {});
  const conflicts = recommendation.conflicts || [];
  const lastCycle = report.last_adaptivity_cycle || {};
  const current = report.current || {};
  const effective = report.effective || {};
  const manualReady = recommendation.manual_ready_strategies || [];
  const automaticReady = recommendation.automatic_ready_strategies || [];

  return (
    <div className="admin-stack auto-tuning-card">
      <div className="simulation-banner">
        <strong>Adaptivity</strong>
        <span>{report.summary || "No adaptivity summary is available."}</span>
        <small>
          Coordinate Dynamic Thresholds, Auto-Tuning, and the Feedback Loop so the gateway can react to traffic drift without losing analyst control.
        </small>
      </div>

      <div className="settings-grid">
        <div className="meta-card">
          <span>Posture</span>
          <strong>{report.posture || "steady"}</strong>
        </div>
        <div className="meta-card">
          <span>Confidence</span>
          <strong>{report.confidence || "low"}</strong>
        </div>
        <div className="meta-card">
          <span>Manual changes</span>
          <strong>{manualChanges.length}</strong>
          <small>{manualReady.length ? manualReady.join(", ") : "No strategy is ready"}</small>
        </div>
        <div className="meta-card">
          <span>Automatic changes</span>
          <strong>{automaticChanges.length}</strong>
          <small>{automaticReady.length ? automaticReady.join(", ") : "No enabled strategy is ready"}</small>
        </div>
        <div className="meta-card">
          <span>Conflicts</span>
          <strong>{conflicts.length}</strong>
          <small>{conflicts.length ? "Feedback wins threshold conflicts" : "No strategy conflict detected"}</small>
        </div>
        <div className="meta-card">
          <span>Dynamic mode</span>
          <strong>{dynamic.mode || "static"}</strong>
          <small>{dynamic.active ? "Effective thresholds are live" : "Static thresholds still apply"}</small>
        </div>
        <div className="meta-card">
          <span>Effective block</span>
          <strong>{Number(effective.block_threshold || current.block_threshold || 0).toFixed(3)}</strong>
          <small>Configured {Number(current.block_threshold || 0).toFixed(3)}</small>
        </div>
        <div className="meta-card">
          <span>Effective monitor</span>
          <strong>{Number(effective.monitor_threshold || current.monitor_threshold || 0).toFixed(3)}</strong>
          <small>Configured {Number(current.monitor_threshold || 0).toFixed(3)}</small>
        </div>
      </div>

      {conflicts.length ? (
        <div className="auto-tuning-reasons">
          {conflicts.map((conflict) => (
            <div className="meta-card" key={`${conflict.field}-${conflict.winner_source}-${conflict.loser_source}`}>
              <span>{conflict.field}</span>
              <strong>
                {conflict.winner_label} kept {conflict.winner_direction} to {conflict.winner_value}
              </strong>
              <small>
                {conflict.loser_label} proposed {conflict.loser_direction} to {conflict.loser_value}
              </small>
            </div>
          ))}
        </div>
      ) : null}

      <div className="section-action-group">
        <button type="button" className="ghost-button" onClick={onRefresh} disabled={busyAction === "adaptivity-refresh"}>
          {busyAction === "adaptivity-refresh" ? "Analyzing..." : "Analyze adaptivity"}
        </button>
        {canAdmin ? (
          <button
            type="button"
            className="primary-button"
            onClick={onApply}
            disabled={busyAction === "adaptivity-apply" || !report.can_apply}
          >
            {busyAction === "adaptivity-apply" ? "Applying..." : "Apply adaptivity now"}
          </button>
        ) : null}
      </div>

      <div className="permission-note auto-tuning-note">
        {buildRuntimeHint({
          enabled: report.can_auto_apply,
          enabledText: "Automatic adaptivity is ready. Enabled strategies can reconcile live traffic signals and analyst feedback without a restart.",
          disabledText: "Adaptivity is in review mode. It still analyzes Dynamic Thresholds, Auto-Tuning, and Feedback Loop even when no automatic merge is currently ready.",
          lastLabel: "Last adaptivity cycle",
          lastValue: lastCycle.created_at,
        })}
      </div>
    </div>
  );
}

function SecurityScopePanel({
  report,
  policyDraft,
  onPolicyDraftChange,
  onRefresh,
  onCreatePolicy,
  onDeletePolicy,
  busyAction,
  canAdmin,
  canReview,
}) {
  if (!canReview) {
    return null;
  }

  if (!report) {
    return <div className="empty-state small">Security-scope analysis has not loaded yet.</div>;
  }

  const ddos = report.ddos_protection || {};
  const layer4 = report.layer4_protection || {};
  const perConnection = layer4.per_connection_throttling || {};
  const perConnectionTelemetry = perConnection.telemetry || {};
  const transport = layer4.transport_awareness || {};
  const transportTelemetry = transport.telemetry || {};
  const proxyTransport = layer4.socket_proxy_controls || {};
  const proxyTransportTelemetry = proxyTransport.telemetry || {};
  const preAppFilter = layer4.volumetric_pre_app_filtering || {};
  const preAppFilterTelemetry = preAppFilter.telemetry || {};
  const telemetry = report.telemetry || {};
  const builtInPolicies = report.built_in_policies || [];
  const policyHighlights = buildEndpointPolicyHighlights(builtInPolicies);
  const customPolicies = report.custom_policies || [];
  const showPreAppFiltering = !!preAppFilter.enabled;
  const showConnectionGuard = !!layer4.enabled;
  const showTransportAwareness = !!transport.enabled;
  const showProxyTransport = !!proxyTransport.enabled;
  const activeModules = [
    ddos.enabled ? "DDoS protection" : null,
    showPreAppFiltering ? "pre-app filtering" : null,
    showConnectionGuard ? "connection guard" : null,
    showTransportAwareness ? "transport awareness" : null,
    showProxyTransport ? "proxy transport controls" : null,
  ].filter(Boolean);
  const overviewCards = [];

  if (ddos.enabled) {
    overviewCards.push(
      { label: "DDoS protection", value: "enabled" },
      {
        label: "Monitor threshold",
        value: `${ddos.monitor_request_threshold || 0} hits`,
        hint: `Pressure ${Number(ddos.monitor_pressure_threshold || 0).toFixed(2)}`,
      },
      {
        label: "Block threshold",
        value: `${ddos.block_request_threshold || 0} hits`,
        hint: `Pressure ${Number(ddos.block_pressure_threshold || 0).toFixed(2)}`,
      },
    );
  }

  if ((telemetry.ddos_events || 0) > 0 || (telemetry.blocked_ddos_events || 0) > 0) {
    overviewCards.push({
      label: "DDoS events",
      value: String(telemetry.ddos_events || 0),
      hint: `${telemetry.blocked_ddos_events || 0} blocked in window`,
    });
  }

  if (showPreAppFiltering) {
    overviewCards.push(
      {
        label: "Pre-app filtering",
        value: "enabled",
        hint: preAppFilter.mode || "wsgi_pre_app",
      },
      {
        label: "Pre-app IP threshold",
        value: String(preAppFilter.ip_request_threshold || 0),
        hint: `Burst ${preAppFilter.ip_burst_threshold || 0}`,
      },
      {
        label: "Pre-app global threshold",
        value: String(preAppFilter.global_request_threshold || 0),
        hint: `${preAppFilter.window_seconds || 0}s window`,
      },
    );
  }

  if ((preAppFilterTelemetry.blocked || 0) > 0 || (preAppFilterTelemetry.active_ip_blocks || 0) > 0) {
    overviewCards.push({
      label: "Pre-app blocked",
      value: String(preAppFilterTelemetry.blocked || 0),
      hint: `${preAppFilterTelemetry.active_ip_blocks || 0} active IP blocks`,
    });
  }

  if ((telemetry.sensitive_path_hits || 0) > 0) {
    overviewCards.push({
      label: "Sensitive path hits",
      value: String(telemetry.sensitive_path_hits || 0),
      hint: `Window ${telemetry.window_seconds || 0}s`,
    });
  }

  if (showConnectionGuard) {
    overviewCards.push(
      {
        label: "Connection guard",
        value: "enabled",
        hint: layer4.transport_scope || "application_gateway",
      },
      {
        label: "Concurrent monitor",
        value: String(layer4.monitor_active_threshold || 0),
        hint: `Block at ${layer4.block_active_threshold || 0}`,
      },
      {
        label: "Burst monitor",
        value: String(layer4.monitor_burst_threshold || 0),
        hint: `Block at ${layer4.block_burst_threshold || 0}`,
      },
      {
        label: "Stale monitor",
        value: String(layer4.monitor_stale_threshold || 0),
        hint: `Block at ${layer4.block_stale_threshold || 0}`,
      },
      {
        label: "Half-open mode",
        value: layer4.half_open_mode || "application_approximation",
        hint: `${layer4.stale_seconds || 0}s stale window`,
      },
      {
        label: "Connections per IP",
        value: String(perConnection.connections_per_ip?.monitor || 0),
        hint: `Block at ${perConnection.connections_per_ip?.block || 0}`,
      },
      {
        label: "New conn/sec",
        value: String(perConnection.new_connections_per_second?.monitor || 0),
        hint: `Block at ${perConnection.new_connections_per_second?.block || 0}`,
      },
      {
        label: "Sessions/source",
        value: String(perConnection.concurrent_sessions_per_source?.monitor || 0),
        hint: `Block at ${perConnection.concurrent_sessions_per_source?.block || 0}`,
      },
    );
  }

  if ((layer4.active_connections_total || 0) > 0 || (layer4.tracked_ips || 0) > 0) {
    overviewCards.push({
      label: "Active connections",
      value: String(layer4.active_connections_total || 0),
      hint: `${layer4.tracked_ips || 0} tracked IPs`,
    });
  }

  if ((perConnectionTelemetry.max_new_connections_per_second || 0) > 0) {
    overviewCards.push({
      label: "Peak new conn/sec",
      value: String(perConnectionTelemetry.max_new_connections_per_second || 0),
      hint: "Live Layer 4 throttle telemetry",
    });
  }

  if ((perConnectionTelemetry.max_concurrent_sessions_per_source || 0) > 0) {
    overviewCards.push({
      label: "Peak sessions/source",
      value: String(perConnectionTelemetry.max_concurrent_sessions_per_source || 0),
      hint: "Concurrent session buckets by source",
    });
  }

  if (showTransportAwareness) {
    overviewCards.push({
      label: "TCP/UDP awareness",
      value: "enabled",
      hint: transport.scope_modes?.join(" + ") || "application_inference",
    });
  }

  if ((transportTelemetry.syn_like_events || 0) > 0) {
    overviewCards.push({
      label: "SYN-like events",
      value: String(transportTelemetry.syn_like_events || 0),
      hint: `Monitor ${transport.syn_monitor_burst_threshold || 0} | Block ${transport.syn_block_burst_threshold || 0}`,
    });
  }

  if ((transportTelemetry.connection_reset_events || 0) > 0) {
    overviewCards.push({
      label: "Reset events",
      value: String(transportTelemetry.connection_reset_events || 0),
      hint: `Stale monitor ${transport.reset_monitor_stale_threshold || 0} | Block ${transport.reset_block_stale_threshold || 0}`,
    });
  }

  if ((transportTelemetry.abnormal_session_events || 0) > 0) {
    overviewCards.push({
      label: "Abnormal sessions",
      value: String(transportTelemetry.abnormal_session_events || 0),
      hint: `Score ${transport.abnormal_session_monitor_score || 0} / ${transport.abnormal_session_block_score || 0}`,
    });
  }

  if ((transportTelemetry.udp_transport_events || 0) > 0) {
    overviewCards.push({
      label: "UDP transport events",
      value: String(transportTelemetry.udp_transport_events || 0),
      hint: `Monitor ${transport.udp_monitor_burst_threshold || 0} | Block ${transport.udp_block_burst_threshold || 0}`,
    });
  }

  if ((transportTelemetry.connection_churn_events || 0) > 0) {
    overviewCards.push({
      label: "Connection churn",
      value: String(transportTelemetry.connection_churn_events || 0),
      hint: `Ratio ${Number(transport.churn_monitor_ratio || 0).toFixed(1)} / ${Number(transport.churn_block_ratio || 0).toFixed(1)}`,
    });
  }

  if ((transportTelemetry.short_lived_abusive_events || 0) > 0) {
    overviewCards.push({
      label: "Short-lived abuse",
      value: String(transportTelemetry.short_lived_abusive_events || 0),
      hint: `${transport.short_lived_duration_ms_threshold || 0} ms | Score ${transport.short_lived_monitor_score || 0}/${transport.short_lived_block_score || 0}`,
    });
  }

  if ((transportTelemetry.retry_timeout_events || 0) > 0) {
    overviewCards.push({
      label: "Retries / timeouts",
      value: String(transportTelemetry.retry_timeout_events || 0),
      hint: `Score ${transport.retry_monitor_score || 0}/${transport.retry_block_score || 0}`,
    });
  }

  if ((transportTelemetry.malformed_transport_events || 0) > 0) {
    overviewCards.push({
      label: "Malformed transport",
      value: String(transportTelemetry.malformed_transport_events || 0),
      hint: `Score ${transport.malformed_monitor_score || 0}/${transport.malformed_block_score || 0}`,
    });
  }

  if ((transportTelemetry.transport_enriched_requests || 0) > 0) {
    overviewCards.push({
      label: "Proxy-enriched requests",
      value: String(transportTelemetry.transport_enriched_requests || 0),
      hint: "Reverse proxy TCP/UDP metadata seen in window",
    });
  }

  if (showProxyTransport) {
    overviewCards.push(
      {
        label: "Proxy connect/read timeout",
        value: `${Number(proxyTransport.connect_timeout_seconds || 0).toFixed(1)} / ${Number(proxyTransport.read_timeout_seconds || 0).toFixed(1)}s`,
        hint: "Socket timeout tuning to the upstream application",
      },
      {
        label: "Upstream pool size",
        value: `${proxyTransport.upstream_pool_connections || 0} / ${proxyTransport.upstream_pool_maxsize || 0}`,
        hint: "Connections / maxsize",
      },
      {
        label: "Pool concurrency limit",
        value: String(proxyTransport.upstream_concurrency_limit || 0),
        hint:
          (proxyTransportTelemetry.pool_protection_blocks || 0) > 0
            ? `${proxyTransportTelemetry.pool_protection_blocks || 0} protection blocks`
            : "Pool protection active",
      },
    );
    if (proxyTransport.keepalive_abuse_protection_enabled) {
      overviewCards.push({
        label: "Keep-alive abuse",
        value: "enabled",
        hint:
          (proxyTransportTelemetry.keepalive_close_events || 0) > 0 || (proxyTransportTelemetry.keepalive_block_events || 0) > 0
            ? `${proxyTransportTelemetry.keepalive_close_events || 0} forced closes | ${proxyTransportTelemetry.keepalive_block_events || 0} hard blocks`
            : "Protection active",
      });
    }
  }

  if ((proxyTransportTelemetry.idle_recycles || 0) > 0) {
    overviewCards.push({
      label: "Idle pool recycle",
      value: `${proxyTransport.idle_pool_recycle_seconds || 0}s`,
      hint: `${proxyTransportTelemetry.idle_recycles || 0} idle pool refreshes`,
    });
  }

  if ((proxyTransportTelemetry.active_upstream_requests || 0) > 0 || (proxyTransportTelemetry.max_active_upstream_requests || 0) > 0) {
    overviewCards.push({
      label: "Active upstream requests",
      value: String(proxyTransportTelemetry.active_upstream_requests || 0),
      hint: `Peak ${proxyTransportTelemetry.max_active_upstream_requests || 0}`,
    });
  }

  return (
    <div className="admin-stack auto-tuning-card">
      <div className="simulation-banner">
        <strong>Security Scope</strong>
        <span>
          {activeModules.length
            ? `Active controls: ${activeModules.join(", ")}.`
            : "No advanced runtime security controls are currently enabled for this scope."}
        </span>
        <small>Only enabled controls and live activity are shown below.</small>
      </div>

      {policyHighlights.length ? (
        <div className="endpoint-policy-shell">
          <div className="simulation-subhead">
            <strong>Built-in endpoint profiles</strong>
            <span>The gateway already gives these paths different policies, rates, and sensitivities.</span>
          </div>
          <div className="endpoint-policy-grid">
            {policyHighlights.map(({ key, title, policy, note }) => (
              <div className="endpoint-policy-card" key={`${key}-${policy.policy_id}`}>
                <div className="endpoint-policy-card-topline">
                  <strong>{title}</strong>
                  <span>{policy.sensitivity}</span>
                </div>
                <div className="endpoint-policy-card-body">
                  <span>Matched by {policy.path_pattern}</span>
                  <span>
                    {(policy.methods || []).join(", ")} | {policy.settings?.bucket_scope || policy.bucket_scope || "ip"}
                  </span>
                  <span>
                    {policy.settings?.requests_per_min || policy.requests_per_min || 0} req/min
                    {" | "}
                    monitor {policy.settings?.monitor_threshold ?? policy.monitor_threshold ?? "-"}
                    {" | "}
                    block {policy.settings?.block_threshold ?? policy.block_threshold ?? "-"}
                  </span>
                  {note ? <small>{note}</small> : null}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      <div className="settings-grid">
        {overviewCards.map((card) => (
          <MetricCard key={`${card.label}-${card.value}-${card.hint || ""}`} label={card.label} value={card.value} hint={card.hint} />
        ))}
      </div>

      {customPolicies.length ? (
        <div className="blacklist-list">
          {customPolicies.map((policy) => (
            <div className="blacklist-item admin-user-item" key={policy.policy_id}>
              <div>
                <strong>{policy.name}</strong>
                <span>{policy.path_pattern}</span>
                <span>{(policy.methods || []).join(", ")}</span>
                <span>{policy.sensitivity}</span>
              </div>
              <div className="section-action-group">
                <span className="muted-inline">{policy.settings?.requests_per_min || 0} req/min</span>
                {canAdmin ? (
                  <button
                    type="button"
                    className="ghost-button"
                    onClick={() => onDeletePolicy(policy.policy_id)}
                    disabled={busyAction === `security-policy-delete-${policy.policy_id}`}
                  >
                    {busyAction === `security-policy-delete-${policy.policy_id}` ? "Removing..." : "Delete"}
                  </button>
                ) : null}
              </div>
            </div>
          ))}
        </div>
      ) : null}

      {canAdmin ? (
        <div className="user-create-card">
          <h3>Create endpoint policy</h3>
          <div className="settings-grid">
            <label className="field compact">
              <span>Name</span>
              <input value={policyDraft.name} onChange={(event) => onPolicyDraftChange("name", event.target.value)} />
            </label>
            <label className="field compact">
              <span>Path pattern</span>
              <input value={policyDraft.path_pattern} onChange={(event) => onPolicyDraftChange("path_pattern", event.target.value)} placeholder="/api/auth/login" />
            </label>
            <label className="field compact">
              <span>Methods</span>
              <input value={policyDraft.methods} onChange={(event) => onPolicyDraftChange("methods", event.target.value)} placeholder="GET,POST" />
            </label>
            <label className="field compact">
              <span>Sensitivity</span>
              <select value={policyDraft.sensitivity} onChange={(event) => onPolicyDraftChange("sensitivity", event.target.value)}>
                <option value="standard">standard</option>
                <option value="protected">protected</option>
                <option value="critical">critical</option>
              </select>
            </label>
            <label className="field compact">
              <span>Req/min</span>
              <input type="number" value={policyDraft.requests_per_min} onChange={(event) => onPolicyDraftChange("requests_per_min", Number(event.target.value))} />
            </label>
            <label className="field compact">
              <span>Bucket scope</span>
              <select value={policyDraft.bucket_scope} onChange={(event) => onPolicyDraftChange("bucket_scope", event.target.value)}>
                <option value="ip_endpoint">ip_endpoint</option>
                <option value="ip">ip</option>
              </select>
            </label>
            <label className="field compact">
              <span>Priority</span>
              <input type="number" value={policyDraft.priority} onChange={(event) => onPolicyDraftChange("priority", Number(event.target.value))} />
            </label>
            <label className="field compact">
              <span>DDoS monitor hits</span>
              <input type="number" value={policyDraft.ddos_monitor_hits} onChange={(event) => onPolicyDraftChange("ddos_monitor_hits", Number(event.target.value))} />
            </label>
            <label className="field compact">
              <span>DDoS block hits</span>
              <input type="number" value={policyDraft.ddos_block_hits} onChange={(event) => onPolicyDraftChange("ddos_block_hits", Number(event.target.value))} />
            </label>
            <label className="field compact">
              <span>Conn. monitor active</span>
              <input
                type="number"
                value={policyDraft.connection_monitor_active}
                onChange={(event) => onPolicyDraftChange("connection_monitor_active", Number(event.target.value))}
              />
            </label>
            <label className="field compact">
              <span>Conn. block active</span>
              <input
                type="number"
                value={policyDraft.connection_block_active}
                onChange={(event) => onPolicyDraftChange("connection_block_active", Number(event.target.value))}
              />
            </label>
            <label className="field compact">
              <span>Conn/IP monitor</span>
              <input
                type="number"
                value={policyDraft.connection_monitor_per_ip}
                onChange={(event) => onPolicyDraftChange("connection_monitor_per_ip", Number(event.target.value))}
              />
            </label>
            <label className="field compact">
              <span>Conn/IP block</span>
              <input
                type="number"
                value={policyDraft.connection_block_per_ip}
                onChange={(event) => onPolicyDraftChange("connection_block_per_ip", Number(event.target.value))}
              />
            </label>
            <label className="field compact">
              <span>Burst monitor</span>
              <input
                type="number"
                value={policyDraft.connection_burst_monitor}
                onChange={(event) => onPolicyDraftChange("connection_burst_monitor", Number(event.target.value))}
              />
            </label>
            <label className="field compact">
              <span>Burst block</span>
              <input
                type="number"
                value={policyDraft.connection_burst_block}
                onChange={(event) => onPolicyDraftChange("connection_burst_block", Number(event.target.value))}
              />
            </label>
            <label className="field compact">
              <span>New conn/sec monitor</span>
              <input
                type="number"
                value={policyDraft.connection_new_per_second_monitor}
                onChange={(event) => onPolicyDraftChange("connection_new_per_second_monitor", Number(event.target.value))}
              />
            </label>
            <label className="field compact">
              <span>New conn/sec block</span>
              <input
                type="number"
                value={policyDraft.connection_new_per_second_block}
                onChange={(event) => onPolicyDraftChange("connection_new_per_second_block", Number(event.target.value))}
              />
            </label>
            <label className="field compact">
              <span>Stale monitor</span>
              <input
                type="number"
                value={policyDraft.connection_stale_monitor}
                onChange={(event) => onPolicyDraftChange("connection_stale_monitor", Number(event.target.value))}
              />
            </label>
            <label className="field compact">
              <span>Stale block</span>
              <input
                type="number"
                value={policyDraft.connection_stale_block}
                onChange={(event) => onPolicyDraftChange("connection_stale_block", Number(event.target.value))}
              />
            </label>
            <label className="field compact">
              <span>Sessions monitor</span>
              <input
                type="number"
                value={policyDraft.connection_sessions_monitor}
                onChange={(event) => onPolicyDraftChange("connection_sessions_monitor", Number(event.target.value))}
              />
            </label>
            <label className="field compact">
              <span>Sessions block</span>
              <input
                type="number"
                value={policyDraft.connection_sessions_block}
                onChange={(event) => onPolicyDraftChange("connection_sessions_block", Number(event.target.value))}
              />
            </label>
            <label className="field compact">
              <span>Block threshold</span>
              <input value={policyDraft.block_threshold} onChange={(event) => onPolicyDraftChange("block_threshold", event.target.value)} placeholder="optional" />
            </label>
            <label className="field compact">
              <span>Monitor threshold</span>
              <input value={policyDraft.monitor_threshold} onChange={(event) => onPolicyDraftChange("monitor_threshold", event.target.value)} placeholder="optional" />
            </label>
            <label className="field compact">
              <span>Description</span>
              <input value={policyDraft.description} onChange={(event) => onPolicyDraftChange("description", event.target.value)} />
            </label>
          </div>
          <div className="section-action-group">
            <button type="button" className="ghost-button" onClick={onRefresh} disabled={busyAction === "security-scope-refresh"}>
              {busyAction === "security-scope-refresh" ? "Refreshing..." : "Refresh security scope"}
            </button>
            <button type="button" className="primary-button" onClick={onCreatePolicy} disabled={busyAction === "security-policy-create"}>
              {busyAction === "security-policy-create" ? "Saving..." : "Save endpoint policy"}
            </button>
          </div>
        </div>
      ) : (
        <div className="section-action-group">
          <button type="button" className="ghost-button" onClick={onRefresh} disabled={busyAction === "security-scope-refresh"}>
            {busyAction === "security-scope-refresh" ? "Refreshing..." : "Refresh security scope"}
          </button>
        </div>
      )}
    </div>
  );
}

function DynamicThresholdsPanel({ report, onRefresh, busyAction, canReview }) {
  if (!canReview) {
    return null;
  }

  if (!report) {
    return <div className="empty-state small">Dynamic threshold analysis has not loaded yet.</div>;
  }

  const telemetry = report.telemetry || {};
  const targets = report.targets || {};
  const effective = report.effective || {};
  const formula = report.formula || {};
  const current = report.current || {};
  const scopeLabel = telemetry.scope === "endpoint" ? telemetry.endpoint_policy_name || telemetry.matched_path || "Matched endpoint" : "Global gateway";

  return (
    <div className="admin-stack auto-tuning-card">
      <div className="simulation-banner">
        <strong>Method 2: Dynamic Thresholds</strong>
        <span>{report.summary || "No dynamic-threshold summary is available."}</span>
        <small>
          Block decisions adapt to recent live traffic using {formula.expression || "avg_score + std_dev"} instead of a single fixed threshold.
        </small>
      </div>

      <div className="settings-grid">
        <div className="meta-card">
          <span>Mode</span>
          <strong>{report.mode || "static"}</strong>
        </div>
        <div className="meta-card">
          <span>Scope</span>
          <strong>{scopeLabel}</strong>
          <small>{telemetry.endpoint_sensitivity || "standard"} sensitivity</small>
        </div>
        <div className="meta-card">
          <span>Active now</span>
          <strong>{report.active ? "yes" : "no"}</strong>
          <small>{report.enabled ? "Enabled in runtime settings" : "Disabled in runtime settings"}</small>
        </div>
        <div className="meta-card">
          <span>Average score</span>
          <strong>{Number(telemetry.avg_risk_score || 0).toFixed(3)}</strong>
          <small>Live traffic only</small>
        </div>
        <div className="meta-card">
          <span>Std dev</span>
          <strong>{Number(telemetry.stddev_risk_score || 0).toFixed(3)}</strong>
          <small>Multiplier {Number(formula.std_multiplier || 1).toFixed(2)}x</small>
        </div>
        <div className="meta-card">
          <span>False positives</span>
          <strong>{Number(telemetry.false_positive_rate || 0).toFixed(3)}</strong>
          <small>Target {Number(targets.target_false_positive_rate || 0).toFixed(3)}</small>
        </div>
        <div className="meta-card">
          <span>Live load</span>
          <strong>{Number(telemetry.requests_per_minute || 0).toFixed(1)} req/min</strong>
          <small>Load ratio {Number(telemetry.load_ratio || 0).toFixed(2)}x</small>
        </div>
        <div className="meta-card">
          <span>Effective block</span>
          <strong>{Number(effective.block_threshold || current.block_threshold || 0).toFixed(3)}</strong>
          <small>Static {Number(current.block_threshold || 0).toFixed(3)}</small>
        </div>
        <div className="meta-card">
          <span>Effective monitor</span>
          <strong>{Number(effective.monitor_threshold || current.monitor_threshold || 0).toFixed(3)}</strong>
          <small>{effective.monitor_threshold_clamped ? "Clamped for ordering" : `Static ${Number(current.monitor_threshold || 0).toFixed(3)}`}</small>
        </div>
        <div className="meta-card">
          <span>Samples</span>
          <strong>{telemetry.total_requests || 0}</strong>
          <small>Minimum {targets.min_samples || 0}</small>
        </div>
        <div className="meta-card">
          <span>Safety band</span>
          <strong>
            {Number(targets.min_block_threshold || 0).toFixed(2)} - {Number(targets.max_block_threshold || 0).toFixed(2)}
          </strong>
          <small>Window {targets.window_seconds || 0}s</small>
        </div>
      </div>

      {report.reasons?.length ? (
        <div className="auto-tuning-reasons">
          {report.reasons.map((reason, index) => (
            <div className="meta-card" key={`${report.generated_at || "dynamic"}-${index}`}>
              <span>Reason {index + 1}</span>
              <strong>{reason}</strong>
            </div>
          ))}
        </div>
      ) : null}

      <div className="section-action-group">
        <button type="button" className="ghost-button" onClick={onRefresh} disabled={busyAction === "dynamic-thresholds-refresh"}>
          {busyAction === "dynamic-thresholds-refresh" ? "Analyzing..." : "Analyze live threshold"}
        </button>
      </div>

      <div className="permission-note auto-tuning-note">
        {buildRuntimeHint({
          enabled: report.enabled,
          enabledText: "Dynamic thresholds are enabled. The gateway can replace static thresholds with live traffic thresholds once enough samples are available.",
          disabledText: "Dynamic thresholds are currently in manual mode. Turn them on from Runtime settings if you want thresholds to follow live traffic automatically.",
        })}
      </div>
    </div>
  );
}

function AdaptiveRateLimitPanel({ report, onRefresh, busyAction, canReview }) {
  if (!canReview) {
    return null;
  }

  if (!report) {
    return <div className="empty-state small">Adaptive rate-limit analysis has not loaded yet.</div>;
  }

  const policy = report.policy || {};
  const classifier = report.classifier || {};
  const telemetry = report.telemetry || {};
  const thresholds = classifier.risk_thresholds || {};
  const profileCounts = telemetry.profile_counts || {};
  const riskBandCounts = telemetry.risk_band_counts || {};
  const topRiskyIps = telemetry.top_risky_ips || [];

  return (
    <div className="admin-stack auto-tuning-card">
      <div className="simulation-banner">
        <strong>Method 3: Adaptive Rate Limiting</strong>
        <span>{report.summary || "No adaptive rate-limit summary is available."}</span>
        <small>
          Risk-based throttling assigns each source IP to a live profile using recent request pressure, flagged activity, and rolling hybrid risk.
        </small>
      </div>

      <div className="settings-grid">
        <div className="meta-card">
          <span>Enabled</span>
          <strong>{report.enabled ? "yes" : "no"}</strong>
        </div>
        <div className="meta-card">
          <span>Normal profile</span>
          <strong>{policy.normal?.requests_per_min || 0} req/min</strong>
          <small>
            Bucket {policy.normal?.capacity || 0} | refill {Number(policy.normal?.refill_rate || 0).toFixed(3)}/s
          </small>
        </div>
        <div className="meta-card">
          <span>Elevated profile</span>
          <strong>{policy.elevated?.requests_per_min || 0} req/min</strong>
          <small>
            Starts near risk score {Number(thresholds.elevated || 0).toFixed(2)}
          </small>
        </div>
        <div className="meta-card">
          <span>Suspicious profile</span>
          <strong>{policy.suspicious?.requests_per_min || 0} req/min</strong>
          <small>
            Starts near risk score {Number(thresholds.suspicious || classifier.min_suspicion_score || 0).toFixed(2)}
          </small>
        </div>
        <div className="meta-card">
          <span>Restricted profile</span>
          <strong>{policy.restricted?.requests_per_min || 0} req/min</strong>
          <small>
            Starts near risk score {Number(thresholds.restricted || 0).toFixed(2)}
          </small>
        </div>
        <div className="meta-card">
          <span>High-volume IPs</span>
          <strong>{telemetry.high_volume_ips || 0}</strong>
          <small>{telemetry.distinct_ips || 0} distinct IPs in live traffic</small>
        </div>
        <div className="meta-card">
          <span>Flagged IPs</span>
          <strong>{telemetry.flagged_ips || 0}</strong>
          <small>Sources with high monitor or block pressure</small>
        </div>
        <div className="meta-card">
          <span>High-risk IPs</span>
          <strong>{telemetry.high_risk_ips || 0}</strong>
          <small>Average or peak risk above the adaptive floor</small>
        </div>
        <div className="meta-card">
          <span>Suspicious candidates</span>
          <strong>{telemetry.suspicious_candidate_ips || 0}</strong>
          <small>Window {classifier.window_seconds || 0}s</small>
        </div>
        <div className="meta-card">
          <span>Restricted candidates</span>
          <strong>{telemetry.restricted_candidate_ips || 0}</strong>
          <small>IPs already severe enough for the tightest budget</small>
        </div>
      </div>

      {report.reasons?.length ? (
        <div className="auto-tuning-reasons">
          {report.reasons.map((reason, index) => (
            <div className="meta-card" key={`${report.generated_at || "adaptive-rate"}-${index}`}>
              <span>Reason {index + 1}</span>
              <strong>{reason}</strong>
            </div>
          ))}
        </div>
      ) : null}

      <div className="section-action-group">
        <button type="button" className="ghost-button" onClick={onRefresh} disabled={busyAction === "adaptive-rate-refresh"}>
          {busyAction === "adaptive-rate-refresh" ? "Analyzing..." : "Analyze IP profiles"}
        </button>
      </div>

      <div className="permission-note auto-tuning-note">
        {buildRuntimeHint({
          enabled: report.enabled,
          enabledText: "Adaptive rate limiting is enabled. The gateway can move sources across normal, elevated, suspicious, and restricted budgets in real time.",
          disabledText: "Adaptive rate limiting is currently in manual mode. Turn it on from Runtime settings to activate multi-tier risk-based throttling.",
        })}
      </div>
    </div>
  );
}

function MlLogTrainingPanel({ report, onRefresh, onApply, busyAction, canAdmin, canReview }) {
  if (!canReview) {
    return null;
  }

  if (!report) {
    return <div className="empty-state small">ML log-training analysis has not loaded yet.</div>;
  }

  const telemetry = report.telemetry || {};
  const targets = report.targets || {};
  const currentModel = report.current_model || {};
  const lastRun = report.last_log_training || {};

  return (
    <div className="admin-stack auto-tuning-card">
      <div className="simulation-banner">
        <strong>Method 5: ML + Logs</strong>
        <span>{report.recommendation?.summary || "No ML log-training summary is available."}</span>
        <small>
          Use reviewed request logs to retrain the runtime model and refresh detection quality over time, including daily improvement when enabled.
        </small>
      </div>

      <div className="settings-grid">
        <div className="meta-card">
          <span>Mode</span>
          <strong>{report.mode || "insufficient_data"}</strong>
        </div>
        <div className="meta-card">
          <span>Algorithm</span>
          <strong>{targets.algorithm || "random_forest"}</strong>
        </div>
        <div className="meta-card">
          <span>Labeled rows</span>
          <strong>{telemetry.labeled_rows || 0}</strong>
          <small>Minimum {targets.min_labeled_rows || 0}</small>
        </div>
        <div className="meta-card">
          <span>Benign / malicious</span>
          <strong>
            {telemetry.benign_rows || 0} / {telemetry.malicious_rows || 0}
          </strong>
          <small>
            Min {targets.min_benign_rows || 0} / {targets.min_malicious_rows || 0}
          </small>
        </div>
        <div className="meta-card">
          <span>Coverage</span>
          <strong>{formatPercent(telemetry.label_coverage_rate)}</strong>
          <small>{telemetry.total_live_requests || 0} live requests in window</small>
        </div>
        <div className="meta-card">
          <span>Distinct paths</span>
          <strong>{telemetry.distinct_labeled_paths || 0}</strong>
          <small>Window {targets.window_seconds || 0}s</small>
        </div>
        <div className="meta-card">
          <span>Current model</span>
          <strong>{currentModel.model_version || "heuristic-fallback"}</strong>
          <small>{currentModel.model_type || "heuristic"}</small>
        </div>
        <div className="meta-card">
          <span>Cooldown</span>
          <strong>{report.cooldown_remaining_seconds || 0}s</strong>
          <small>{report.enabled ? "Auto daily training enabled" : "Manual mode"}</small>
        </div>
      </div>

      {report.recommendation?.reasons?.length ? (
        <div className="auto-tuning-reasons">
          {report.recommendation.reasons.map((reason, index) => (
            <div className="meta-card" key={`${report.generated_at || "ml-logs"}-${index}`}>
              <span>Reason {index + 1}</span>
              <strong>{reason}</strong>
            </div>
          ))}
        </div>
      ) : null}

      <div className="section-action-group">
        <button type="button" className="ghost-button" onClick={onRefresh} disabled={busyAction === "ml-log-training-refresh"}>
          {busyAction === "ml-log-training-refresh" ? "Analyzing..." : "Analyze training logs"}
        </button>
        {canAdmin ? (
          <button
            type="button"
            className="primary-button"
            onClick={onApply}
            disabled={busyAction === "ml-log-training-apply" || !report.can_apply}
          >
            {busyAction === "ml-log-training-apply" ? "Training..." : "Train from logs now"}
          </button>
        ) : null}
      </div>

      <div className="permission-note auto-tuning-note">
        {buildRuntimeHint({
          enabled: report.enabled,
          enabledText: "Daily ML retraining is enabled. The gateway can build a stronger model from reviewed request logs whenever enough labeled data is available.",
          disabledText: "Daily ML retraining is currently manual. Turn it on from Runtime settings if you want the model to improve automatically from reviewed logs.",
          lastLabel: "Last log training",
          lastValue: lastRun.created_at,
        })}
      </div>
    </div>
  );
}

function FeedbackLoopPanel({ report, onRefresh, onApply, busyAction, canAdmin, canReview }) {
  if (!canReview) {
    return null;
  }

  if (!report) {
    return <div className="empty-state small">Feedback-loop analysis has not loaded yet.</div>;
  }

  const telemetry = report.telemetry || {};
  const recommendation = report.recommendation || {};
  const changes = Object.entries(recommendation.changes || {});
  const targets = report.targets || {};
  const lastRun = report.last_feedback_apply || {};

  return (
    <div className="admin-stack auto-tuning-card">
      <div className="simulation-banner">
        <strong>Method 4: Feedback Loop</strong>
        <span>{recommendation.summary || "No feedback-loop summary is available."}</span>
        <small>
          If a blocked request is later labeled benign, the gateway relaxes. If an allowed request is later labeled malicious, the gateway hardens.
        </small>
      </div>

      <div className="settings-grid">
        <div className="meta-card">
          <span>Mode</span>
          <strong>{report.mode || "steady"}</strong>
        </div>
        <div className="meta-card">
          <span>Confidence</span>
          <strong>{report.confidence || "low"}</strong>
        </div>
        <div className="meta-card">
          <span>Total feedback</span>
          <strong>{telemetry.total_feedback || 0}</strong>
          <small>Minimum {targets.min_feedback || 0}</small>
        </div>
        <div className="meta-card">
          <span>Benign after block</span>
          <strong>{telemetry.benign_blocked || 0}</strong>
          <small>{formatPercent(telemetry.benign_false_positive_rate)} false-positive pressure</small>
        </div>
        <div className="meta-card">
          <span>Malicious after allow</span>
          <strong>{telemetry.malicious_allowed || 0}</strong>
          <small>{formatPercent(telemetry.malicious_escape_rate)} escape pressure</small>
        </div>
        <div className="meta-card">
          <span>Cooldown</span>
          <strong>{report.cooldown_remaining_seconds || 0}s</strong>
          <small>Window {targets.window_seconds || 0}s</small>
        </div>
      </div>

      {recommendation.reasons?.length ? (
        <div className="auto-tuning-reasons">
          {recommendation.reasons.map((reason, index) => (
            <div className="meta-card" key={`${report.generated_at || "feedback"}-${index}`}>
              <span>Reason {index + 1}</span>
              <strong>{reason}</strong>
            </div>
          ))}
        </div>
      ) : null}

      <div className="section-action-group">
        <button type="button" className="ghost-button" onClick={onRefresh} disabled={busyAction === "feedback-loop-refresh"}>
          {busyAction === "feedback-loop-refresh" ? "Analyzing..." : "Analyze feedback"}
        </button>
        {canAdmin ? (
          <button
            type="button"
            className="primary-button"
            onClick={onApply}
            disabled={busyAction === "feedback-loop-apply" || !report.can_apply}
          >
            {busyAction === "feedback-loop-apply" ? "Applying..." : "Apply feedback now"}
          </button>
        ) : null}
      </div>

      <div className="permission-note auto-tuning-note">
        {buildRuntimeHint({
          enabled: report.enabled,
          enabledText: "Feedback loop is enabled. Analyst labels can automatically relax or harden sensitivity after the cooldown period.",
          disabledText: "Feedback loop is currently manual. Turn it on from Runtime settings if you want analyst review to adjust sensitivity automatically.",
          lastLabel: "Last feedback update",
          lastValue: lastRun.created_at,
        })}
      </div>
    </div>
  );
}

function AutoTuningPanel({ report, onRefresh, onApply, busyAction, canAdmin, canReview }) {
  if (!canReview) {
    return null;
  }

  if (!report) {
    return <div className="empty-state small">Auto-tuning analysis has not loaded yet.</div>;
  }

  const telemetry = report.telemetry || {};
  const recommendation = report.recommendation || {};
  const changes = Object.entries(recommendation.changes || {});
  const targets = report.targets || {};
  const lastRun = report.last_auto_tune || {};

  return (
    <div className="admin-stack auto-tuning-card">
      <div className="simulation-banner">
        <strong>Method 1: Auto-Tuning</strong>
        <span>{recommendation.summary || "No recommendation summary is available."}</span>
        <small>
          Monitor false positives and attack pressure, then recommend or auto-apply safer thresholds and rate limits.
        </small>
      </div>

      <div className="settings-grid">
        <div className="meta-card">
          <span>Mode</span>
          <strong>{report.mode || "steady"}</strong>
        </div>
        <div className="meta-card">
          <span>Confidence</span>
          <strong>{report.confidence || "low"}</strong>
        </div>
        <div className="meta-card">
          <span>False positives</span>
          <strong>{formatPercent(telemetry.false_positive_rate)}</strong>
          <small>Target {formatPercent(targets.false_positive_rate)}</small>
        </div>
        <div className="meta-card">
          <span>Attack rate</span>
          <strong>{formatPercent(telemetry.attack_rate)}</strong>
          <small>Target {formatPercent(targets.attack_rate)}</small>
        </div>
        <div className="meta-card">
          <span>Samples</span>
          <strong>{telemetry.total_requests || 0}</strong>
          <small>Minimum {targets.min_samples || 0}</small>
        </div>
        <div className="meta-card">
          <span>Cooldown</span>
          <strong>{report.cooldown_remaining_seconds || 0}s</strong>
          <small>Window {targets.window_seconds || 0}s</small>
        </div>
      </div>

      {recommendation.reasons?.length ? (
        <div className="auto-tuning-reasons">
          {recommendation.reasons.map((reason, index) => (
            <div className="meta-card" key={`${report.generated_at || "reason"}-${index}`}>
              <span>Reason {index + 1}</span>
              <strong>{reason}</strong>
            </div>
          ))}
        </div>
      ) : null}

      <div className="section-action-group">
        <button type="button" className="ghost-button" onClick={onRefresh} disabled={busyAction === "auto-tune-refresh"}>
          {busyAction === "auto-tune-refresh" ? "Analyzing..." : "Analyze recent traffic"}
        </button>
        {canAdmin ? (
          <button
            type="button"
            className="primary-button"
            onClick={onApply}
            disabled={busyAction === "auto-tune-apply" || !report.can_apply}
          >
            {busyAction === "auto-tune-apply" ? "Applying..." : "Apply auto-tuning now"}
          </button>
        ) : null}
      </div>

      <div className="permission-note auto-tuning-note">
        {buildRuntimeHint({
          enabled: report.enabled,
          enabledText: "Auto-tuning is enabled. The gateway can keep adjusting thresholds and rate limits as traffic quality changes.",
          disabledText: "Auto-tuning is currently manual. Turn it on from Runtime settings if you want the gateway to keep tuning itself automatically.",
          lastLabel: "Last auto-tune",
          lastValue: lastRun.created_at,
        })}
      </div>
    </div>
  );
}

export function SettingsEditor({
  settingsData,
  draft,
  onChange,
  onSubmit,
  busy,
  canAdmin,
  canReview,
  securityScope,
  securityPolicyDraft,
  onSecurityPolicyDraftChange,
  onRefreshSecurityScope,
  onCreateSecurityPolicy,
  onDeleteSecurityPolicy,
  adaptivity,
  onRefreshAdaptivity,
  onApplyAdaptivity,
  autoTuning,
  onRefreshAutoTuning,
  onApplyAutoTuning,
  mlLogTraining,
  onRefreshMlLogTraining,
  onApplyMlLogTraining,
  feedbackLoop,
  onRefreshFeedbackLoop,
  onApplyFeedbackLoop,
  dynamicThresholds,
  onRefreshDynamicThresholds,
  adaptiveRateLimit,
  onRefreshAdaptiveRateLimit,
  busyAction,
}) {
  const entries = Object.entries(draft || {});
  const [openSections, setOpenSections] = useState({
    securityScope: true,
    adaptivity: false,
    mlLogTraining: false,
    feedbackLoop: false,
    adaptiveRateLimit: false,
    dynamicThresholds: false,
    autoTuning: false,
    runtimeSettings: false,
    runtimeJson: false,
  });
  const [openFieldGroups, setOpenFieldGroups] = useState({
    gateway: true,
    traffic: true,
    preapp: false,
    proxy: false,
    connection: false,
    transport: false,
    adaptivity: false,
    dynamic: false,
    adaptiveRate: false,
    feedback: false,
    mlLogs: false,
    modelAuth: false,
    other: false,
  });
  const runtimeFieldGroups = groupRuntimeEntries(entries);

  function toggleSection(sectionKey) {
    setOpenSections((current) => ({ ...current, [sectionKey]: !current[sectionKey] }));
  }

  function toggleFieldGroup(groupKey) {
    setOpenFieldGroups((current) => ({ ...current, [groupKey]: !current[groupKey] }));
  }

  if (!entries.length) {
    return <div className="empty-state small">Settings metadata has not loaded yet.</div>;
  }

  if (!canAdmin) {
    return (
      <div className="admin-stack">
        <RuntimeStrategySection
          sectionKey="securityScope"
          title="Security Scope"
          description="Endpoint policy, DDoS scope, Layer 4 telemetry, and pre-app filtering."
          open={openSections.securityScope}
          onToggle={toggleSection}
        >
          <SecurityScopePanel
            report={securityScope}
            policyDraft={securityPolicyDraft}
            onPolicyDraftChange={onSecurityPolicyDraftChange}
            onRefresh={onRefreshSecurityScope}
            onCreatePolicy={onCreateSecurityPolicy}
            onDeletePolicy={onDeleteSecurityPolicy}
            busyAction={busyAction}
            canAdmin={canAdmin}
            canReview={canReview}
          />
        </RuntimeStrategySection>
        <RuntimeStrategySection
          sectionKey="adaptivity"
          title="Adaptivity"
          description="Unified posture control for thresholds, feedback, and self-adjustment."
          open={openSections.adaptivity}
          onToggle={toggleSection}
        >
          <AdaptivityPanel
            report={adaptivity}
            onRefresh={onRefreshAdaptivity}
            onApply={onApplyAdaptivity}
            busyAction={busyAction}
            canAdmin={canAdmin}
            canReview={canReview}
          />
        </RuntimeStrategySection>
        <RuntimeStrategySection
          sectionKey="mlLogTraining"
          title="ML + Logs"
          description="Model retraining from reviewed logs and continuous supervised improvement."
          open={openSections.mlLogTraining}
          onToggle={toggleSection}
        >
          <MlLogTrainingPanel
            report={mlLogTraining}
            onRefresh={onRefreshMlLogTraining}
            onApply={onApplyMlLogTraining}
            busyAction={busyAction}
            canAdmin={canAdmin}
            canReview={canReview}
          />
        </RuntimeStrategySection>
        <RuntimeStrategySection
          sectionKey="feedbackLoop"
          title="Feedback Loop"
          description="Relax or harden sensitivity based on analyst review outcomes."
          open={openSections.feedbackLoop}
          onToggle={toggleSection}
        >
          <FeedbackLoopPanel
            report={feedbackLoop}
            onRefresh={onRefreshFeedbackLoop}
            onApply={onApplyFeedbackLoop}
            busyAction={busyAction}
            canAdmin={canAdmin}
            canReview={canReview}
          />
        </RuntimeStrategySection>
        <RuntimeStrategySection
          sectionKey="adaptiveRateLimit"
          title="Adaptive Rate Limiting"
          description="Risk-based throttling profiles for normal, elevated, suspicious, and restricted sources."
          open={openSections.adaptiveRateLimit}
          onToggle={toggleSection}
        >
          <AdaptiveRateLimitPanel
            report={adaptiveRateLimit}
            onRefresh={onRefreshAdaptiveRateLimit}
            busyAction={busyAction}
            canReview={canReview}
          />
        </RuntimeStrategySection>
        <RuntimeStrategySection
          sectionKey="dynamicThresholds"
          title="Dynamic Thresholds"
          description="Move monitor and block thresholds with live traffic statistics."
          open={openSections.dynamicThresholds}
          onToggle={toggleSection}
        >
          <DynamicThresholdsPanel
            report={dynamicThresholds}
            onRefresh={onRefreshDynamicThresholds}
            busyAction={busyAction}
            canReview={canReview}
          />
        </RuntimeStrategySection>
        <RuntimeStrategySection
          sectionKey="autoTuning"
          title="Auto-Tuning"
          description="Self-adjust gateway parameters from observed false positives and attack pressure."
          open={openSections.autoTuning}
          onToggle={toggleSection}
        >
          <AutoTuningPanel
            report={autoTuning}
            onRefresh={onRefreshAutoTuning}
            onApply={onApplyAutoTuning}
            busyAction={busyAction}
            canAdmin={canAdmin}
            canReview={canReview}
          />
        </RuntimeStrategySection>
        <RuntimeStrategySection
          sectionKey="runtimeJson"
          title="Runtime settings snapshot"
          description="Read-only JSON view of the current effective runtime settings."
          open={openSections.runtimeJson}
          onToggle={toggleSection}
        >
          <div className="json-block">
            <h4>Runtime settings</h4>
            <pre>{JSON.stringify(settingsData.settings || {}, null, 2)}</pre>
          </div>
        </RuntimeStrategySection>
      </div>
    );
  }

  return (
    <div className="admin-stack">
      <RuntimeStrategySection
        sectionKey="securityScope"
        title="Security Scope"
        description="Endpoint policy, DDoS scope, Layer 4 telemetry, and pre-app filtering."
        open={openSections.securityScope}
        onToggle={toggleSection}
      >
        <SecurityScopePanel
          report={securityScope}
          policyDraft={securityPolicyDraft}
          onPolicyDraftChange={onSecurityPolicyDraftChange}
          onRefresh={onRefreshSecurityScope}
          onCreatePolicy={onCreateSecurityPolicy}
          onDeletePolicy={onDeleteSecurityPolicy}
          busyAction={busyAction}
          canAdmin={canAdmin}
          canReview={canReview}
        />
      </RuntimeStrategySection>
      <RuntimeStrategySection
        sectionKey="adaptivity"
        title="Adaptivity"
        description="Unified posture control for thresholds, feedback, and self-adjustment."
        open={openSections.adaptivity}
        onToggle={toggleSection}
      >
        <AdaptivityPanel
          report={adaptivity}
          onRefresh={onRefreshAdaptivity}
          onApply={onApplyAdaptivity}
          busyAction={busyAction}
          canAdmin={canAdmin}
          canReview={canReview}
        />
      </RuntimeStrategySection>
      <RuntimeStrategySection
        sectionKey="mlLogTraining"
        title="ML + Logs"
        description="Model retraining from reviewed logs and continuous supervised improvement."
        open={openSections.mlLogTraining}
        onToggle={toggleSection}
      >
        <MlLogTrainingPanel
          report={mlLogTraining}
          onRefresh={onRefreshMlLogTraining}
          onApply={onApplyMlLogTraining}
          busyAction={busyAction}
          canAdmin={canAdmin}
          canReview={canReview}
        />
      </RuntimeStrategySection>
      <RuntimeStrategySection
        sectionKey="feedbackLoop"
        title="Feedback Loop"
        description="Relax or harden sensitivity based on analyst review outcomes."
        open={openSections.feedbackLoop}
        onToggle={toggleSection}
      >
        <FeedbackLoopPanel
          report={feedbackLoop}
          onRefresh={onRefreshFeedbackLoop}
          onApply={onApplyFeedbackLoop}
          busyAction={busyAction}
          canAdmin={canAdmin}
          canReview={canReview}
        />
      </RuntimeStrategySection>
      <RuntimeStrategySection
        sectionKey="adaptiveRateLimit"
        title="Adaptive Rate Limiting"
        description="Risk-based throttling profiles for normal, elevated, suspicious, and restricted sources."
        open={openSections.adaptiveRateLimit}
        onToggle={toggleSection}
      >
        <AdaptiveRateLimitPanel
          report={adaptiveRateLimit}
          onRefresh={onRefreshAdaptiveRateLimit}
          busyAction={busyAction}
          canReview={canReview}
        />
      </RuntimeStrategySection>
      <RuntimeStrategySection
        sectionKey="dynamicThresholds"
        title="Dynamic Thresholds"
        description="Move monitor and block thresholds with live traffic statistics."
        open={openSections.dynamicThresholds}
        onToggle={toggleSection}
      >
        <DynamicThresholdsPanel
          report={dynamicThresholds}
          onRefresh={onRefreshDynamicThresholds}
          busyAction={busyAction}
          canReview={canReview}
        />
      </RuntimeStrategySection>
      <RuntimeStrategySection
        sectionKey="autoTuning"
        title="Auto-Tuning"
        description="Self-adjust gateway parameters from observed false positives and attack pressure."
        open={openSections.autoTuning}
        onToggle={toggleSection}
      >
        <AutoTuningPanel
          report={autoTuning}
          onRefresh={onRefreshAutoTuning}
          onApply={onApplyAutoTuning}
          busyAction={busyAction}
          canAdmin={canAdmin}
          canReview={canReview}
        />
      </RuntimeStrategySection>
      <RuntimeStrategySection
        sectionKey="runtimeSettings"
        title="Editable runtime values"
        description="Direct edit mode for threshold, proxy, and gateway configuration fields."
        open={openSections.runtimeSettings}
        onToggle={toggleSection}
      >
        <div className="runtime-field-stack">
          {runtimeFieldGroups.map((group) => (
            <section className={`runtime-field-group ${openFieldGroups[group.key] ? "is-open" : "is-closed"}`} key={group.key}>
              <button
                type="button"
                className="runtime-field-group-header"
                onClick={() => toggleFieldGroup(group.key)}
                aria-expanded={!!openFieldGroups[group.key]}
              >
                <div className="runtime-field-group-copy">
                  <strong>{group.title}</strong>
                  <span>{group.description}</span>
                </div>
                <span className="runtime-field-group-toggle">{openFieldGroups[group.key] ? "Hide" : "Show"}</span>
              </button>
              {openFieldGroups[group.key] ? (
                <div className="runtime-field-group-body">
                  <div className="settings-grid runtime-settings-grid">
                    {group.items.map(([key, value]) => {
                      const isBoolean = typeof settingsData.settings?.[key] === "boolean";
                      const isNumber = typeof settingsData.settings?.[key] === "number";
                      return (
                        <label className="field compact runtime-field" key={key}>
                          <span>{formatRuntimeFieldLabel(key)}</span>
                          <small className="runtime-field-key">{key}</small>
                          {isBoolean ? (
                            <select value={value ? "true" : "false"} onChange={(event) => onChange(key, event.target.value === "true")}>
                              <option value="true">true</option>
                              <option value="false">false</option>
                            </select>
                          ) : (
                            <input
                              type={isNumber ? "number" : "text"}
                              step={typeof value === "number" && !Number.isInteger(value) ? "0.01" : "1"}
                              value={value}
                              onChange={(event) => onChange(key, isNumber ? Number(event.target.value) : event.target.value)}
                            />
                          )}
                        </label>
                      );
                    })}
                  </div>
                </div>
              ) : null}
            </section>
          ))}
        </div>
        <button className="primary-button" type="button" onClick={onSubmit} disabled={busy}>
          {busy ? "Saving..." : "Save runtime settings"}
        </button>
      </RuntimeStrategySection>
    </div>
  );
}

export function UserDirectory({ users, drafts, onDraftChange, onCreateChange, createForm, onCreate, onSaveUser, busyAction }) {
  return (
    <div className="admin-stack">
      <div className="user-create-card">
        <h3>Create user</h3>
        <div className="settings-grid">
          <label className="field compact">
            <span>Username</span>
            <input value={createForm.username} onChange={(event) => onCreateChange("username", event.target.value)} />
          </label>
          <label className="field compact">
            <span>Display name</span>
            <input value={createForm.display_name} onChange={(event) => onCreateChange("display_name", event.target.value)} />
          </label>
          <label className="field compact">
            <span>Role</span>
            <select value={createForm.role} onChange={(event) => onCreateChange("role", event.target.value)}>
              <option value="viewer">viewer</option>
              <option value="analyst">analyst</option>
              <option value="admin">admin</option>
            </select>
          </label>
          <label className="field compact">
            <span>Password</span>
            <input type="password" value={createForm.password} onChange={(event) => onCreateChange("password", event.target.value)} />
          </label>
        </div>
        <button className="primary-button" type="button" onClick={onCreate} disabled={busyAction === "create-user"}>
          {busyAction === "create-user" ? "Saving..." : "Create user"}
        </button>
      </div>

      <div className="blacklist-list">
        {users.map((user) => {
          const draft = drafts[user.user_id] || {};
          return (
            <div className="blacklist-item admin-user-item" key={user.user_id}>
              <div>
                <strong>
                  {user.display_name} <RoleBadge role={user.role} />
                </strong>
                <span>{user.username}</span>
                <span>{user.is_active ? "active" : "disabled"}</span>
              </div>
              <div className="user-edit-grid">
                <label className="field compact">
                  <span>Role</span>
                  <select value={draft.role || user.role} onChange={(event) => onDraftChange(user.user_id, "role", event.target.value)}>
                    <option value="viewer">viewer</option>
                    <option value="analyst">analyst</option>
                    <option value="admin">admin</option>
                  </select>
                </label>
                <label className="field compact">
                  <span>Status</span>
                  <select
                    value={draft.is_active ?? user.is_active ? "true" : "false"}
                    onChange={(event) => onDraftChange(user.user_id, "is_active", event.target.value === "true")}
                  >
                    <option value="true">active</option>
                    <option value="false">disabled</option>
                  </select>
                </label>
                <label className="field compact">
                  <span>Reset password</span>
                  <input
                    type="password"
                    value={draft.password || ""}
                    onChange={(event) => onDraftChange(user.user_id, "password", event.target.value)}
                    placeholder="leave blank"
                  />
                </label>
                <button
                  type="button"
                  className="ghost-button"
                  disabled={busyAction === `save-user-${user.user_id}`}
                  onClick={() => onSaveUser(user.user_id)}
                >
                  {busyAction === `save-user-${user.user_id}` ? "Saving..." : "Save"}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function AuditTrail({ items }) {
  if (!items.length) {
    return <div className="empty-state small">No audit events captured yet.</div>;
  }

  return (
    <div className="audit-list">
      {items.map((item) => (
        <div className="audit-item" key={item.event_id}>
          <div>
            <strong>{item.action}</strong>
            <span>{item.actor_username || "system"} on {item.target_type}</span>
          </div>
          <span>{new Date(item.created_at).toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}
