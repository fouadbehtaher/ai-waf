import { startTransition, useDeferredValue, useEffect, useState } from "react";
import { AuditTrail, RoleBadge, SettingsEditor, UserDirectory } from "./AdminPanels";
import LoginScreen from "./LoginScreen";
import { apiFetch, clearStoredSession, readStoredSession, roleAllows, writeStoredSession } from "./session";

const numberFormatter = new Intl.NumberFormat();

const emptySummary = {
  total_requests: 0,
  allowed: 0,
  monitored: 0,
  blocked: 0,
  unique_ips: 0,
  avg_latency_ms: 0,
  avg_risk_score: 0,
  blacklist_size: 0,
  top_attack_types: [],
  top_offenders: [],
  events: [],
  auth: {},
  system: {},
  notifications: [],
  notification_counts: { total: 0, by_kind: {}, by_category: {} },
  simulation: null,
};

const emptyRequests = {
  items: [],
  pagination: {
    page: 1,
    page_size: 20,
    total: 0,
    pages: 1,
  },
};

function StatCard({ label, value, hint, tone = "neutral" }) {
  return (
    <article className={`stat-card tone-${tone}`}>
      <span className="stat-label">{label}</span>
      <strong className="stat-value">{value}</strong>
      <span className="stat-hint">{hint}</span>
    </article>
  );
}

function SectionTitle({ eyebrow, title, description, actions }) {
  return (
    <div className="section-title">
      <div>
        {eyebrow ? <span className="section-eyebrow">{eyebrow}</span> : null}
        <h2>{title}</h2>
        {description ? <p>{description}</p> : null}
      </div>
      {actions ? <div className="section-actions">{actions}</div> : null}
    </div>
  );
}

function TimelineChart({ items }) {
  const trimmed = items.slice(-24);
  const maxValue = Math.max(
    1,
    ...trimmed.map((item) => item.allow + item.monitor + item.block)
  );

  return (
    <div className="timeline-chart">
      {trimmed.map((item) => {
        const total = item.allow + item.monitor + item.block;
        const label = new Date(item.bucket_start).toLocaleString([], {
          month: "short",
          day: "numeric",
          hour: "2-digit",
        });
        return (
          <div className="timeline-column" key={item.bucket_start} title={`${label} | allow ${item.allow} | monitor ${item.monitor} | block ${item.block}`}>
            <div className="timeline-stack">
              <span className="segment allow" style={{ height: `${(item.allow / maxValue) * 100}%` }} />
              <span className="segment monitor" style={{ height: `${(item.monitor / maxValue) * 100}%` }} />
              <span className="segment block" style={{ height: `${(item.block / maxValue) * 100}%` }} />
            </div>
            <span className="timeline-label">{label}</span>
            <strong className="timeline-total">{total}</strong>
          </div>
        );
      })}
    </div>
  );
}

function DistributionList({ items, emptyLabel, tone = "teal" }) {
  const maxValue = Math.max(1, ...items.map((item) => item.count || item.blocked_requests || item.total_requests || 0));
  if (!items.length) {
    return <div className="empty-state small">{emptyLabel}</div>;
  }

  return (
    <div className="distribution-list">
      {items.map((item) => {
        const value = item.count ?? item.blocked_requests ?? item.total_requests ?? 0;
        const label = item.label || item.attack_type || item.remote_addr || "Unknown";
        const description = item.description || "";
        return (
          <div className="distribution-item" key={label}>
            <div className="distribution-copy">
              <div className="distribution-copy-text">
                <strong>{label}</strong>
                {description ? <span>{description}</span> : null}
              </div>
              <span className="distribution-metric">{value} event{value === 1 ? "" : "s"}</span>
            </div>
            <div className="distribution-bar">
              <span className={`distribution-fill tone-${tone}`} style={{ width: `${(value / maxValue) * 100}%` }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function JsonBlock({ title, value }) {
  return (
    <div className="json-block">
      <h4>{title}</h4>
      <pre>{JSON.stringify(value, null, 2)}</pre>
    </div>
  );
}

function formatPercent(value) {
  return `${Math.round(Number(value || 0) * 100)}%`;
}

function DecisionEngineSection({ engine }) {
  if (!engine || !Object.keys(engine).length) {
    return null;
  }

  const score = engine.score || {};
  const thresholds = engine.thresholds || {};
  const confidence = engine.confidence || {};
  const rules = engine.rules || {};
  const history = engine.offense_history || {};
  const basis = Array.isArray(engine.decision_basis) ? engine.decision_basis : [];
  const offenseSignals = Array.isArray(history.signals) ? history.signals : [];

  return (
    <div className="decision-engine-shell">
      <div className="simulation-banner simulation-banner-subtle">
        <strong>Decision engine</strong>
        <span>{engine.summary || "No decision summary is available for this request yet."}</span>
        <small>{confidence.usage || "The live decision is based on rules, thresholds, and history-aware controls."}</small>
      </div>

      <div className="detail-copy-grid">
        <div className="meta-card">
          <span>Primary driver</span>
          <strong>{String(engine.decision_path || "allow_below_thresholds").replace(/_/g, " ")}</strong>
          <small>{engine.action || "allow"}</small>
        </div>
        <div className="meta-card">
          <span>Score and threshold</span>
          <strong>
            {Number(score.risk_score || 0).toFixed(3)} vs {Number(thresholds.block_threshold || 0).toFixed(3)}
          </strong>
          <small>
            Monitor {Number(thresholds.monitor_threshold || 0).toFixed(3)} | mode {thresholds.threshold_mode || "static"}
          </small>
        </div>
        <div className="meta-card">
          <span>Confidence</span>
          <strong>{confidence.level || "low"}</strong>
          <small>{confidence.reason || "No confidence explanation is available."}</small>
        </div>
        <div className="meta-card">
          <span>Model blend</span>
          <strong>
            {score.weighted_combination
              ? `${Math.round(Number(score.heuristic_weight || 0) * 100)}% heuristic / ${Math.round(Number(score.ml_weight || 0) * 100)}% ML`
              : "Heuristic score only"}
          </strong>
          <small>{score.model_name || "unknown model"} | {score.model_version || "no version"}</small>
        </div>
        <div className="meta-card">
          <span>Rule pressure</span>
          <strong>{rules.matched_count || 0} matched</strong>
          <small>
            {rules.blocking_rule_hit ? "Blocking rule hit" : rules.monitor_rule_hit ? "Monitor rule hit" : "No decisive rule hit"}
          </small>
        </div>
        <div className="meta-card">
          <span>Offense history</span>
          <strong>
            {history.blocked_count_window || 0} blocked / {history.request_count_window || 0} requests
          </strong>
          <small>
            Flagged {formatPercent(history.flagged_ratio)} | Fingerprint reuse {history.fingerprint_reuse_count || 0}
          </small>
        </div>
      </div>

      {basis.length ? (
        <div className="decision-basis-row">
          {basis.map((item) => (
            <span className="mini-flag neutral" key={item}>
              {String(item).replace(/_/g, " ")}
            </span>
          ))}
        </div>
      ) : null}

      <div className="decision-signal-list">
        {offenseSignals.length ? (
          offenseSignals.map((signal, index) => (
            <div className="meta-card" key={`${engine.decision_path || "decision"}-${index}`}>
              <span>History signal {index + 1}</span>
              <strong>{signal}</strong>
            </div>
          ))
        ) : (
          <div className="meta-card">
            <span>History influence</span>
            <strong>No elevated offense history shaped this request.</strong>
            <small>The action came mainly from the current score and rule state.</small>
          </div>
        )}
      </div>
    </div>
  );
}

function AdvancedDiagnosticsSection({ canViewInternals, scoreBreakdown, ruleResult, features, contextLabel = "request" }) {
  const [open, setOpen] = useState(false);

  if (!canViewInternals) {
    return (
      <div className="permission-note">
        Internal model and rule diagnostics are restricted to analyst and admin roles.
      </div>
    );
  }

  return (
    <div className="diagnostics-shell">
      <div className="diagnostics-summary">
        <div>
          <strong>Advanced diagnostics</strong>
          <span>
            Detailed scoring, rule, and feature internals for this {contextLabel} are hidden by default to keep the review
            workspace focused.
          </span>
        </div>
        <button type="button" className="ghost-button diagnostics-toggle" onClick={() => setOpen((current) => !current)}>
          {open ? "Hide diagnostics" : "Show diagnostics"}
        </button>
      </div>

      {open ? (
        <>
          <JsonBlock title="Score breakdown" value={scoreBreakdown} />
          <JsonBlock title="Rules and hits" value={ruleResult} />
          <JsonBlock title="Feature vector" value={features} />
        </>
      ) : null}
    </div>
  );
}

function formatScopeLabel(scopeType) {
  const normalized = String(scopeType || "").trim().toLowerCase();
  if (normalized === "signature") {
    return "Request signature";
  }
  if (normalized === "path") {
    return "Method + path";
  }
  if (normalized === "session") {
    return "Session match";
  }
  if (normalized === "ip") {
    return "IP address";
  }
  return normalized ? normalized.replace(/_/g, " ") : "Rule";
}

function formatRuleCriteria(criteria = {}) {
  const entries = [];
  if (criteria.method) {
    entries.push({ label: "Method", value: String(criteria.method) });
  }
  if (criteria.path) {
    entries.push({ label: "Path", value: String(criteria.path) });
  }
  if (criteria.session_id) {
    entries.push({ label: "Session", value: String(criteria.session_id) });
  }
  if (criteria.remote_addr) {
    entries.push({ label: "IP", value: String(criteria.remote_addr) });
  }
  if (criteria.request_fingerprint) {
    const fingerprint = String(criteria.request_fingerprint);
    entries.push({
      label: "Fingerprint",
      value: fingerprint.length > 18 ? `${fingerprint.slice(0, 10)}...${fingerprint.slice(-6)}` : fingerprint,
      title: fingerprint,
      mono: true,
    });
  }

  for (const [key, rawValue] of Object.entries(criteria || {})) {
    if (["method", "path", "session_id", "remote_addr", "request_fingerprint"].includes(key)) {
      continue;
    }
    entries.push({
      label: key.replace(/_/g, " "),
      value: typeof rawValue === "string" ? rawValue : JSON.stringify(rawValue),
    });
  }

  return entries;
}

function ManualRulesPanel({ items, busyAction, onRemove }) {
  if (!items.length) {
    return <div className="empty-state small">No targeted block rules are active.</div>;
  }

  return (
    <div className="manual-rule-stack">
      <div className="manual-rule-summary">
        <strong>{items.length} active targeted rule{items.length === 1 ? "" : "s"}</strong>
        <span>Fine-grained match blocks created from specific request factors rather than broad IP blacklisting.</span>
      </div>

      {items.map((rule) => {
        const criteriaRows = formatRuleCriteria(rule.criteria || {});
        return (
          <article className="manual-rule-card" key={rule.rule_id}>
            <div className="manual-rule-topline">
              <div className="manual-rule-tags">
                <span className="mini-flag blocked">{formatScopeLabel(rule.scope_type)}</span>
                <span className="mini-flag neutral">{rule.source || "manual"}</span>
              </div>
              <button
                type="button"
                className="ghost-button"
                disabled={busyAction === `manual-rule-${rule.rule_id}`}
                onClick={() => onRemove(rule.rule_id)}
              >
                {busyAction === `manual-rule-${rule.rule_id}` ? "Removing..." : "Remove"}
              </button>
            </div>

            <div className="manual-rule-body">
              <div className="manual-rule-copy">
                <strong>{rule.reason || "Targeted rule"}</strong>
                <span>Rule ID: {rule.rule_id}</span>
              </div>

              <div className="manual-rule-meta">
                <div className="manual-rule-meta-card">
                  <span>Created</span>
                  <strong>{formatDateTime(rule.created_at)}</strong>
                  <small>{formatRelativeTime(rule.created_at)}</small>
                </div>
                <div className="manual-rule-meta-card">
                  <span>Expires</span>
                  <strong>{rule.expires_at ? formatDateTime(rule.expires_at) : "No expiry"}</strong>
                  <small>{rule.expires_at ? formatRelativeTime(rule.expires_at) : "Persistent rule"}</small>
                </div>
              </div>

              {criteriaRows.length ? (
                <div className="manual-rule-criteria">
                  {criteriaRows.map((entry) => (
                    <div className="manual-rule-criteria-item" key={`${rule.rule_id}-${entry.label}`}>
                      <span>{entry.label}</span>
                      <strong className={entry.mono ? "mono-value" : ""} title={entry.title || entry.value}>
                        {entry.value}
                      </strong>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
          </article>
        );
      })}
    </div>
  );
}

function StatusToast({ toast, onClose }) {
  if (!toast?.message) {
    return null;
  }

  return (
    <div className={`status-toast toast-${toast.kind || "success"}`} role="status" aria-live="polite">
      <div>
        <strong>{toast.kind === "error" ? "Error" : toast.kind === "info" ? "Info" : "Success"}</strong>
        <span>{toast.message}</span>
      </div>
      <button type="button" className="toast-close" onClick={onClose}>
        Close
      </button>
    </div>
  );
}

function formatDateTime(value) {
  if (!value) {
    return "Unavailable";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return date.toLocaleString([], {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatRelativeTime(value) {
  if (!value) {
    return "No recent activity";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  const deltaSeconds = Math.round((date.getTime() - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const units = [
    ["day", 86400],
    ["hour", 3600],
    ["minute", 60],
  ];
  for (const [unit, seconds] of units) {
    if (Math.abs(deltaSeconds) >= seconds || unit === "minute") {
      return formatter.format(Math.round(deltaSeconds / seconds), unit);
    }
  }
  return "just now";
}

function NotificationCenter({ items, counts, activeFilter, onFilterChange, onRefresh, loading, onViewRequest }) {
  const byCategory = counts?.by_category || {};
  const filterOptions = [
    { key: "all", label: "All", count: counts?.total ?? items?.length ?? 0 },
    { key: "command", label: "Commands", count: byCategory.command || 0 },
    { key: "threat", label: "Threats", count: byCategory.threat || 0 },
    { key: "session", label: "Session", count: byCategory.session || 0 },
    { key: "model", label: "Model", count: byCategory.model || 0 },
    { key: "system", label: "System", count: byCategory.system || 0 },
  ].filter((option) => option.key === "all" || option.count > 0);

  const filteredItems =
    activeFilter === "all" ? items || [] : (items || []).filter((item) => (item.category || "system") === activeFilter);

  return (
    <div className="notification-center">
      <div className="notification-toolbar">
        <div className="notification-filters">
          {filterOptions.map((option) => (
            <button
              type="button"
              key={option.key}
              className={`notification-filter ${activeFilter === option.key ? "active" : ""}`}
              onClick={() => onFilterChange(option.key)}
            >
              <span>{option.label}</span>
              <strong>{option.count}</strong>
            </button>
          ))}
        </div>
        <button type="button" className="ghost-button" onClick={onRefresh} disabled={loading}>
          {loading ? "Syncing..." : "Sync now"}
        </button>
      </div>

      {!filteredItems.length ? (
        <div className="empty-state small">No operational notifications match the selected filter right now.</div>
      ) : (
        <div className="notification-list">
          {filteredItems.map((item) => (
            <article className={`notification-card tone-${item.kind || "info"}`} key={item.id}>
              <div className="notification-copy">
                <div>
                  <div className="notification-tags">
                    <span className="notification-kind">{item.kind || "info"}</span>
                    <span className="notification-category">{item.category || "system"}</span>
                    <span className="notification-source">{item.source || "runtime"}</span>
                  </div>
                  <h3>{item.title}</h3>
                </div>
                <div className="notification-time">
                  <time>{formatDateTime(item.timestamp)}</time>
                  <small>{formatRelativeTime(item.timestamp)}</small>
                </div>
              </div>
              <p>{item.message}</p>
              {item.request_id ? (
                <button type="button" className="ghost-button" onClick={() => onViewRequest(item.request_id)}>
                  Open related request
                </button>
              ) : null}
            </article>
          ))}
        </div>
      )}
    </div>
  );
}

function RuntimeInfoPanel({ systemInfo = {}, sessionInfo = {} }) {
  const facts = [
    { label: "Gateway origin", value: systemInfo.current_origin || window.location.origin, hint: "Current dashboard origin" },
    { label: "Transparent mode", value: systemInfo.transparent_proxy ? "Enabled" : "Disabled", hint: "Root path inspection and forwarding" },
    { label: "Backend", value: systemInfo.backend_base_url || "Unavailable", hint: "Protected upstream target" },
    { label: "Database", value: systemInfo.database_backend || "unknown", hint: "Persistence engine" },
    { label: "Rate limiter", value: systemInfo.rate_limit_backend || "unknown", hint: "Runtime quota backend" },
    {
      label: "Model",
      value: systemInfo.active_model?.model_version || "heuristic-fallback",
      hint: systemInfo.active_model?.model_type || "heuristic",
    },
    { label: "Login IP", value: sessionInfo.ip_address || "unknown", hint: "Source recorded for this session" },
    { label: "User agent", value: sessionInfo.user_agent || "unknown", hint: "Last authenticated client fingerprint" },
  ];

  return (
    <div className="runtime-grid">
      {facts.map((fact) => (
        <div className="runtime-card" key={fact.label}>
          <span>{fact.label}</span>
          <strong>{fact.value}</strong>
          <small>{fact.hint}</small>
        </div>
      ))}
      <div className="runtime-card runtime-card-wide">
        <span>LAN endpoints</span>
        <div className="runtime-links">
          {(systemInfo.lan_urls || []).length ? (
            (systemInfo.lan_urls || []).map((item) => (
              <a key={item.origin} href={item.origin} target="_blank" rel="noreferrer">
                {item.origin}
              </a>
            ))
          ) : (
            <strong>{systemInfo.current_origin || window.location.origin}</strong>
          )}
        </div>
        <small>Use these addresses from other devices on the same local network.</small>
      </div>
    </div>
  );
}

function ModelVerificationPanel({ verification }) {
  if (!verification) {
    return <div className="empty-state small">No pattern-verification report is attached to the active model yet.</div>;
  }

  const familyResults = verification.family_results || [];
  const topFamilies = familyResults.slice(0, 6);
  return (
    <div className="model-verification">
      <div className="model-card">
        <div>
          <span className="model-label">Families verified</span>
          <strong>
            {verification.verified_families ?? 0}/{verification.supported_families ?? 0}
          </strong>
        </div>
        <div>
          <span className="model-label">Family pass rate</span>
          <strong>{Number((verification.family_pass_rate || 0) * 100).toFixed(1)}%</strong>
        </div>
        <div>
          <span className="model-label">Benign ML clear rate</span>
          <strong>{Number((verification.benign_ml_clear_rate || 0) * 100).toFixed(1)}%</strong>
        </div>
        <div>
          <span className="model-label">Last verified</span>
          <strong>{formatDateTime(verification.generated_at)}</strong>
        </div>
      </div>
      {topFamilies.length ? (
        <div className="model-verification-list">
          {topFamilies.map((item) => (
            <div className="model-verification-item" key={item.attack_type}>
              <div>
                <strong>{item.label || item.attack_type}</strong>
                <span>{item.description}</span>
              </div>
              <div>
                <strong>{Number((item.hybrid_detect_rate || 0) * 100).toFixed(0)}%</strong>
                <span>{item.verified ? "verified" : "needs tuning"}</span>
              </div>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function AttackSimulationPanel({ simulation, canRun }) {
  if (!simulation) {
    return (
      <div className="empty-state small">
        {canRun
          ? "Run the attack simulation suite to generate live traffic and validate threat-family counters."
          : "No attack simulation run has been recorded yet."}
      </div>
    );
  }

  const familyResults = (simulation.families || []).filter((item) => (item.sent || 0) > 0);
  const observed = simulation.observed_attack_types || [];
  const summary = simulation.summary || {};
  const controlTraffic = simulation.control_traffic || {};
  const supportedFamilies = summary.supported_attack_families || familyResults.length;
  const exercisedFamilies = summary.attack_families_exercised || summary.families_exercised || familyResults.length;

  return (
    <div className="simulation-suite">
      <div className="simulation-banner">
        <strong>Last {simulation.profile || "full"} run</strong>
        <span>
          {formatDateTime(simulation.generated_at)} | {exercisedFamilies}/{supportedFamilies} attack families |{" "}
          {summary.blocked || 0} blocked / {simulation.total_requests || 0} requests
        </span>
        <small>
          This simulation report is isolated from live operational counters. Benign control traffic is shown separately and does
          not inflate Top attack types.
        </small>
      </div>

      <div className="model-card">
        <div>
          <span className="model-label">Requests generated</span>
          <strong>{numberFormatter.format(simulation.total_requests || 0)}</strong>
        </div>
        <div>
          <span className="model-label">Attack requests</span>
          <strong>{numberFormatter.format(summary.attack_requests || 0)}</strong>
        </div>
        <div>
          <span className="model-label">Benign controls</span>
          <strong>{numberFormatter.format(summary.control_requests || controlTraffic.sent || 0)}</strong>
        </div>
        <div>
          <span className="model-label">Blocked</span>
          <strong>{numberFormatter.format(summary.blocked || 0)}</strong>
        </div>
        <div>
          <span className="model-label">Monitored</span>
          <strong>{numberFormatter.format(summary.monitored || 0)}</strong>
        </div>
        <div>
          <span className="model-label">Allowed</span>
          <strong>{numberFormatter.format(summary.allowed || 0)}</strong>
        </div>
      </div>

      {summary.control_requests || controlTraffic.sent ? (
        <div className="simulation-banner simulation-banner-subtle">
          <strong>{controlTraffic.label || "Benign Control Traffic"}</strong>
          <span>{controlTraffic.description}</span>
          <small>
            {numberFormatter.format(controlTraffic.allowed || 0)} allowed, {numberFormatter.format(controlTraffic.monitored || 0)}{" "}
            monitored, {numberFormatter.format(controlTraffic.blocked || 0)} blocked out of{" "}
            {numberFormatter.format(controlTraffic.sent || 0)} safe validation requests.
          </small>
        </div>
      ) : null}

      {observed.length ? (
        <>
          <div className="simulation-subhead">
            <strong>Observed simulation detections</strong>
            <span>Threat families the WAF actually flagged during the most recent isolated run.</span>
          </div>
          <DistributionList
            items={observed.slice(0, 6).map((item) => ({
              ...item,
              count: item.count || 0,
            }))}
            emptyLabel="No attack types were observed in the last simulation."
            tone="teal"
          />
        </>
      ) : null}
    </div>
  );
}

function RequestInspectorModal({
  open,
  requestItem,
  detailLoading,
  reviewNotes,
  blockScope,
  onBlockScopeChange,
  onNotesChange,
  onClose,
  onLabel,
  onBlock,
  onDelete,
  busyAction,
  isManuallyBlocked,
  isSourceBlacklisted,
  canReview,
  canDelete,
}) {
  if (!open) {
    return null;
  }

  const canViewInternals = canReview && requestItem?.can_view_internals !== false;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card" onClick={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <div>
            <span className="section-eyebrow">Request Inspector</span>
            <h3>{requestItem ? requestItem.path : "Loading request"}</h3>
            <p>
              {requestItem
                ? `${requestItem.method} from ${requestItem.remote_addr} | ${requestItem.decision_action}`
                : "Fetching request details from the backend."}
            </p>
          </div>
          <button type="button" className="ghost-button" onClick={onClose}>
            Close
          </button>
        </div>

        {detailLoading ? (
          <div className="empty-state">Loading request details...</div>
        ) : requestItem ? (
          <>
            <div className="detail-metrics">
              <div>
                <span>Risk</span>
                <strong>{requestItem.risk_score.toFixed(3)}</strong>
              </div>
              <div>
                <span>Status</span>
                <strong>{requestItem.decision_status_code}</strong>
              </div>
              <div>
                <span>Latency</span>
                <strong>{Math.round(requestItem.latency_ms)} ms</strong>
              </div>
              <div>
                <span>Match Block</span>
                <strong>{isManuallyBlocked ? "Active" : "Not blocked"}</strong>
              </div>
              <div>
                <span>IP Blacklist</span>
                <strong>{isSourceBlacklisted ? "Active" : "Not blocked"}</strong>
              </div>
            </div>

            {canReview ? (
              <label className="field compact">
                <span>Block scope</span>
                <select value={blockScope} onChange={(event) => onBlockScopeChange(event.target.value)}>
                  <option value="signature">Request signature</option>
                  <option value="path">Method + path</option>
                  <option value="session">Session</option>
                  <option value="ip">IP address</option>
                </select>
              </label>
            ) : null}

            <div className="detail-actions modal-actions">
              {canReview ? (
                <>
                  <button type="button" className="primary-button" disabled={busyAction === "malicious"} onClick={() => onLabel("malicious")}>
                    Mark malicious
                  </button>
                  <button type="button" className="secondary-button" disabled={busyAction === "benign"} onClick={() => onLabel("benign")}>
                    Mark benign
                  </button>
                  <button type="button" className="secondary-button" disabled={busyAction === "needs_review"} onClick={() => onLabel("needs_review")}>
                    Needs review
                  </button>
                  <button type="button" className="secondary-button danger" disabled={busyAction.startsWith("block-")} onClick={onBlock}>
                    {blockScope === "ip"
                      ? isSourceBlacklisted
                        ? "Remove IP blacklist"
                        : "Blacklist IP"
                      : isManuallyBlocked
                        ? "Remove match block"
                        : "Block match"}
                  </button>
                </>
              ) : (
                <div className="permission-note">Viewer role can inspect requests but cannot relabel or block them.</div>
              )}
              {canDelete ? (
                <button type="button" className="ghost-button" disabled={busyAction.startsWith("delete-")} onClick={onDelete}>
                  Delete request
                </button>
              ) : null}
            </div>

            <label className="field">
              <span>Analyst notes</span>
              <textarea
                rows="4"
                value={reviewNotes}
                disabled={!canReview}
                onChange={(event) => onNotesChange(event.target.value)}
                placeholder="Explain why this request should be retained, relabeled, or blocked."
              />
            </label>

            <div className="detail-copy-grid">
              <div className="meta-card">
                <span>URL</span>
                <strong>{requestItem.full_url}</strong>
              </div>
              <div className="meta-card">
                <span>User Agent</span>
                <strong>{requestItem.user_agent || "unknown"}</strong>
              </div>
              <div className="meta-card">
                <span>Session</span>
                <strong>{requestItem.session_id || "anonymous"}</strong>
              </div>
              <div className="meta-card">
                <span>Payload Preview</span>
                <strong>{requestItem.payload_preview || "No body preview"}</strong>
              </div>
            </div>

            <AdvancedDiagnosticsSection
              canViewInternals={canViewInternals}
              scoreBreakdown={requestItem.score_breakdown}
              ruleResult={requestItem.rule_result}
              features={requestItem.features}
              contextLabel="request"
            />
          </>
        ) : (
          <div className="empty-state">Request details are unavailable.</div>
        )}
      </div>
    </div>
  );
}

function RequestRow({ item, selected, onView, onBlock, onDelete, busyAction, canReview, canDelete }) {
  return (
    <tr className={selected ? "selected" : ""} onClick={() => onView(item.request_id)}>
      <td>
        <div className="request-id-cell">
          <strong>{item.request_id}</strong>
          <span>{item.method}</span>
        </div>
      </td>
      <td>
        <div className="request-path-cell">
          <strong>{item.path}</strong>
          <span>{item.remote_addr}</span>
          {item.manually_blocked ? <span className="mini-flag blocked">match blocked</span> : null}
          {item.source_blacklisted ? <span className="mini-flag blocked">ip blacklisted</span> : null}
        </div>
      </td>
      <td>
        <span className={`pill ${item.action}`}>{item.action}</span>
      </td>
      <td>{item.risk_score.toFixed(3)}</td>
      <td>{Math.round(item.latency_ms)} ms</td>
      <td>{item.label || "unlabeled"}</td>
      <td>{item.attack_types.join(", ") || "none"}</td>
      <td>
        <div className="inline-actions" onClick={(event) => event.stopPropagation()}>
          <button type="button" className="ghost-button" onClick={() => onView(item.request_id)}>
            {selected ? "Open" : "View"}
          </button>
          {canReview ? (
            <button
              type="button"
              className="ghost-button danger"
              disabled={busyAction === `block-${item.request_id}`}
              onClick={() => onBlock(item.request_id)}
            >
              {busyAction === `block-${item.request_id}`
                ? "Updating..."
                : item.manually_blocked
                  ? "Unblock Match"
                  : "Block Match"}
            </button>
          ) : null}
          {canDelete ? (
            <button
              type="button"
              className="ghost-button"
              disabled={busyAction === `delete-${item.request_id}`}
              onClick={() => onDelete(item.request_id)}
            >
              {busyAction === `delete-${item.request_id}` ? "Deleting..." : "Delete"}
            </button>
          ) : null}
        </div>
      </td>
    </tr>
  );
}

export default function App() {
  const [session, setSession] = useState(() => readStoredSession());
  const [authLoading, setAuthLoading] = useState(true);
  const [authBusy, setAuthBusy] = useState(false);
  const [loginForm, setLoginForm] = useState({ username: "admin", password: "Admin123!" });
  const [windowSeconds, setWindowSeconds] = useState(86400);
  const [summary, setSummary] = useState(emptySummary);
  const [notificationsFeed, setNotificationsFeed] = useState([]);
  const [notificationCounts, setNotificationCounts] = useState({ total: 0, by_kind: {}, by_category: {} });
  const [notificationFilter, setNotificationFilter] = useState("all");
  const [timeline, setTimeline] = useState([]);
  const [model, setModel] = useState(null);
  const [blacklist, setBlacklist] = useState([]);
  const [manualRules, setManualRules] = useState([]);
  const [requests, setRequests] = useState(emptyRequests);
  const [selectedRequestId, setSelectedRequestId] = useState("");
  const [selectedRequest, setSelectedRequest] = useState(null);
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [reviewNotes, setReviewNotes] = useState("");
  const [blockScope, setBlockScope] = useState("signature");
  const [dashboardLoading, setDashboardLoading] = useState(true);
  const [notificationsLoading, setNotificationsLoading] = useState(true);
  const [requestsLoading, setRequestsLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [busyAction, setBusyAction] = useState("");
  const [flash, setFlash] = useState("");
  const [error, setError] = useState("");
  const [blacklistForm, setBlacklistForm] = useState({ ip_address: "", reason: "", ttl_seconds: 900 });
  const [settingsData, setSettingsData] = useState({ settings: {}, editable_fields: [] });
  const [settingsDraft, setSettingsDraft] = useState({});
  const [securityScope, setSecurityScope] = useState(null);
  const [securityPolicyDraft, setSecurityPolicyDraft] = useState({
    name: "",
    path_pattern: "",
    methods: "GET,POST",
    sensitivity: "protected",
    requests_per_min: 12,
    bucket_scope: "ip_endpoint",
    priority: 60,
    ddos_monitor_hits: 4,
    ddos_block_hits: 8,
    connection_monitor_active: 3,
    connection_block_active: 6,
    connection_monitor_per_ip: 3,
    connection_block_per_ip: 6,
    connection_burst_monitor: 4,
    connection_burst_block: 8,
    connection_new_per_second_monitor: 2,
    connection_new_per_second_block: 4,
    connection_stale_monitor: 2,
    connection_stale_block: 4,
    connection_sessions_monitor: 2,
    connection_sessions_block: 4,
    block_threshold: "",
    monitor_threshold: "",
    description: "",
  });
  const [adaptivity, setAdaptivity] = useState(null);
  const [autoTuning, setAutoTuning] = useState(null);
  const [feedbackLoop, setFeedbackLoop] = useState(null);
  const [mlLogTraining, setMlLogTraining] = useState(null);
  const [dynamicThresholds, setDynamicThresholds] = useState(null);
  const [adaptiveRateLimit, setAdaptiveRateLimit] = useState(null);
  const [users, setUsers] = useState([]);
  const [userDrafts, setUserDrafts] = useState({});
  const [createUserForm, setCreateUserForm] = useState({
    username: "",
    display_name: "",
    role: "viewer",
    password: "",
  });
  const [auditEvents, setAuditEvents] = useState([]);
  const [filters, setFilters] = useState({
    search: "",
    action: "",
    label: "",
    attack_type: "",
    remote_addr: "",
    page: 1,
    page_size: 12,
  });

  const deferredSearch = useDeferredValue(filters.search);
  const blacklistedIpSet = new Set((blacklist || []).map((item) => item.ip_address));
  const userRole = session?.user?.role || "";
  const canReview = roleAllows(userRole, "analyst");
  const canAdmin = roleAllows(userRole, "admin");
  const canViewInternals = canReview && selectedRequest?.can_view_internals !== false;

  const topEvents = summary.events?.slice(0, 5) || [];

  useEffect(() => {
    restoreSession();
  }, []);

  useEffect(() => {
    if (!flash) {
      return undefined;
    }
    const timer = window.setTimeout(() => setFlash(""), 3200);
    return () => window.clearTimeout(timer);
  }, [flash]);

  useEffect(() => {
    if (!error) {
      return undefined;
    }
    const timer = window.setTimeout(() => setError(""), 4200);
    return () => window.clearTimeout(timer);
  }, [error]);

  useEffect(() => {
    if (!session) {
      return;
    }
    loadDashboard();
  }, [session?.user?.role, windowSeconds]);

  useEffect(() => {
    if (!session) {
      setNotificationsFeed([]);
      setNotificationCounts({ total: 0, by_kind: {}, by_category: {} });
      return;
    }
    loadNotifications();
  }, [session?.user?.role, windowSeconds]);

  useEffect(() => {
    if (!session) {
      return undefined;
    }
    const intervalId = window.setInterval(() => {
      loadNotifications({ silent: true });
    }, 5000);
    return () => window.clearInterval(intervalId);
  }, [session?.user?.role, windowSeconds]);

  useEffect(() => {
    if (!session) {
      return undefined;
    }
    const intervalId = window.setInterval(() => {
      loadDashboard({ silent: true });
    }, 15000);
    return () => window.clearInterval(intervalId);
  }, [session?.user?.role, windowSeconds]);

  useEffect(() => {
    if (!session) {
      return;
    }
    loadRequests();
  }, [
    session?.user?.role,
    deferredSearch,
    filters.action,
    filters.label,
    filters.attack_type,
    filters.remote_addr,
    filters.page,
    filters.page_size,
  ]);

  useEffect(() => {
    if (!session) {
      return;
    }
    if (!selectedRequestId) {
      setSelectedRequest(null);
      return;
    }
    loadRequestDetail(selectedRequestId);
  }, [session?.user?.role, selectedRequestId]);

  useEffect(() => {
    if (!session || !canReview) {
      setSettingsData({ settings: {}, editable_fields: [] });
      setSettingsDraft({});
      setSecurityScope(null);
      setAdaptivity(null);
      setAutoTuning(null);
      setFeedbackLoop(null);
      setMlLogTraining(null);
      setDynamicThresholds(null);
      setAdaptiveRateLimit(null);
      return;
    }
    loadSettings();
  }, [session?.user?.role]);

  useEffect(() => {
    if (!session || !canAdmin) {
      setUsers([]);
      setUserDrafts({});
      setAuditEvents([]);
      return;
    }
    loadUsers();
    loadAudit();
  }, [session?.user?.role]);

  function handleApiError(apiError, fallbackMessage = "") {
    if (apiError?.status === 401) {
      clearStoredSession();
      setSession(null);
      setNotificationsFeed([]);
      setNotificationCounts({ total: 0, by_kind: {}, by_category: {} });
      setSelectedRequestId("");
      setSelectedRequest(null);
      setInspectorOpen(false);
      setError("Your session expired. Please sign in again.");
      return true;
    }
    setError(apiError?.message || fallbackMessage || "Request failed");
    return false;
  }

  function syncSessionFromAuth(authPayload) {
    if (!authPayload?.user) {
      return;
    }
    setSession((current) => {
      const nextSession = {
        ...(current || {}),
        token: current?.token || "",
        user: authPayload.user,
        created_at: authPayload.created_at,
        last_seen_at: authPayload.last_seen_at,
        expires_at: authPayload.expires_at,
        ip_address: authPayload.ip_address || "",
        user_agent: authPayload.user_agent || "",
        capabilities: authPayload.capabilities || current?.capabilities || {},
      };
      writeStoredSession(nextSession);
      return nextSession;
    });
  }

  async function restoreSession() {
    setAuthLoading(true);
    try {
      const payload = await apiFetch("/api/auth/me");
      const stored = readStoredSession();
      const nextSession = {
        token: stored?.token || "",
        user: payload.user,
        created_at: payload.created_at,
        last_seen_at: payload.last_seen_at,
        expires_at: payload.expires_at,
        ip_address: payload.ip_address || "",
        user_agent: payload.user_agent || "",
        capabilities: payload.capabilities || {},
      };
      writeStoredSession(nextSession);
      setSession(nextSession);
    } catch (apiError) {
      clearStoredSession();
      setSession(null);
      if (apiError?.status !== 401) {
        setError(apiError.message);
      }
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleLogin(event) {
    event.preventDefault();
    setAuthBusy(true);
    setError("");
    try {
      const payload = await apiFetch("/api/auth/login", {
        method: "POST",
        skipAuth: true,
        body: JSON.stringify(loginForm),
      });
      const nextSession = {
        token: payload.token || "",
        user: payload.user,
        created_at: payload.created_at,
        last_seen_at: payload.last_seen_at,
        expires_at: payload.expires_at,
        ip_address: payload.ip_address || "",
        user_agent: payload.user_agent || "",
        capabilities: payload.capabilities || {},
      };
      writeStoredSession(nextSession);
      setSession(nextSession);
      setFlash(`Signed in as ${payload.user.display_name || payload.user.username}`);
    } catch (apiError) {
      handleApiError(apiError, "Login failed");
    } finally {
      setAuthBusy(false);
      setAuthLoading(false);
    }
  }

  async function handleLogout() {
    setBusyAction("logout");
    try {
      await apiFetch("/api/auth/logout", { method: "POST" });
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      clearStoredSession();
      setSession(null);
      setBusyAction("");
      setSummary(emptySummary);
      setNotificationsFeed([]);
      setNotificationCounts({ total: 0, by_kind: {}, by_category: {} });
      setRequests(emptyRequests);
      setSelectedRequestId("");
      setSelectedRequest(null);
      setInspectorOpen(false);
    }
  }

  async function loadDashboard({ silent = false } = {}) {
    if (!session) {
      return;
    }
    if (!silent) {
      setDashboardLoading(true);
    }
    setError("");
    try {
      const [summaryPayload, timelinePayload, modelPayload, blacklistPayload, manualRulesPayload] = await Promise.all([
        apiFetch(`/api/dashboard/summary?window_seconds=${windowSeconds}&limit=8`),
        apiFetch(`/api/dashboard/timeline?window_seconds=${windowSeconds}&bucket_seconds=3600`),
        apiFetch("/api/model"),
        apiFetch("/api/blacklist"),
        apiFetch("/api/manual-blocks"),
      ]);
      startTransition(() => {
        setSummary(summaryPayload);
        setTimeline(timelinePayload.items || []);
        setModel(modelPayload);
        setBlacklist(blacklistPayload.items || []);
        setManualRules(manualRulesPayload.items || []);
        if (!notificationsFeed.length && (summaryPayload.notifications || []).length) {
          setNotificationsFeed(summaryPayload.notifications || []);
          setNotificationCounts(summaryPayload.notification_counts || { total: 0, by_kind: {}, by_category: {} });
        }
      });
      syncSessionFromAuth(summaryPayload.auth);
    } catch (loadError) {
      handleApiError(loadError);
    } finally {
      if (!silent) {
        setDashboardLoading(false);
      }
    }
  }

  async function loadSettings() {
    try {
      const [payload, securityScopePayload, adaptivityPayload, autoTuningPayload, feedbackLoopPayload, mlLogTrainingPayload, dynamicThresholdPayload, adaptiveRatePayload] = await Promise.all([
        apiFetch("/api/admin/settings"),
        apiFetch("/api/admin/security-scope"),
        apiFetch("/api/admin/settings/adaptivity"),
        apiFetch("/api/admin/settings/auto-tune"),
        apiFetch("/api/admin/settings/feedback-loop"),
        apiFetch("/api/admin/settings/ml-log-training"),
        apiFetch("/api/admin/settings/dynamic-thresholds"),
        apiFetch("/api/admin/settings/adaptive-rate-limit"),
      ]);
      startTransition(() => {
        setSettingsData(payload);
        setSettingsDraft(payload.settings || {});
        setSecurityScope(securityScopePayload);
        setAdaptivity(adaptivityPayload);
        setAutoTuning(autoTuningPayload);
        setFeedbackLoop(feedbackLoopPayload);
        setMlLogTraining(mlLogTrainingPayload);
        setDynamicThresholds(dynamicThresholdPayload);
        setAdaptiveRateLimit(adaptiveRatePayload);
      });
    } catch (apiError) {
      handleApiError(apiError);
    }
  }

  async function loadFeedbackLoop() {
    if (!session || !canReview) {
      return;
    }
    setBusyAction("feedback-loop-refresh");
    try {
      const payload = await apiFetch("/api/admin/settings/feedback-loop");
      startTransition(() => {
        setFeedbackLoop(payload);
      });
      setFlash("Feedback-loop analysis refreshed");
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  async function loadMlLogTraining() {
    if (!session || !canReview) {
      return;
    }
    setBusyAction("ml-log-training-refresh");
    try {
      const payload = await apiFetch("/api/admin/settings/ml-log-training");
      startTransition(() => {
        setMlLogTraining(payload);
      });
      setFlash("ML log-training analysis refreshed");
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  async function loadSecurityScope() {
    if (!session || !canReview) {
      return;
    }
    setBusyAction("security-scope-refresh");
    try {
      const payload = await apiFetch("/api/admin/security-scope");
      startTransition(() => {
        setSecurityScope(payload);
      });
      setFlash("Security scope refreshed");
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  async function loadAdaptivity() {
    if (!session || !canReview) {
      return;
    }
    setBusyAction("adaptivity-refresh");
    try {
      const payload = await apiFetch("/api/admin/settings/adaptivity");
      startTransition(() => {
        setAdaptivity(payload);
      });
      setFlash("Adaptivity analysis refreshed");
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  async function loadDynamicThresholds() {
    if (!session || !canReview) {
      return;
    }
    setBusyAction("dynamic-thresholds-refresh");
    try {
      const payload = await apiFetch("/api/admin/settings/dynamic-thresholds");
      startTransition(() => {
        setDynamicThresholds(payload);
      });
      setFlash("Dynamic-threshold analysis refreshed");
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  async function loadAdaptiveRateLimit() {
    if (!session || !canReview) {
      return;
    }
    setBusyAction("adaptive-rate-refresh");
    try {
      const payload = await apiFetch("/api/admin/settings/adaptive-rate-limit");
      startTransition(() => {
        setAdaptiveRateLimit(payload);
      });
      setFlash("Adaptive rate-limit analysis refreshed");
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  async function loadAutoTuning() {
    if (!session || !canReview) {
      return;
    }
    setBusyAction("auto-tune-refresh");
    try {
      const payload = await apiFetch("/api/admin/settings/auto-tune");
      startTransition(() => {
        setAutoTuning(payload);
      });
      setFlash("Auto-tuning analysis refreshed");
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  async function handleApplyAutoTuning() {
    if (!canAdmin) {
      return;
    }
    setBusyAction("auto-tune-apply");
    try {
      const payload = await apiFetch("/api/admin/settings/auto-tune", {
        method: "POST",
        body: JSON.stringify({ action: "apply", trigger: "dashboard_manual" }),
      });
      startTransition(() => {
        if (payload.report) {
          setAutoTuning(payload.report);
        }
        if (payload.settings) {
          setSettingsData((current) => ({ ...current, settings: payload.settings }));
          setSettingsDraft(payload.settings || {});
        }
      });
      setFlash(payload.message || "Auto-tuning applied");
      await Promise.all([
        loadDashboard({ silent: true }),
        loadNotifications({ silent: true }),
        canAdmin ? loadAudit() : Promise.resolve(),
      ]);
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  async function handleApplyAdaptivity() {
    if (!canAdmin) {
      return;
    }
    setBusyAction("adaptivity-apply");
    try {
      const payload = await apiFetch("/api/admin/settings/adaptivity", {
        method: "POST",
        body: JSON.stringify({ action: "apply", trigger: "dashboard_manual" }),
      });
      startTransition(() => {
        if (payload.report) {
          setAdaptivity(payload.report);
        }
        if (payload.settings) {
          setSettingsData((current) => ({ ...current, settings: payload.settings }));
          setSettingsDraft(payload.settings || {});
        }
      });
      setFlash(payload.message || "Adaptivity applied");
      await Promise.all([loadDashboard({ silent: true }), loadNotifications({ silent: true }), loadAudit(), loadSettings()]);
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  function updateSecurityPolicyDraft(key, value) {
    setSecurityPolicyDraft((current) => ({
      ...current,
      [key]: value,
    }));
  }

  async function handleCreateSecurityPolicy() {
    if (!canAdmin) {
      return;
    }
    setBusyAction("security-policy-create");
    try {
      const payload = await apiFetch("/api/admin/security-scope/policies", {
        method: "POST",
        body: JSON.stringify(securityPolicyDraft),
      });
      setSecurityPolicyDraft({
        name: "",
        path_pattern: "",
        methods: "GET,POST",
        sensitivity: "protected",
        requests_per_min: 12,
        bucket_scope: "ip_endpoint",
        priority: 60,
        ddos_monitor_hits: 4,
        ddos_block_hits: 8,
        connection_monitor_active: 3,
        connection_block_active: 6,
        connection_monitor_per_ip: 3,
        connection_block_per_ip: 6,
        connection_burst_monitor: 4,
        connection_burst_block: 8,
        connection_new_per_second_monitor: 2,
        connection_new_per_second_block: 4,
        connection_stale_monitor: 2,
        connection_stale_block: 4,
        connection_sessions_monitor: 2,
        connection_sessions_block: 4,
        block_threshold: "",
        monitor_threshold: "",
        description: "",
      });
      startTransition(() => {
        if (payload.report) {
          setSecurityScope(payload.report);
        }
      });
      setFlash(payload.message || "Endpoint policy saved");
      await Promise.all([loadDashboard({ silent: true }), loadNotifications({ silent: true }), loadAudit(), loadSettings()]);
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  async function handleDeleteSecurityPolicy(policyId) {
    if (!canAdmin || !policyId) {
      return;
    }
    setBusyAction(`security-policy-delete-${policyId}`);
    try {
      const payload = await apiFetch(`/api/admin/security-scope/policies/${policyId}`, {
        method: "DELETE",
      });
      setFlash(payload.message || "Endpoint policy deleted");
      await Promise.all([loadDashboard({ silent: true }), loadNotifications({ silent: true }), loadAudit(), loadSettings()]);
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  async function handleApplyFeedbackLoop() {
    if (!canAdmin) {
      return;
    }
    setBusyAction("feedback-loop-apply");
    try {
      const payload = await apiFetch("/api/admin/settings/feedback-loop", {
        method: "POST",
        body: JSON.stringify({ action: "apply", trigger: "dashboard_manual" }),
      });
      startTransition(() => {
        if (payload.report) {
          setFeedbackLoop(payload.report);
        }
        if (payload.settings) {
          setSettingsData((current) => ({ ...current, settings: payload.settings }));
          setSettingsDraft(payload.settings || {});
        }
      });
      setFlash(payload.message || "Feedback loop applied");
      await Promise.all([loadDashboard({ silent: true }), loadNotifications({ silent: true }), loadAudit(), loadSettings()]);
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  async function handleApplyMlLogTraining() {
    if (!canAdmin) {
      return;
    }
    setBusyAction("ml-log-training-apply");
    try {
      const payload = await apiFetch("/api/admin/settings/ml-log-training", {
        method: "POST",
        body: JSON.stringify({ action: "apply", trigger: "dashboard_manual" }),
      });
      startTransition(() => {
        if (payload.report) {
          setMlLogTraining(payload.report);
        }
      });
      setFlash(payload.message || "ML log training completed");
      await Promise.all([loadDashboard({ silent: true }), loadNotifications({ silent: true }), loadAudit(), loadSettings()]);
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  async function loadUsers() {
    try {
      const payload = await apiFetch("/api/admin/users");
      startTransition(() => {
        setUsers(payload.items || []);
        const nextDrafts = {};
        (payload.items || []).forEach((user) => {
          nextDrafts[user.user_id] = {
            role: user.role,
            is_active: user.is_active,
            password: "",
          };
        });
        setUserDrafts(nextDrafts);
      });
    } catch (apiError) {
      handleApiError(apiError);
    }
  }

  async function loadAudit() {
    try {
      const payload = await apiFetch("/api/admin/audit?limit=25");
      startTransition(() => {
        setAuditEvents(payload.items || []);
      });
    } catch (apiError) {
      handleApiError(apiError);
    }
  }

  async function loadNotifications({ silent = false } = {}) {
    if (!session) {
      return;
    }
    if (!silent) {
      setNotificationsLoading(true);
    }
    try {
      const payload = await apiFetch(`/api/dashboard/notifications?window_seconds=${windowSeconds}&limit=12`);
      startTransition(() => {
        setNotificationsFeed(payload.notifications || []);
        setNotificationCounts(payload.counts || { total: 0, by_kind: {}, by_category: {} });
      });
      syncSessionFromAuth(payload.auth);
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      if (!silent) {
        setNotificationsLoading(false);
      }
    }
  }

  async function handleRunAttackSimulation(profile = "full") {
    if (!canReview) {
      return;
    }
    setBusyAction(`simulate-${profile}`);
    setError("");
    try {
      const payload = await apiFetch("/api/simulations/attack-suite", {
        method: "POST",
        body: JSON.stringify({ profile }),
      });
      setFlash(
        `Attack simulation completed: ${payload.summary?.blocked || 0} blocked across ${payload.summary?.families_exercised || 0} exercised families`
      );
      await Promise.all([
        loadDashboard({ silent: true }),
        loadNotifications({ silent: true }),
        loadRequests(),
        canAdmin ? loadAudit() : Promise.resolve(),
      ]);
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  async function loadRequests() {
    if (!session) {
      return;
    }
    setRequestsLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({
        page: String(filters.page),
        page_size: String(filters.page_size),
      });
      if (deferredSearch) params.set("search", deferredSearch);
      if (filters.action) params.set("action", filters.action);
      if (filters.label) params.set("label", filters.label);
      if (filters.attack_type) params.set("attack_type", filters.attack_type);
      if (filters.remote_addr) params.set("remote_addr", filters.remote_addr);

      const payload = await apiFetch(`/api/requests?${params.toString()}`);
      startTransition(() => {
        setRequests(payload);
        if (payload.items?.length) {
          const stillExists = payload.items.some((item) => item.request_id === selectedRequestId);
          if (!selectedRequestId || !stillExists) {
            setSelectedRequestId(payload.items[0].request_id);
          }
        } else {
          setSelectedRequestId("");
        }
      });
    } catch (loadError) {
      handleApiError(loadError);
    } finally {
      setRequestsLoading(false);
    }
  }

  async function loadRequestDetail(requestId) {
    setDetailLoading(true);
    setError("");
    try {
      const payload = await apiFetch(`/api/requests/${requestId}`);
      startTransition(() => {
        setSelectedRequest(payload);
        setReviewNotes(payload.notes || "");
      });
    } catch (loadError) {
      handleApiError(loadError);
    } finally {
      setDetailLoading(false);
    }
  }

  function handleViewRequest(requestId) {
    setSelectedRequestId(requestId);
    setInspectorOpen(true);
  }

  function getRequestListItem(requestId) {
    return requests.items.find((item) => item.request_id === requestId) || null;
  }

  function getManualRuleForRequest(requestId) {
    if (selectedRequest?.request_id === requestId && selectedRequest?.manual_block_rule) {
      return selectedRequest.manual_block_rule;
    }
    return getRequestListItem(requestId)?.manual_block_rule || null;
  }

  function getSourceIpForRequest(requestId) {
    if (selectedRequest?.request_id === requestId && selectedRequest?.remote_addr) {
      return selectedRequest.remote_addr;
    }
    return getRequestListItem(requestId)?.remote_addr || "";
  }

  function updateFilter(name, value) {
    startTransition(() => {
      setFilters((current) => ({
        ...current,
        [name]: value,
        page: name === "page" ? value : 1,
      }));
    });
  }

  async function handleLabel(label) {
    if (!selectedRequestId || !canReview) {
      return;
    }
    setBusyAction(label);
    try {
      await apiFetch(`/api/requests/${selectedRequestId}/label`, {
        method: "POST",
        body: JSON.stringify({ label, notes: reviewNotes }),
      });
      setFlash(`Request labeled as ${label}`);
      await Promise.all([
        loadRequests(),
        loadRequestDetail(selectedRequestId),
        loadDashboard({ silent: true }),
        loadNotifications({ silent: true }),
        canAdmin ? loadAudit() : Promise.resolve(),
      ]);
    } catch (actionError) {
      handleApiError(actionError);
    } finally {
      setBusyAction("");
    }
  }

  async function handleToggleSourceBlock(requestId = selectedRequestId, scopeOverride = null) {
    if (!requestId || !canReview) {
      return;
    }
    const effectiveScope = scopeOverride || blockScope;
    const sourceIp = getSourceIpForRequest(requestId);
    const matchedRule = getManualRuleForRequest(requestId);
    if (!sourceIp) {
      setError("Unable to determine the source IP for this request.");
      return;
    }

    setBusyAction(`block-${requestId}`);
    try {
      if (effectiveScope === "ip") {
        if (blacklistedIpSet.has(sourceIp)) {
          await apiFetch(`/api/blacklist/${encodeURIComponent(sourceIp)}`, { method: "DELETE" });
          setFlash(`Source IP ${sourceIp} removed from blacklist`);
        } else {
          await apiFetch(`/api/requests/${requestId}/blacklist`, {
            method: "POST",
            body: JSON.stringify({
              scope: "ip",
              reason: "Blocked from React command center by IP",
              ttl_seconds: 900,
            }),
          });
          setFlash(`Source IP ${sourceIp} added to blacklist`);
        }
      } else if (matchedRule?.rule_id) {
        await apiFetch(`/api/manual-blocks/${matchedRule.rule_id}`, { method: "DELETE" });
        setFlash(`Manual ${matchedRule.scope_type} block removed`);
      } else {
        await apiFetch(`/api/requests/${requestId}/blacklist`, {
          method: "POST",
          body: JSON.stringify({
            scope: effectiveScope,
            reason: `Blocked from React command center (${effectiveScope})`,
            ttl_seconds: 900,
          }),
        });
        setFlash(`Manual ${effectiveScope} block created for the selected request`);
      }
      await Promise.all([
        loadDashboard({ silent: true }),
        loadNotifications({ silent: true }),
        loadRequests(),
        canAdmin ? loadAudit() : Promise.resolve(),
      ]);
      if (requestId === selectedRequestId) {
        await loadRequestDetail(requestId);
        setInspectorOpen(true);
      }
    } catch (actionError) {
      handleApiError(actionError);
    } finally {
      setBusyAction("");
    }
  }

  async function handleDeleteRequest(requestId = selectedRequestId) {
    if (!requestId || !canAdmin) {
      return;
    }
    const confirmed = window.confirm("Delete this request record from the audit log?");
    if (!confirmed) {
      return;
    }

    setBusyAction(`delete-${requestId}`);
    try {
      await apiFetch(`/api/requests/${requestId}`, { method: "DELETE" });
      setFlash("Request deleted");
      if (requestId === selectedRequestId) {
        setSelectedRequestId("");
        setSelectedRequest(null);
        setInspectorOpen(false);
      }
      await Promise.all([loadRequests(), loadDashboard({ silent: true }), loadNotifications({ silent: true }), loadAudit()]);
    } catch (actionError) {
      handleApiError(actionError);
    } finally {
      setBusyAction("");
    }
  }

  async function handleBlacklistSubmit(event) {
    event.preventDefault();
    if (!canReview) {
      return;
    }
    setBusyAction("blacklist-form");
    try {
      await apiFetch("/api/blacklist", {
        method: "POST",
        body: JSON.stringify(blacklistForm),
      });
      setBlacklistForm({ ip_address: "", reason: "", ttl_seconds: 900 });
      setFlash("Blacklist entry created");
      await Promise.all([loadDashboard({ silent: true }), loadNotifications({ silent: true }), canAdmin ? loadAudit() : Promise.resolve()]);
    } catch (actionError) {
      handleApiError(actionError);
    } finally {
      setBusyAction("");
    }
  }

  async function handleBlacklistRemove(ipAddress) {
    if (!canReview) {
      return;
    }
    setBusyAction(`remove-${ipAddress}`);
    try {
      await apiFetch(`/api/blacklist/${encodeURIComponent(ipAddress)}`, { method: "DELETE" });
      setFlash("Blacklist entry removed");
      await Promise.all([loadDashboard({ silent: true }), loadNotifications({ silent: true }), canAdmin ? loadAudit() : Promise.resolve()]);
    } catch (actionError) {
      handleApiError(actionError);
    } finally {
      setBusyAction("");
    }
  }

  async function handleManualRuleRemove(ruleId) {
    if (!canReview) {
      return;
    }
    setBusyAction(`manual-rule-${ruleId}`);
    try {
      await apiFetch(`/api/manual-blocks/${ruleId}`, { method: "DELETE" });
      setFlash("Targeted block rule removed");
      await Promise.all([
        loadDashboard({ silent: true }),
        loadNotifications({ silent: true }),
        loadRequests(),
        canAdmin ? loadAudit() : Promise.resolve(),
      ]);
      if (selectedRequestId) {
        await loadRequestDetail(selectedRequestId);
      }
    } catch (actionError) {
      handleApiError(actionError);
    } finally {
      setBusyAction("");
    }
  }

  function updateSettingsDraft(key, value) {
    setSettingsDraft((current) => ({
      ...current,
      [key]: value,
    }));
  }

  async function handleSettingsSave() {
    if (!canAdmin) {
      return;
    }
    setBusyAction("save-settings");
    try {
      const payload = await apiFetch("/api/admin/settings", {
        method: "PATCH",
        body: JSON.stringify({ settings: settingsDraft }),
      });
      setSettingsData(payload);
      setSettingsDraft(payload.settings || {});
      setFlash("Runtime settings updated");
      await Promise.all([loadDashboard({ silent: true }), loadNotifications({ silent: true }), loadAudit(), loadSettings()]);
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  function updateCreateUserForm(key, value) {
    setCreateUserForm((current) => ({
      ...current,
      [key]: value,
    }));
  }

  async function handleCreateUser() {
    if (!canAdmin) {
      return;
    }
    setBusyAction("create-user");
    try {
      await apiFetch("/api/admin/users", {
        method: "POST",
        body: JSON.stringify(createUserForm),
      });
      setCreateUserForm({ username: "", display_name: "", role: "viewer", password: "" });
      setFlash("User saved");
      await Promise.all([loadUsers(), loadAudit(), loadNotifications({ silent: true })]);
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  function updateUserDraft(userId, key, value) {
    setUserDrafts((current) => ({
      ...current,
      [userId]: {
        ...(current[userId] || {}),
        [key]: value,
      },
    }));
  }

  async function handleSaveUser(userId) {
    if (!canAdmin) {
      return;
    }
    setBusyAction(`save-user-${userId}`);
    try {
      await apiFetch(`/api/admin/users/${userId}`, {
        method: "PATCH",
        body: JSON.stringify(userDrafts[userId] || {}),
      });
      setFlash("User updated");
      await Promise.all([loadUsers(), loadAudit(), loadNotifications({ silent: true })]);
    } catch (apiError) {
      handleApiError(apiError);
    } finally {
      setBusyAction("");
    }
  }

  const pageSummary = `${requests.pagination.page} / ${requests.pagination.pages}`;
  const selectedRequestBlocked = Boolean(selectedRequest?.manual_block_rule);
  const selectedSourceBlacklisted = Boolean(selectedRequest?.source_blacklisted);
  const dashboardAuth = summary.auth?.user ? summary.auth : session;
  const systemInfo = summary.system || {};
  const notificationItems = notificationsFeed.length ? notificationsFeed : summary.notifications || [];
  const simulation = summary.simulation || null;
  const toast = error
    ? { kind: "error", message: error }
    : flash
      ? { kind: "success", message: flash }
      : null;

  if (!session) {
    return (
      <>
        <StatusToast toast={toast} onClose={() => setError("")} />
        <LoginScreen
          form={loginForm}
          onChange={(key, value) => setLoginForm((current) => ({ ...current, [key]: value }))}
          onSubmit={handleLogin}
          busy={authBusy}
          authLoading={authLoading}
          error={error}
        />
      </>
    );
  }

  return (
    <div className="shell">
      <div className="ambient ambient-a" />
      <div className="ambient ambient-b" />

      <header className="hero-panel">
        <div className="hero-copy">
          <span className="hero-kicker">AI-Based Web Application Firewall</span>
          <h1>Intelligent protection, live threat analysis, and administrative control for modern web applications.</h1>
          <p>
            This project is an AI-based Web Application Firewall designed to inspect incoming HTTP requests in real time,
            combine rule-based defense with anomaly-aware scoring, support blocking and review workflows, and provide a
            clear monitoring dashboard for detected threats, attack types, and offending sources.
          </p>
          <div className="session-strip">
            <div className="session-card">
              <span>Signed in as</span>
              <strong>{dashboardAuth.user.display_name || dashboardAuth.user.username}</strong>
            </div>
            <div className="session-card">
              <span>Role</span>
              <strong><RoleBadge role={dashboardAuth.user.role} /></strong>
            </div>
            <div className="session-card">
              <span>Mode</span>
              <strong>{canAdmin ? "Full admin" : canReview ? "Analyst review" : "Read only"}</strong>
            </div>
            <div className="session-card">
              <span>Signed in at</span>
              <strong>{formatDateTime(dashboardAuth.created_at)}</strong>
              <small>{formatRelativeTime(dashboardAuth.created_at)}</small>
            </div>
            <div className="session-card">
              <span>Last activity</span>
              <strong>{formatDateTime(dashboardAuth.last_seen_at)}</strong>
              <small>{formatRelativeTime(dashboardAuth.last_seen_at)}</small>
            </div>
            <div className="session-card">
              <span>Session expires</span>
              <strong>{formatDateTime(dashboardAuth.expires_at)}</strong>
              <small>{formatRelativeTime(dashboardAuth.expires_at)}</small>
            </div>
          </div>
        </div>

        <div className="hero-actions">
          <label className="field compact">
            <span>Time window</span>
            <select value={windowSeconds} onChange={(event) => setWindowSeconds(Number(event.target.value))}>
              <option value={3600}>Last hour</option>
              <option value={21600}>Last 6 hours</option>
              <option value={86400}>Last 24 hours</option>
              <option value={604800}>Last 7 days</option>
            </select>
          </label>

          <button className="primary-button" onClick={() => loadDashboard()} disabled={dashboardLoading}>
            {dashboardLoading ? "Refreshing..." : "Refresh"}
          </button>
          <a className="secondary-button" href="/reports/summary" target="_blank" rel="noreferrer">
            Summary Report
          </a>
          <a className="secondary-button" href="/reports/events.csv">
            Export CSV
          </a>
          <button className="ghost-button" type="button" onClick={handleLogout} disabled={busyAction === "logout"}>
            {busyAction === "logout" ? "Signing out..." : "Sign out"}
          </button>
        </div>
      </header>

      <StatusToast
        toast={toast}
        onClose={() => {
          setError("");
          setFlash("");
        }}
      />

      <section className="top-grid">
        <article className="panel wide">
          <SectionTitle
            eyebrow="Notifications"
            title="Operational alerts and session activity"
            description="Live signals from request blocking, session state, model mode, and runtime behavior."
          />
          <NotificationCenter
            items={notificationItems}
            counts={notificationCounts}
            activeFilter={notificationFilter}
            onFilterChange={setNotificationFilter}
            onRefresh={() => loadNotifications()}
            loading={notificationsLoading}
            onViewRequest={handleViewRequest}
          />
        </article>

        <article className="panel">
          <SectionTitle
            eyebrow="Runtime Info"
            title="Gateway context and access information"
            description="Backend mode, network endpoints, model, and session metadata."
          />
          <RuntimeInfoPanel systemInfo={systemInfo} sessionInfo={dashboardAuth} />
        </article>
      </section>

      <section className="stats-grid">
        <StatCard
          label="Total Requests"
          value={numberFormatter.format(summary.total_requests)}
          hint="Captured inside the selected time window"
        />
        <StatCard label="Allowed" value={numberFormatter.format(summary.allowed)} hint="Traffic passed the gateway" tone="allow" />
        <StatCard label="Monitored" value={numberFormatter.format(summary.monitored)} hint="Requests flagged for analyst review" tone="monitor" />
        <StatCard label="Blocked" value={numberFormatter.format(summary.blocked)} hint="Requests denied by rules or hybrid scoring" tone="block" />
        <StatCard label="Unique IPs" value={numberFormatter.format(summary.unique_ips)} hint="Distinct client sources seen by the WAF" />
        <StatCard
          label="Avg Latency"
          value={`${Math.round(summary.avg_latency_ms || 0)} ms`}
          hint={`Risk avg ${Number(summary.avg_risk_score || 0).toFixed(3)} | Blacklist ${summary.blacklist_size}`}
        />
      </section>

      <section className="top-grid">
        <article className="panel wide">
          <SectionTitle
            eyebrow="Traffic Pulse"
            title="Decision timeline"
            description="Hourly flow of allow, monitor, and block actions."
          />
          <TimelineChart items={timeline} />
        </article>

        <article className="panel">
          <SectionTitle eyebrow="Model" title="Active runtime model" description="The current scoring artifact loaded by the gateway." />
          <div className="model-card">
            <div>
              <span className="model-label">Version</span>
              <strong>{model?.model_version || "heuristic-fallback"}</strong>
            </div>
            <div>
              <span className="model-label">Type</span>
              <strong>{model?.model_type || "heuristic"}</strong>
            </div>
            <div>
              <span className="model-label">Precision</span>
              <strong>{model?.metrics?.precision ?? "-"}</strong>
            </div>
            <div>
              <span className="model-label">Recall</span>
              <strong>{model?.metrics?.recall ?? "-"}</strong>
            </div>
          </div>
          <ModelVerificationPanel verification={model?.verification} />
        </article>
      </section>

      <section className="top-grid">
        <article className="panel">
          <SectionTitle
            eyebrow="Threats"
            title="Top attack types"
            description="Supported web attack families observed in real live traffic during the selected window. Simulation runs are excluded."
            actions={
              canReview ? (
                <div className="section-action-group">
                  <button
                    type="button"
                    className="ghost-button"
                    disabled={busyAction === "simulate-quick"}
                    onClick={() => handleRunAttackSimulation("quick")}
                  >
                    {busyAction === "simulate-quick" ? "Running..." : "Quick simulation"}
                  </button>
                  <button
                    type="button"
                    className="primary-button"
                    disabled={busyAction === "simulate-full"}
                    onClick={() => handleRunAttackSimulation("full")}
                  >
                    {busyAction === "simulate-full" ? "Running..." : "Full simulation"}
                  </button>
                </div>
              ) : null
            }
          />
          <DistributionList items={summary.top_attack_types || []} emptyLabel="No attacks recorded yet." tone="block" />
          <AttackSimulationPanel simulation={simulation} canRun={canReview} />
        </article>

        <article className="panel">
          <SectionTitle eyebrow="Sources" title="Most active offenders" description="IPs with the strongest concentration of blocked traffic." />
          <DistributionList
            items={(summary.top_offenders || []).map((item) => ({ ...item, count: item.blocked_requests || item.total_requests }))}
            emptyLabel="No offending sources in this window."
            tone="teal"
          />
        </article>

        <article className="panel">
          <SectionTitle eyebrow="Latest" title="Recent decisive events" description="Fast scan of the newest inspected requests." />
          <div className="event-stack">
            {topEvents.length ? (
              topEvents.map((item) => (
                <button key={item.request_id} className="event-chip" onClick={() => handleViewRequest(item.request_id)}>
                  <span className={`pill ${item.action}`}>{item.action}</span>
                  <strong>{item.path}</strong>
                  <span>{item.remote_addr}</span>
                </button>
              ))
            ) : (
              <div className="empty-state small">No events recorded yet.</div>
            )}
          </div>
        </article>
      </section>

      <section className="workspace-grid">
        <article className="panel table-panel">
          <SectionTitle
            eyebrow="Request Review"
            title="Search, filter, and moderate captured traffic"
            description="Select an event to inspect features, rule hits, and hybrid scoring."
            actions={
              <div className="pagination-pill">
                <button disabled={filters.page <= 1} onClick={() => updateFilter("page", filters.page - 1)}>
                  Prev
                </button>
                <span>{pageSummary}</span>
                <button
                  disabled={filters.page >= requests.pagination.pages}
                  onClick={() => updateFilter("page", filters.page + 1)}
                >
                  Next
                </button>
              </div>
            }
          />

          <div className="filter-grid">
            <label className="field">
              <span>Search</span>
              <input
                type="text"
                value={filters.search}
                onChange={(event) => updateFilter("search", event.target.value)}
                placeholder="request id, path, ip, payload"
              />
            </label>
            <label className="field">
              <span>Action</span>
              <select value={filters.action} onChange={(event) => updateFilter("action", event.target.value)}>
                <option value="">All</option>
                <option value="allow">Allow</option>
                <option value="monitor">Monitor</option>
                <option value="block">Block</option>
              </select>
            </label>
            <label className="field">
              <span>Label</span>
              <select value={filters.label} onChange={(event) => updateFilter("label", event.target.value)}>
                <option value="">All</option>
                <option value="benign">Benign</option>
                <option value="malicious">Malicious</option>
                <option value="needs_review">Needs review</option>
              </select>
            </label>
            <label className="field">
              <span>Attack Type</span>
              <input
                type="text"
                value={filters.attack_type}
                onChange={(event) => updateFilter("attack_type", event.target.value)}
                placeholder="sql_injection, xss, traversal"
              />
            </label>
          </div>

          <div className="table-shell">
            <table>
              <thead>
                <tr>
                  <th>Request</th>
                  <th>Path & Source</th>
                  <th>Decision</th>
                  <th>Risk</th>
                  <th>Latency</th>
                  <th>Label</th>
                  <th>Attack Types</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {requestsLoading ? (
                  <tr>
                    <td colSpan="8">
                      <div className="empty-state">Loading requests...</div>
                    </td>
                  </tr>
                ) : requests.items.length ? (
                  requests.items.map((item) => (
                    <RequestRow
                      key={item.request_id}
                      item={item}
                      selected={selectedRequestId === item.request_id}
                      onView={handleViewRequest}
                      onBlock={(requestId) => handleToggleSourceBlock(requestId, "signature")}
                      onDelete={handleDeleteRequest}
                      busyAction={busyAction}
                      canReview={canReview}
                      canDelete={canAdmin}
                    />
                  ))
                ) : (
                  <tr>
                    <td colSpan="8">
                      <div className="empty-state">No requests match the current filters.</div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </article>

        <aside className="side-panel-stack">
          <article className="panel detail-panel">
            <SectionTitle
              eyebrow="Decision Center"
              title={selectedRequest ? selectedRequest.path : "Select a request"}
              description={
                selectedRequest
                  ? `${selectedRequest.method} from ${selectedRequest.remote_addr} | decision ${selectedRequest.decision_action}`
                  : "Choose a row to inspect scoring, rules, and analyst actions."
              }
            />

            {detailLoading ? (
              <div className="empty-state">Loading request details...</div>
            ) : selectedRequest ? (
              <>
                <div className="detail-metrics">
                  <div>
                    <span>Risk</span>
                    <strong>{selectedRequest.risk_score.toFixed(3)}</strong>
                  </div>
                  <div>
                    <span>Status</span>
                    <strong>{selectedRequest.decision_status_code}</strong>
                  </div>
                  <div>
                    <span>Latency</span>
                    <strong>{Math.round(selectedRequest.latency_ms)} ms</strong>
                  </div>
                  <div>
                    <span>Label</span>
                    <strong>{selectedRequest.label || "unlabeled"}</strong>
                  </div>
                  <div>
                    <span>Match Block</span>
                    <strong>{selectedRequestBlocked ? "Active" : "Not blocked"}</strong>
                  </div>
                  <div>
                    <span>IP Blacklist</span>
                    <strong>{selectedSourceBlacklisted ? "Active" : "Not blocked"}</strong>
                  </div>
                </div>

                {canReview ? (
                  <>
                    <label className="field compact">
                      <span>Block scope</span>
                      <select value={blockScope} onChange={(event) => setBlockScope(event.target.value)}>
                        <option value="signature">Request signature</option>
                        <option value="path">Method + path</option>
                        <option value="session">Session</option>
                        <option value="ip">IP address</option>
                      </select>
                    </label>

                    <div className="detail-actions">
                      <button className="primary-button" disabled={busyAction === "malicious"} onClick={() => handleLabel("malicious")}>
                        Mark malicious
                      </button>
                      <button className="secondary-button" disabled={busyAction === "benign"} onClick={() => handleLabel("benign")}>
                        Mark benign
                      </button>
                      <button className="secondary-button" disabled={busyAction === "needs_review"} onClick={() => handleLabel("needs_review")}>
                        Needs review
                      </button>
                      <button
                        type="button"
                        className="secondary-button danger"
                        disabled={busyAction.startsWith("block-")}
                        onClick={() => handleToggleSourceBlock()}
                      >
                        {blockScope === "ip"
                          ? selectedSourceBlacklisted
                            ? "Remove IP blacklist"
                            : "Blacklist IP"
                          : selectedRequestBlocked
                            ? "Remove match block"
                            : "Block match"}
                      </button>
                      {canAdmin ? (
                        <button type="button" className="ghost-button" disabled={busyAction.startsWith("delete-")} onClick={() => handleDeleteRequest()}>
                          Delete request
                        </button>
                      ) : null}
                    </div>
                  </>
                ) : (
                  <div className="permission-note">Viewer role can inspect request details but cannot modify labels or policies.</div>
                )}

                <label className="field">
                  <span>Analyst notes</span>
                  <textarea
                    rows="4"
                    value={reviewNotes}
                    disabled={!canReview}
                    onChange={(event) => setReviewNotes(event.target.value)}
                    placeholder="Explain why this request should be retained, relabeled, or blocked."
                  />
                </label>

                <div className="detail-copy-grid">
                  <div className="meta-card">
                    <span>URL</span>
                    <strong>{selectedRequest.full_url}</strong>
                  </div>
                  <div className="meta-card">
                    <span>User Agent</span>
                    <strong>{selectedRequest.user_agent || "unknown"}</strong>
                  </div>
                  <div className="meta-card">
                    <span>Session</span>
                    <strong>{selectedRequest.session_id || "anonymous"}</strong>
                  </div>
                  <div className="meta-card">
                    <span>Payload Preview</span>
                    <strong>{selectedRequest.payload_preview || "No body preview"}</strong>
                  </div>
                </div>

                <DecisionEngineSection engine={selectedRequest.decision_engine} />

                <AdvancedDiagnosticsSection
                  canViewInternals={canViewInternals}
                  scoreBreakdown={selectedRequest.score_breakdown}
                  ruleResult={selectedRequest.rule_result}
                  features={selectedRequest.features}
                  contextLabel="request"
                />
              </>
            ) : (
              <div className="empty-state">No request selected yet.</div>
            )}
          </article>

          {canReview ? (
            <>
              <article className="panel">
                <SectionTitle eyebrow="Blacklist" title="Manual IP control" description="Add or remove blocked sources from the dashboard." />
                <form className="blacklist-form" onSubmit={handleBlacklistSubmit}>
                  <label className="field">
                    <span>IP Address</span>
                    <input
                      type="text"
                      value={blacklistForm.ip_address}
                      onChange={(event) => setBlacklistForm((current) => ({ ...current, ip_address: event.target.value }))}
                      placeholder="203.0.113.12"
                    />
                  </label>
                  <label className="field">
                    <span>Reason</span>
                    <input
                      type="text"
                      value={blacklistForm.reason}
                      onChange={(event) => setBlacklistForm((current) => ({ ...current, reason: event.target.value }))}
                      placeholder="manual investigation"
                    />
                  </label>
                  <label className="field">
                    <span>TTL Seconds</span>
                    <input
                      type="number"
                      min="60"
                      value={blacklistForm.ttl_seconds}
                      onChange={(event) => setBlacklistForm((current) => ({ ...current, ttl_seconds: Number(event.target.value) || 900 }))}
                    />
                  </label>
                  <button className="primary-button" type="submit" disabled={busyAction === "blacklist-form"}>
                    Add to blacklist
                  </button>
                </form>

                <div className="blacklist-list">
                  {blacklist.length ? (
                    blacklist.map((item) => (
                      <div className="blacklist-item" key={item.ip_address}>
                        <div>
                          <strong>{item.ip_address}</strong>
                          <span>{item.reason}</span>
                        </div>
                        <button type="button" className="ghost-button" onClick={() => handleBlacklistRemove(item.ip_address)}>
                          Remove
                        </button>
                      </div>
                    ))
                  ) : (
                    <div className="empty-state small">No active blacklist entries.</div>
                  )}
                </div>
              </article>

              <article className="panel">
                <SectionTitle
                  eyebrow="Targeted Rules"
                  title="Active match blocks"
                  description="Fine-grained blocks created from request signature, path, session, or IP criteria."
                />
                <ManualRulesPanel items={manualRules} busyAction={busyAction} onRemove={handleManualRuleRemove} />
              </article>
            </>
          ) : null}
        </aside>
      </section>

      {(canReview || canAdmin) ? (
        <section className="admin-grid">
          <article className="panel admin-panel admin-panel-runtime">
              <SectionTitle
                eyebrow="Runtime"
                title="Editable gateway settings"
                description={
                  canAdmin
                    ? "Tune the active WAF thresholds and proxy settings without restarting the app, including Adaptivity, Auto-Tuning, Feedback Loop, ML + Logs, Dynamic Thresholds, and Adaptive Rate Limiting."
                    : "Current runtime settings are visible because your role can review operations."
                }
              />
            <SettingsEditor
              settingsData={settingsData}
              draft={settingsDraft}
              onChange={updateSettingsDraft}
              onSubmit={handleSettingsSave}
              busy={busyAction === "save-settings"}
              canAdmin={canAdmin}
              canReview={canReview}
              securityScope={securityScope}
              securityPolicyDraft={securityPolicyDraft}
              onSecurityPolicyDraftChange={updateSecurityPolicyDraft}
              onRefreshSecurityScope={loadSecurityScope}
              onCreateSecurityPolicy={handleCreateSecurityPolicy}
              onDeleteSecurityPolicy={handleDeleteSecurityPolicy}
              adaptivity={adaptivity}
              onRefreshAdaptivity={loadAdaptivity}
              onApplyAdaptivity={handleApplyAdaptivity}
              autoTuning={autoTuning}
              onRefreshAutoTuning={loadAutoTuning}
              onApplyAutoTuning={handleApplyAutoTuning}
              mlLogTraining={mlLogTraining}
              onRefreshMlLogTraining={loadMlLogTraining}
              onApplyMlLogTraining={handleApplyMlLogTraining}
              feedbackLoop={feedbackLoop}
              onRefreshFeedbackLoop={loadFeedbackLoop}
              onApplyFeedbackLoop={handleApplyFeedbackLoop}
              dynamicThresholds={dynamicThresholds}
              onRefreshDynamicThresholds={loadDynamicThresholds}
              adaptiveRateLimit={adaptiveRateLimit}
              onRefreshAdaptiveRateLimit={loadAdaptiveRateLimit}
              busyAction={busyAction}
            />
          </article>

          {canAdmin ? (
            <>
              <article className="panel admin-panel admin-panel-users">
                <SectionTitle eyebrow="Users" title="Roles and access" description="Create accounts and adjust operational permissions for the WAF team." />
                <UserDirectory
                  users={users}
                  drafts={userDrafts}
                  onDraftChange={updateUserDraft}
                  onCreateChange={updateCreateUserForm}
                  createForm={createUserForm}
                  onCreate={handleCreateUser}
                  onSaveUser={handleSaveUser}
                  busyAction={busyAction}
                />
              </article>

              <article className="panel admin-panel admin-panel-audit">
                <SectionTitle eyebrow="Audit" title="Administrative activity" description="Every review, block, delete, login, and settings change is recorded here." />
                <AuditTrail items={auditEvents} />
              </article>
            </>
          ) : null}
        </section>
      ) : null}

      <RequestInspectorModal
        open={inspectorOpen}
        requestItem={selectedRequest}
        detailLoading={detailLoading}
        reviewNotes={reviewNotes}
        blockScope={blockScope}
        onBlockScopeChange={setBlockScope}
        onNotesChange={setReviewNotes}
        onClose={() => setInspectorOpen(false)}
        onLabel={handleLabel}
        onBlock={() => handleToggleSourceBlock()}
        onDelete={() => handleDeleteRequest()}
        busyAction={busyAction}
        isManuallyBlocked={selectedRequestBlocked}
        isSourceBlacklisted={selectedSourceBlacklisted}
        canReview={canReview}
        canDelete={canAdmin}
      />
    </div>
  );
}
