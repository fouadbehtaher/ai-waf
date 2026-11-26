from dataclasses import dataclass, field
from typing import List


@dataclass
class MitigationDecision:
    action: str
    status_code: int
    reasons: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    attack_types: List[str] = field(default_factory=list)
    model_name: str = ""
    model_version: str = ""
    block_threshold_used: float = 0.0
    monitor_threshold_used: float = 0.0
    threshold_mode: str = "static"
    decision_path: str = "allow_below_thresholds"
    decision_confidence: str = "low"
    confidence_reason: str = ""
    progressive_stage: str = "baseline"
    progressive_reason: str = ""

    def as_dict(self) -> dict:
        return {
            "action": self.action,
            "status_code": self.status_code,
            "reasons": self.reasons,
            "risk_score": self.risk_score,
            "attack_types": self.attack_types,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "block_threshold_used": self.block_threshold_used,
            "monitor_threshold_used": self.monitor_threshold_used,
            "threshold_mode": self.threshold_mode,
            "decision_path": self.decision_path,
            "decision_confidence": self.decision_confidence,
            "confidence_reason": self.confidence_reason,
            "progressive_stage": self.progressive_stage,
            "progressive_reason": self.progressive_reason,
        }


def _progressive_adjustment(block_threshold: float, monitor_threshold: float, history_snapshot, settings) -> dict:
    if history_snapshot is None:
        return {
            "block_threshold": block_threshold,
            "monitor_threshold": monitor_threshold,
            "stage": "baseline",
            "reason": "",
            "adjusted": False,
        }

    block_delta = 0.0
    monitor_delta = 0.0
    stage = "baseline"
    reason = ""
    repeat_threshold = max(int(getattr(settings, "blacklist_repeat_offense_threshold", 3) or 3), 1)
    block_count = int(getattr(history_snapshot, "ip_block_count_window", 0) or 0)
    monitor_count = int(getattr(history_snapshot, "ip_monitor_count_window", 0) or 0)
    block_ratio = float(getattr(history_snapshot, "ip_block_ratio", 0.0) or 0.0)
    flagged_ratio = float(getattr(history_snapshot, "ip_flagged_ratio", 0.0) or 0.0)
    fingerprint_reuse = int(getattr(history_snapshot, "fingerprint_reuse_count", 0) or 0)
    path_hits = int(getattr(history_snapshot, "path_hits_window", 0) or 0)
    request_count = int(getattr(history_snapshot, "ip_request_count_window", 0) or 0)

    if (
        block_count >= (repeat_threshold + 2)
        or (
            block_count >= repeat_threshold
            and block_ratio >= 0.85
            and flagged_ratio >= 0.9
            and (fingerprint_reuse >= 5 or path_hits >= 6 or request_count >= 8)
        )
    ):
        stage = "escalated_repeat_offender"
        block_delta = 0.05
        monitor_delta = 0.04
        reason = "Progressive blocking escalated because this source is close to adaptive blacklisting."
    elif block_count >= max(repeat_threshold - 1, 1) or block_ratio >= 0.34 or fingerprint_reuse >= 3 or flagged_ratio >= 0.5:
        stage = "repeat_offender"
        block_delta = 0.03
        monitor_delta = 0.025
        if fingerprint_reuse >= 3 or path_hits >= 3:
            block_delta += 0.01
            monitor_delta += 0.005
        reason = "Progressive blocking tightened thresholds because the source has recent blocked behavior or repeated fingerprint reuse."
    elif monitor_count >= 2 or flagged_ratio >= 0.25 or path_hits >= 3 or request_count >= 6:
        stage = "watch"
        block_delta = 0.01
        monitor_delta = 0.01
        reason = "Progressive blocking lowered thresholds slightly because the source already shows repeated suspicious activity."

    if stage == "baseline":
        return {
            "block_threshold": block_threshold,
            "monitor_threshold": monitor_threshold,
            "stage": stage,
            "reason": reason,
            "adjusted": False,
        }

    adjusted_block = max(block_threshold - block_delta, 0.28)
    adjusted_monitor = max(min(monitor_threshold - monitor_delta, adjusted_block - 0.08), 0.20)
    return {
        "block_threshold": adjusted_block,
        "monitor_threshold": adjusted_monitor,
        "stage": stage,
        "reason": reason,
        "adjusted": True,
    }


def _resolve_thresholds(settings, dynamic_threshold_report, history_snapshot=None) -> dict:
    block_threshold = float(getattr(settings, "block_threshold", 0.72) or 0.72)
    monitor_threshold = float(getattr(settings, "monitor_threshold", 0.48) or 0.48)
    threshold_mode = "static"
    reason_suffix = ""
    progressive_stage = "baseline"
    progressive_reason = ""

    if dynamic_threshold_report and dynamic_threshold_report.get("active"):
        effective = dynamic_threshold_report.get("effective") or {}
        telemetry = dynamic_threshold_report.get("telemetry") or {}
        formula = dynamic_threshold_report.get("formula") or {}
        block_threshold = float(effective.get("block_threshold", block_threshold) or block_threshold)
        monitor_threshold = float(effective.get("monitor_threshold", monitor_threshold) or monitor_threshold)
        threshold_mode = str(effective.get("source") or "dynamic")
        reason_suffix = "Dynamic threshold active: avg_score {0:.3f} + {1:.2f} x std_dev {2:.3f} = {3:.3f}.".format(
            float(telemetry.get("avg_risk_score") or 0.0),
            float(formula.get("std_multiplier") or 1.0),
            float(telemetry.get("stddev_risk_score") or 0.0),
            block_threshold,
        )

    progressive = _progressive_adjustment(block_threshold, monitor_threshold, history_snapshot, settings)
    if progressive["adjusted"]:
        block_threshold = float(progressive["block_threshold"])
        monitor_threshold = float(progressive["monitor_threshold"])
        progressive_stage = str(progressive["stage"])
        progressive_reason = str(progressive["reason"])
        threshold_mode = (
            "{0}+progressive".format(threshold_mode)
            if threshold_mode != "static"
            else "progressive"
        )
        reason_suffix = " ".join(part for part in [reason_suffix, progressive_reason] if part).strip()

    return {
        "block_threshold": block_threshold,
        "monitor_threshold": monitor_threshold,
        "threshold_mode": threshold_mode,
        "reason_suffix": reason_suffix,
        "progressive_stage": progressive_stage,
        "progressive_reason": progressive_reason,
    }


def _decision_confidence(rule_result, score_result, block_threshold: float, monitor_threshold: float, action: str) -> tuple[str, str]:
    rule_strength = float(getattr(rule_result, "severity", 0.0) or 0.0)
    score = float(getattr(score_result, "score", 0.0) or 0.0)
    margin_to_block = score - float(block_threshold)
    margin_to_monitor = score - float(monitor_threshold)

    if action == "block":
        if getattr(rule_result, "should_block", False):
            return "high", "Explicit blocking rules matched, so the rule engine took precedence over threshold-only scoring."
        if margin_to_block >= 0.12:
            return "high", "The hybrid score was well above the active block threshold."
        return "medium", "The hybrid score crossed the active block threshold, but only by a narrow margin."

    if action == "monitor":
        if getattr(rule_result, "should_monitor", False) and score >= block_threshold:
            return "high", "Both monitoring rules and elevated score support continued review of this request."
        if getattr(rule_result, "should_monitor", False):
            return "medium", "Monitoring rules matched even though the score did not reach a hard block."
        if margin_to_monitor >= 0.08:
            return "medium", "The hybrid score clearly crossed the monitor threshold."
        return "low", "The request was monitored with only a small margin above the active threshold."

    if getattr(rule_result, "matched_rules", None):
        return "medium", "The request stayed below thresholds, but some low-severity indicators were still present."
    if rule_strength >= 0.75:
        return "medium", "Signals were noticeable, but they did not meet the monitor threshold."
    return "high", "No blocking rules matched and the score stayed comfortably below the active thresholds."


def build_decision_explanation(rule_result, score_result, history_snapshot, decision: MitigationDecision, settings) -> dict:
    score_value = round(float(getattr(score_result, "score", 0.0) or 0.0), 4)
    model_name = str(getattr(score_result, "model_name", "") or "")
    weighted_combination = model_name == "hybrid"
    offense_signals = []

    if history_snapshot and getattr(history_snapshot, "ip_block_count_window", 0):
        offense_signals.append(
            "The source already has {0} blocked request(s) in the active history window.".format(
                int(getattr(history_snapshot, "ip_block_count_window", 0) or 0)
            )
        )
    if history_snapshot and float(getattr(history_snapshot, "ip_block_ratio", 0.0) or 0.0) >= 0.5:
        offense_signals.append(
            "The recent IP block ratio is {0:.0%}, so this source is behaving like a repeat offender.".format(
                float(getattr(history_snapshot, "ip_block_ratio", 0.0) or 0.0)
            )
        )
    if history_snapshot and int(getattr(history_snapshot, "fingerprint_reuse_count", 0) or 0) >= 2:
        offense_signals.append("The same request fingerprint has already been reused in the current window.")
    if history_snapshot and int(getattr(history_snapshot, "path_hits_window", 0) or 0) >= 3:
        offense_signals.append("The same path has been hit repeatedly in the current window.")
    if history_snapshot and int(getattr(history_snapshot, "unique_paths_window", 0) or 0) >= 10:
        offense_signals.append("The source has touched many distinct paths, which looks like probing or reconnaissance.")

    basis = []
    if getattr(rule_result, "should_block", False) or getattr(rule_result, "should_monitor", False):
        basis.append("rules")
    if score_value >= float(decision.monitor_threshold_used or 0.0):
        basis.append("score")
        basis.append("thresholds")
    if offense_signals:
        basis.append("offense_history")
    if decision.progressive_stage != "baseline":
        basis.append("progressive_blocking")
    if weighted_combination:
        basis.append("weighted_ml_plus_rules")
    else:
        basis.append("heuristic_scoring")

    summary = ""
    if decision.decision_path == "rule_block":
        summary = "Blocked because explicit rules matched this request."
    elif decision.decision_path == "score_block":
        summary = "Blocked because the hybrid risk score crossed the active block threshold."
    elif decision.decision_path == "rule_and_score_monitor":
        summary = "Monitored because both rules and score signaled elevated risk."
    elif decision.decision_path == "rule_monitor":
        summary = "Monitored because rules matched, even though the request did not reach a hard block."
    elif decision.decision_path == "score_monitor":
        summary = "Monitored because the hybrid score crossed the active monitor threshold."
    elif decision.decision_path == "proxy_transport_block":
        summary = "Blocked by transport controls before the request could complete upstream."
    else:
        summary = "Allowed because no hard rules matched and the score stayed below the active thresholds."

    return {
        "summary": summary,
        "action": decision.action,
        "decision_path": decision.decision_path,
        "decision_basis": basis,
        "score": {
            "risk_score": score_value,
            "raw_score": round(float(getattr(score_result, "raw_score", score_value) or score_value), 4),
            "model_name": model_name,
            "model_version": str(getattr(score_result, "model_version", "") or ""),
            "weighted_combination": weighted_combination,
            "heuristic_weight": round(float(getattr(settings, "heuristic_weight", 1.0) or 1.0), 3),
            "ml_weight": round(float(getattr(settings, "ml_weight", 0.0) or 0.0), 3),
        },
        "thresholds": {
            "monitor_threshold": round(float(decision.monitor_threshold_used or 0.0), 4),
            "block_threshold": round(float(decision.block_threshold_used or 0.0), 4),
            "threshold_mode": decision.threshold_mode,
            "progressive_stage": decision.progressive_stage,
            "progressive_reason": decision.progressive_reason,
            "score_minus_monitor": round(score_value - float(decision.monitor_threshold_used or 0.0), 4),
            "score_minus_block": round(score_value - float(decision.block_threshold_used or 0.0), 4),
        },
        "rules": {
            "matched_count": len(getattr(rule_result, "matched_rules", []) or []),
            "blocking_rule_hit": bool(getattr(rule_result, "should_block", False)),
            "monitor_rule_hit": bool(getattr(rule_result, "should_monitor", False)),
            "max_severity": round(float(getattr(rule_result, "severity", 0.0) or 0.0), 4),
            "attack_types": list(getattr(rule_result, "attack_types", []) or []),
        },
        "confidence": {
            "level": decision.decision_confidence,
            "reason": decision.confidence_reason,
            "usage": "Confidence explains certainty to analysts; the live action still follows rules, thresholds, and history-driven controls.",
        },
        "offense_history": {
            "request_count_window": int(getattr(history_snapshot, "ip_request_count_window", 0) or 0) if history_snapshot else 0,
            "blocked_count_window": int(getattr(history_snapshot, "ip_block_count_window", 0) or 0) if history_snapshot else 0,
            "monitored_count_window": int(getattr(history_snapshot, "ip_monitor_count_window", 0) or 0) if history_snapshot else 0,
            "session_request_count_window": int(getattr(history_snapshot, "session_request_count_window", 0) or 0) if history_snapshot else 0,
            "fingerprint_reuse_count": int(getattr(history_snapshot, "fingerprint_reuse_count", 0) or 0) if history_snapshot else 0,
            "path_hits_window": int(getattr(history_snapshot, "path_hits_window", 0) or 0) if history_snapshot else 0,
            "unique_paths_window": int(getattr(history_snapshot, "unique_paths_window", 0) or 0) if history_snapshot else 0,
            "block_ratio": round(float(getattr(history_snapshot, "ip_block_ratio", 0.0) or 0.0), 4) if history_snapshot else 0.0,
            "flagged_ratio": round(float(getattr(history_snapshot, "ip_flagged_ratio", 0.0) or 0.0), 4) if history_snapshot else 0.0,
            "avg_risk_score_window": round(float(getattr(history_snapshot, "ip_avg_risk_score_window", 0.0) or 0.0), 4) if history_snapshot else 0.0,
            "max_risk_score_window": round(float(getattr(history_snapshot, "ip_max_risk_score_window", 0.0) or 0.0), 4) if history_snapshot else 0.0,
            "signals": offense_signals,
            "usage": "Offense history affects repeat-offender rules, adaptive throttling, and blacklist escalation before or alongside the final action.",
        },
    }


def decide_action(rule_result, score_result, history_snapshot, settings, dynamic_threshold_report=None) -> MitigationDecision:
    reasons = list(rule_result.reasons)
    attack_types = list(rule_result.attack_types)
    threshold_state = _resolve_thresholds(settings, dynamic_threshold_report, history_snapshot=history_snapshot)
    block_threshold = threshold_state["block_threshold"]
    monitor_threshold = threshold_state["monitor_threshold"]
    threshold_mode = threshold_state["threshold_mode"]
    reason_suffix = threshold_state["reason_suffix"]
    progressive_stage = threshold_state["progressive_stage"]
    progressive_reason = threshold_state["progressive_reason"]

    if rule_result.should_block:
        confidence, confidence_reason = _decision_confidence(
            rule_result, score_result, block_threshold, monitor_threshold, "block"
        )
        return MitigationDecision(
            action="block",
            status_code=403,
            reasons=reasons,
            risk_score=score_result.score,
            attack_types=attack_types,
            model_name=score_result.model_name,
            model_version=score_result.model_version,
            block_threshold_used=block_threshold,
            monitor_threshold_used=monitor_threshold,
            threshold_mode=threshold_mode,
            decision_path="rule_block",
            decision_confidence=confidence,
            confidence_reason=confidence_reason,
            progressive_stage=progressive_stage,
            progressive_reason=progressive_reason,
        )

    if score_result.score >= block_threshold:
        if "anomaly" not in attack_types:
            attack_types.append("anomaly")
        reasons.append(
            "Hybrid risk score crossed the {0} blocking threshold ({1:.3f}).".format(
                "active" if threshold_mode != "static" else "configured",
                block_threshold,
            )
        )
        if reason_suffix:
            reasons.append(reason_suffix)
        confidence, confidence_reason = _decision_confidence(
            rule_result, score_result, block_threshold, monitor_threshold, "block"
        )
        return MitigationDecision(
            action="block",
            status_code=403,
            reasons=reasons,
            risk_score=score_result.score,
            attack_types=attack_types,
            model_name=score_result.model_name,
            model_version=score_result.model_version,
            block_threshold_used=block_threshold,
            monitor_threshold_used=monitor_threshold,
            threshold_mode=threshold_mode,
            decision_path="score_block",
            decision_confidence=confidence,
            confidence_reason=confidence_reason,
            progressive_stage=progressive_stage,
            progressive_reason=progressive_reason,
        )

    if score_result.score >= monitor_threshold or rule_result.should_monitor:
        if score_result.score >= monitor_threshold and "anomaly" not in attack_types:
            attack_types.append("anomaly")
            reasons.append(
                "Hybrid risk score crossed the {0} monitoring threshold ({1:.3f}).".format(
                    "active" if threshold_mode != "static" else "configured",
                    monitor_threshold,
                )
            )
            if reason_suffix:
                reasons.append(reason_suffix)
        confidence, confidence_reason = _decision_confidence(
            rule_result, score_result, block_threshold, monitor_threshold, "monitor"
        )
        return MitigationDecision(
            action="monitor",
            status_code=200,
            reasons=reasons or ["Request allowed but marked for monitoring"],
            risk_score=score_result.score,
            attack_types=attack_types,
            model_name=score_result.model_name,
            model_version=score_result.model_version,
            block_threshold_used=block_threshold,
            monitor_threshold_used=monitor_threshold,
            threshold_mode=threshold_mode,
            decision_path="rule_and_score_monitor"
            if rule_result.should_monitor and score_result.score >= monitor_threshold
            else "score_monitor"
            if score_result.score >= monitor_threshold
            else "rule_monitor",
            decision_confidence=confidence,
            confidence_reason=confidence_reason,
            progressive_stage=progressive_stage,
            progressive_reason=progressive_reason,
        )

    confidence, confidence_reason = _decision_confidence(
        rule_result, score_result, block_threshold, monitor_threshold, "allow"
    )
    return MitigationDecision(
        action="allow",
        status_code=200,
        reasons=["Request allowed"],
        risk_score=score_result.score,
        attack_types=attack_types,
        model_name=score_result.model_name,
        model_version=score_result.model_version,
        block_threshold_used=block_threshold,
        monitor_threshold_used=monitor_threshold,
        threshold_mode=threshold_mode,
        decision_path="allow_below_thresholds",
        decision_confidence=confidence,
        confidence_reason=confidence_reason,
        progressive_stage=progressive_stage,
        progressive_reason=progressive_reason,
    )


def should_blacklist_ip(decision: MitigationDecision, history_snapshot, settings, remote_addr: str) -> bool:
    if decision.action != "block":
        return False
    if remote_addr in getattr(settings, "trusted_ips", ()):
        return False
    return (history_snapshot.ip_block_count_window + 1) >= settings.blacklist_repeat_offense_threshold


def block_request(request_record, decision: MitigationDecision) -> dict:
    return {
        "message": "Request blocked by the AI-based WAF",
        "request_id": request_record.request_id,
        "path": request_record.path,
        "risk_score": decision.risk_score,
        "attack_types": decision.attack_types,
        "reasons": decision.reasons,
        "model_name": decision.model_name,
        "model_version": decision.model_version,
    }
