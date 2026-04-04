import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs

from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from core.attack_taxonomy import ATTACK_FAMILIES
from core import dynamic_thresholds as dt
from core import endpoint_policy as ep
from core import mitigation as mi
from config import settings
from main import create_api_app, create_app


ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


class BackendServer:
    def __init__(self) -> None:
        self.app = Flask("backend-test")

        @self.app.route("/", defaults={"subpath": ""}, methods=ALL_METHODS)
        @self.app.route("/<path:subpath>", methods=ALL_METHODS)
        def echo(subpath: str):
            sleep_values = parse_qs(request.query_string.decode("utf-8", errors="ignore")).get("sleep_ms", [])
            if sleep_values:
                try:
                    time.sleep(max(int(sleep_values[0]), 0) / 1000.0)
                except (TypeError, ValueError):
                    pass
            return jsonify(
                {
                    "backend": "test-backend",
                    "method": request.method,
                    "path": "/" + subpath if subpath else "/",
                    "args": request.args.to_dict(flat=True),
                    "body": request.get_data(as_text=True),
                    "forwarded_for": request.headers.get("X-Forwarded-For", ""),
                    "waf_request_id": request.headers.get("X-WAF-Request-ID", ""),
                    "proxy_connection_mode": request.headers.get("X-WAF-Proxy-Connection-Mode", ""),
                    "upstream_pool_generation": request.headers.get("X-WAF-Upstream-Pool-Generation", ""),
                    "connection": request.headers.get("Connection", ""),
                }
            )

        self.server = make_server("127.0.0.1", 0, self.app)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=2)


class WafPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.backend = BackendServer()
        cls.backend.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.backend.stop()

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        db_path = Path(self.temp_dir.name) / "test.sqlite3"
        model_artifact_path = Path(self.temp_dir.name) / "models" / "active_model.joblib"
        test_settings = settings.with_overrides(
            db_path=db_path,
            model_artifact_path=model_artifact_path,
            backend_base_url="http://127.0.0.1:{0}".format(self.backend.port),
            transparent_proxy=False,
            debug=False,
            auto_tuning_min_samples=6,
            auto_tuning_window_seconds=3600,
            auto_tuning_cooldown_seconds=60,
            dynamic_thresholds_min_samples=6,
            dynamic_thresholds_window_seconds=3600,
            feedback_loop_min_feedback=1,
            feedback_loop_window_seconds=3600,
            feedback_loop_cooldown_seconds=60,
            ml_log_training_min_labeled_rows=4,
            ml_log_training_min_benign_rows=2,
            ml_log_training_min_malicious_rows=2,
            ml_log_training_window_seconds=3600,
            ml_log_training_cooldown_seconds=60,
        )
        self.app = create_app(test_settings)
        self.app.testing = True
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.client = None
        self.app = None
        time.sleep(0.05)
        self.temp_dir.cleanup()

    def login_as(self, username: str, password: str):
        response = self.client.post(
            "/api/auth/login",
            data=json.dumps({"username": username, "password": password}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        return response

    def test_proxy_request_is_forwarded_to_backend(self) -> None:
        response = self.client.get("/proxy/api/hello?name=world")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["backend"], "test-backend")
        self.assertEqual(payload["path"], "/api/hello")
        self.assertEqual(payload["args"]["name"], "world")
        self.assertTrue(payload["waf_request_id"])
        self.assertIn(payload["proxy_connection_mode"], {"close", "keepalive"})

    def test_malicious_request_is_blocked(self) -> None:
        response = self.client.get("/protected?message=bad_keyword")
        self.assertEqual(response.status_code, 403)
        payload = response.get_json()
        self.assertEqual(payload["message"], "Request blocked by the AI-based WAF")
        self.assertIn("suspicious_payload", payload["attack_types"])

    def test_attack_catalog_reflects_project_threat_families(self) -> None:
        self.client.post("/protected", data="union select password from users", content_type="text/plain")
        self.client.post("/protected", data="<script>alert(1)</script>", content_type="text/plain")
        self.client.post("/protected", data="cmd=cat /etc/passwd", content_type="text/plain")
        self.client.get("/protected?message=../../etc/passwd")
        for _ in range(6):
            self.client.get("/inspect/admin/login?username=admin", headers={"User-Agent": "curl/8.0"})

        self.login_as("admin", "Admin123!")
        summary = self.client.get("/api/dashboard/summary")
        self.assertEqual(summary.status_code, 200)
        attack_rows = {item["attack_type"]: item for item in summary.get_json()["top_attack_types"]}

        for attack_type in (
            "sql_injection",
            "xss",
            "ddos",
            "path_traversal",
            "command_injection",
            "brute_force",
            "reconnaissance",
            "automation_abuse",
            "payload_evasion",
            "anomaly",
        ):
            self.assertIn(attack_type, attack_rows)
            self.assertIn("label", attack_rows[attack_type])
            self.assertIn("description", attack_rows[attack_type])

        self.assertGreater(attack_rows["sql_injection"]["count"], 0)
        self.assertGreater(attack_rows["xss"]["count"], 0)
        self.assertGreater(attack_rows["path_traversal"]["count"], 0)
        self.assertGreater(attack_rows["command_injection"]["count"], 0)
        self.assertGreater(attack_rows["brute_force"]["count"], 0)
        self.assertGreater(attack_rows["reconnaissance"]["count"], 0)
        self.assertGreater(attack_rows["automation_abuse"]["count"], 0)

    def test_headless_scraping_bot_is_blocked_and_recorded_as_automation_abuse(self) -> None:
        response = self.client.get(
            "/inspect/search?q=laptop&page=1",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/123.0.0.0 Safari/537.36",
                "Accept": "*/*",
            },
        )
        self.assertEqual(response.status_code, 403)
        payload = response.get_json()
        self.assertTrue(any(item in {"malicious_automation", "automation_abuse"} for item in payload["attack_types"]))

        self.login_as("admin", "Admin123!")
        detail = self.client.get(f"/api/requests/{payload['request_id']}").get_json()
        self.assertEqual(detail["endpoint_policy"]["policy_id"], "builtin-search-surface")
        self.assertEqual(detail["features"]["headless_browser_signal"], 1.0)
        self.assertEqual(detail["features"]["scraping_pattern_signal"], 1.0)
        self.assertGreaterEqual(detail["features"]["bot_likelihood_score"], 1.0)

    def test_browser_integrity_mismatch_monitors_fake_browser_on_login_surface(self) -> None:
        response = self.client.post(
            "/inspect/login",
            data=json.dumps({"username": "demo"}),
            content_type="application/json",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/123.0.0.0 Safari/537.36",
                "Accept": "*/*",
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["action"], "monitor")
        self.assertTrue(any(item in {"malicious_automation", "automation_abuse"} for item in payload["attack_types"]))
        self.assertEqual(payload["endpoint_policy"]["policy_id"], "builtin-login-surface")
        self.assertEqual(payload["features"]["browser_claim_signal"], 1.0)
        self.assertEqual(payload["features"]["browser_integrity_signal"], 1.0)
        self.assertEqual(payload["features"]["human_browser_signal"], 0.0)

    def test_human_like_browser_search_is_not_flagged_as_bot(self) -> None:
        response = self.client.get(
            "/inspect/search?q=tablet",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
                "Sec-CH-UA": "\"Chromium\";v=\"123\", \"Google Chrome\";v=\"123\"",
                "Referer": "http://127.0.0.1:5000/dashboard/",
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["action"], "allow")
        self.assertEqual(payload["endpoint_policy"]["policy_id"], "builtin-search-surface")
        self.assertEqual(payload["features"]["human_browser_signal"], 1.0)
        self.assertEqual(payload["features"]["browser_integrity_signal"], 0.0)
        self.assertEqual(payload["features"]["automation_fingerprint_signal"], 0.0)
        self.assertEqual(payload["features"]["headless_browser_signal"], 0.0)
        self.assertFalse(any(item in {"malicious_automation", "automation_abuse"} for item in payload["attack_types"]))

    def test_dashboard_and_reports_are_available(self) -> None:
        self.client.get("/protected?message=hello")
        login_response = self.login_as("admin", "Admin123!")
        dashboard = self.client.get("/dashboard", follow_redirects=True)
        summary = self.client.get("/reports/summary.json")
        csv_export = self.client.get("/reports/events.csv")
        api_summary = self.client.get("/api/dashboard/summary")
        notifications = self.client.get("/api/dashboard/notifications")
        auth_me = self.client.get("/api/auth/me")
        model_verification = self.client.get("/api/model/verification")
        request_listing = self.client.get("/api/requests?page=1&page_size=5")

        self.assertEqual(dashboard.status_code, 200)
        self.assertEqual(summary.status_code, 200)
        self.assertEqual(csv_export.status_code, 200)
        self.assertEqual(api_summary.status_code, 200)
        self.assertEqual(notifications.status_code, 200)
        self.assertEqual(auth_me.status_code, 200)
        self.assertEqual(request_listing.status_code, 200)
        self.assertIn(model_verification.status_code, {200, 404})
        self.assertIn("total_requests", summary.get_json())
        self.assertIn("active_model", api_summary.get_json())
        self.assertIn("auth", api_summary.get_json())
        self.assertIn("system", api_summary.get_json())
        self.assertIn("notifications", api_summary.get_json())
        self.assertIn("simulation", api_summary.get_json())
        self.assertIn("created_at", auth_me.get_json())
        self.assertIn("last_seen_at", auth_me.get_json())
        self.assertIn("capabilities", auth_me.get_json())
        self.assertIn("created_at", login_response.get_json())
        self.assertIn("notifications", notifications.get_json())
        self.assertIn("items", request_listing.get_json())
        self.assertIn("request_id", csv_export.get_data(as_text=True))
        health_payload = self.client.get("/health").get_json()
        self.assertIn("database_backend", health_payload)
        self.assertIn("rate_limit_backend", health_payload)
        self.assertIn("pre_app_filter_enabled", health_payload)

    def test_blacklist_and_labeling_work(self) -> None:
        block_response = self.client.get("/protected?message=bad_keyword")
        request_id = block_response.get_json()["request_id"]
        self.login_as("admin", "Admin123!")

        add_blacklist = self.client.post(
            "/api/blacklist",
            data=json.dumps({"ip_address": "127.0.0.1", "reason": "unit test", "ttl_seconds": 60}),
            content_type="application/json",
        )
        self.assertEqual(add_blacklist.status_code, 201)

        list_blacklist = self.client.get("/api/blacklist")
        self.assertEqual(list_blacklist.status_code, 200)
        self.assertEqual(list_blacklist.get_json()["items"][0]["ip_address"], "127.0.0.1")

        label_response = self.client.post(
            "/api/labels/{0}".format(request_id),
            data=json.dumps({"label": "malicious", "notes": "confirmed in test"}),
            content_type="application/json",
        )
        self.assertEqual(label_response.status_code, 200)

        request_detail = self.client.get("/api/requests/{0}".format(request_id))
        self.assertEqual(request_detail.status_code, 200)
        detail_payload = request_detail.get_json()
        self.assertEqual(detail_payload["request_id"], request_id)
        self.assertIn("decision_engine", detail_payload)
        self.assertIn("thresholds", detail_payload["decision_engine"])
        self.assertIn("confidence", detail_payload["decision_engine"])
        self.assertIn("offense_history", detail_payload["decision_engine"])

        request_blacklist = self.client.post(
            "/api/requests/{0}/blacklist".format(request_id),
            data=json.dumps({"reason": "dashboard block", "ttl_seconds": 120}),
            content_type="application/json",
        )
        self.assertEqual(request_blacklist.status_code, 201)

        delete_response = self.client.delete("/api/requests/{0}".format(request_id))
        self.assertEqual(delete_response.status_code, 200)

        missing_after_delete = self.client.get("/api/requests/{0}".format(request_id))
        self.assertEqual(missing_after_delete.status_code, 404)

    def test_targeted_block_only_blocks_the_selected_signature(self) -> None:
        first_response = self.client.get("/protected?message=alpha")
        second_response = self.client.get("/protected?message=beta")
        first_request_id = first_response.get_json()["request_id"]
        self.login_as("analyst", "Analyst123!")

        targeted_block = self.client.post(
            "/api/requests/{0}/blacklist".format(first_request_id),
            data=json.dumps({"scope": "signature", "reason": "targeted unit test", "ttl_seconds": 120}),
            content_type="application/json",
        )
        self.assertEqual(targeted_block.status_code, 201)
        self.assertEqual(targeted_block.get_json()["scope"], "signature")

        blacklist_items = self.client.get("/api/blacklist").get_json()
        self.assertEqual(blacklist_items["count"], 0)

        replay_blocked = self.client.get("/protected?message=alpha")
        replay_allowed = self.client.get("/protected?message=beta")

        self.assertEqual(replay_blocked.status_code, 403)
        self.assertIn("manual_policy", replay_blocked.get_json()["attack_types"])
        self.assertEqual(replay_allowed.status_code, 200)

    def test_api_requires_authentication(self) -> None:
        response = self.client.get("/api/dashboard/summary")
        self.assertEqual(response.status_code, 401)

    def test_viewer_can_read_but_cannot_block(self) -> None:
        benign_response = self.client.get("/protected?message=viewer-check")
        request_id = benign_response.get_json()["request_id"]
        self.login_as("viewer", "Viewer123!")

        request_listing = self.client.get("/api/requests?page=1&page_size=5")
        self.assertEqual(request_listing.status_code, 200)

        request_detail = self.client.get("/api/requests/{0}".format(request_id))
        self.assertEqual(request_detail.status_code, 200)
        detail_payload = request_detail.get_json()
        self.assertFalse(detail_payload["can_view_internals"])
        self.assertIsNone(detail_payload["score_breakdown"])
        self.assertIsNone(detail_payload["rule_result"])
        self.assertIsNone(detail_payload["features"])
        self.assertIn("decision_engine", detail_payload)
        self.assertIn("summary", detail_payload["decision_engine"])
        self.assertIn("confidence", detail_payload["decision_engine"])

        block_attempt = self.client.post(
            "/api/requests/{0}/blacklist".format(request_id),
            data=json.dumps({"scope": "signature", "reason": "viewer should fail"}),
            content_type="application/json",
        )
        self.assertEqual(block_attempt.status_code, 403)

    def test_admin_can_update_runtime_settings_and_manage_users(self) -> None:
        self.login_as("admin", "Admin123!")

        settings_response = self.client.patch(
            "/api/admin/settings",
            data=json.dumps({"settings": {"block_threshold": 0.8, "token_bucket_capacity": 99}}),
            content_type="application/json",
        )
        self.assertEqual(settings_response.status_code, 200)
        self.assertEqual(settings_response.get_json()["settings"]["token_bucket_capacity"], 99)

        create_user = self.client.post(
            "/api/admin/users",
            data=json.dumps(
                {
                    "username": "ops1",
                    "display_name": "Ops One",
                    "role": "viewer",
                    "password": "Ops12345!",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create_user.status_code, 201)
        created_user = create_user.get_json()["user"]

        update_user = self.client.patch(
            "/api/admin/users/{0}".format(created_user["user_id"]),
            data=json.dumps({"role": "analyst", "is_active": True}),
            content_type="application/json",
        )
        self.assertEqual(update_user.status_code, 200)
        self.assertEqual(update_user.get_json()["user"]["role"], "analyst")

        audit_log = self.client.get("/api/admin/audit?limit=10")
        self.assertEqual(audit_log.status_code, 200)
        self.assertTrue(audit_log.get_json()["items"])

    def test_auto_tuning_can_preview_and_apply_runtime_changes(self) -> None:
        self.login_as("admin", "Admin123!")

        preview_before = self.client.get("/api/admin/settings/auto-tune")
        self.assertEqual(preview_before.status_code, 200)
        self.assertEqual(preview_before.get_json()["mode"], "insufficient_data")

        for _ in range(6):
            self.client.get("/protected?message=bad_keyword")

        preview_after = self.client.get("/api/admin/settings/auto-tune")
        self.assertEqual(preview_after.status_code, 200)
        preview_payload = preview_after.get_json()
        self.assertEqual(preview_payload["mode"], "harden")
        self.assertTrue(preview_payload["can_apply"])
        self.assertIn("block_threshold", preview_payload["recommendation"]["changes"])

        apply_response = self.client.post(
            "/api/admin/settings/auto-tune",
            data=json.dumps({"action": "apply", "trigger": "test-manual"}),
            content_type="application/json",
        )
        self.assertEqual(apply_response.status_code, 200)
        apply_payload = apply_response.get_json()
        self.assertTrue(apply_payload["applied"])
        self.assertLess(apply_payload["settings"]["block_threshold"], settings.block_threshold)

    def test_enabled_auto_tuning_self_adjusts_after_enough_requests(self) -> None:
        self.login_as("admin", "Admin123!")

        enable_auto = self.client.patch(
            "/api/admin/settings",
            data=json.dumps({"settings": {"auto_tuning_enabled": True, "auto_tuning_cooldown_seconds": 60}}),
            content_type="application/json",
        )
        self.assertEqual(enable_auto.status_code, 200)

        for _ in range(6):
            self.client.get("/protected?message=bad_keyword")

        auto_tune_report = self.client.get("/api/admin/settings/auto-tune")
        self.assertEqual(auto_tune_report.status_code, 200)
        auto_payload = auto_tune_report.get_json()
        self.assertTrue(auto_payload["enabled"])
        self.assertTrue(auto_payload["last_auto_tune"]["created_at"])
        self.assertIn(
            auto_payload["last_auto_tune"]["details"].get("trigger", ""),
            {"blocked_request", "inspected_request", "proxy_failure", "failed_login", "proxied_request"},
        )
        runtime_settings = self.client.get("/api/admin/settings").get_json()["settings"]
        self.assertLess(runtime_settings["block_threshold"], settings.block_threshold)

    def test_feedback_loop_can_preview_and_apply_relaxation(self) -> None:
        blocked_response = self.client.get("/protected?message=bad_keyword")
        request_id = blocked_response.get_json()["request_id"]
        self.login_as("admin", "Admin123!")

        label_response = self.client.post(
            "/api/requests/{0}/label".format(request_id),
            data=json.dumps({"label": "benign", "notes": "false positive in test"}),
            content_type="application/json",
        )
        self.assertEqual(label_response.status_code, 200)

        preview = self.client.get("/api/admin/settings/feedback-loop")
        self.assertEqual(preview.status_code, 200)
        preview_payload = preview.get_json()
        self.assertEqual(preview_payload["mode"], "relax")
        self.assertTrue(preview_payload["can_apply"])
        self.assertIn("block_threshold", preview_payload["recommendation"]["changes"])

        apply_response = self.client.post(
            "/api/admin/settings/feedback-loop",
            data=json.dumps({"action": "apply", "trigger": "test-manual"}),
            content_type="application/json",
        )
        self.assertEqual(apply_response.status_code, 200)
        apply_payload = apply_response.get_json()
        self.assertTrue(apply_payload["applied"])
        self.assertGreater(apply_payload["settings"]["block_threshold"], settings.block_threshold)

    def test_enabled_feedback_loop_self_hardens_after_missed_attack_label(self) -> None:
        self.login_as("admin", "Admin123!")

        enable_feedback_loop = self.client.patch(
            "/api/admin/settings",
            data=json.dumps({"settings": {"feedback_loop_enabled": True, "feedback_loop_cooldown_seconds": 60}}),
            content_type="application/json",
        )
        self.assertEqual(enable_feedback_loop.status_code, 200)

        allowed_response = self.client.get("/protected?message=feedback-check")
        request_id = allowed_response.get_json()["request_id"]

        label_response = self.client.post(
            "/api/requests/{0}/label".format(request_id),
            data=json.dumps({"label": "malicious", "notes": "escaped attack in test"}),
            content_type="application/json",
        )
        self.assertEqual(label_response.status_code, 200)

        report = self.client.get("/api/admin/settings/feedback-loop")
        self.assertEqual(report.status_code, 200)
        report_payload = report.get_json()
        self.assertTrue(report_payload["enabled"])
        self.assertTrue(report_payload["last_feedback_apply"]["created_at"])

        runtime_settings = self.client.get("/api/admin/settings").get_json()["settings"]
        self.assertLess(runtime_settings["block_threshold"], settings.block_threshold)

    def test_adaptivity_report_prefers_feedback_when_threshold_changes_conflict(self) -> None:
        request_ids = []
        for _ in range(6):
            blocked_response = self.client.get("/protected?message=bad_keyword")
            self.assertEqual(blocked_response.status_code, 403)
            request_ids.append(blocked_response.get_json()["request_id"])

        self.login_as("admin", "Admin123!")
        label_response = self.client.post(
            "/api/requests/{0}/label".format(request_ids[0]),
            data=json.dumps({"label": "benign", "notes": "feedback should relax thresholds"}),
            content_type="application/json",
        )
        self.assertEqual(label_response.status_code, 200)

        preview = self.client.get("/api/admin/settings/adaptivity")
        self.assertEqual(preview.status_code, 200)
        preview_payload = preview.get_json()
        self.assertEqual(preview_payload["posture"], "mixed")
        self.assertTrue(preview_payload["can_apply"])
        self.assertEqual(preview_payload["recommendation"]["change_sources"]["block_threshold"], "feedback_loop")
        self.assertTrue(preview_payload["recommendation"]["conflicts"])

        apply_response = self.client.post(
            "/api/admin/settings/adaptivity",
            data=json.dumps({"action": "apply", "trigger": "test-manual"}),
            content_type="application/json",
        )
        self.assertEqual(apply_response.status_code, 200)
        apply_payload = apply_response.get_json()
        self.assertTrue(apply_payload["applied"])
        self.assertEqual(apply_payload["change_sources"]["block_threshold"], "feedback_loop")
        self.assertGreater(apply_payload["settings"]["block_threshold"], settings.block_threshold)

    def test_enabled_adaptivity_runs_after_label_and_records_merged_cycle(self) -> None:
        request_ids = []
        for _ in range(6):
            blocked_response = self.client.get("/protected?message=bad_keyword")
            self.assertEqual(blocked_response.status_code, 403)
            request_ids.append(blocked_response.get_json()["request_id"])

        self.login_as("admin", "Admin123!")
        enable_adaptivity = self.client.patch(
            "/api/admin/settings",
            data=json.dumps(
                {
                    "settings": {
                        "auto_tuning_enabled": True,
                        "auto_tuning_cooldown_seconds": 60,
                        "feedback_loop_enabled": True,
                        "feedback_loop_cooldown_seconds": 60,
                    }
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(enable_adaptivity.status_code, 200)

        label_response = self.client.post(
            "/api/requests/{0}/label".format(request_ids[0]),
            data=json.dumps({"label": "benign", "notes": "auto adaptivity merge"}),
            content_type="application/json",
        )
        self.assertEqual(label_response.status_code, 200)

        adaptivity_report = self.client.get("/api/admin/settings/adaptivity")
        self.assertEqual(adaptivity_report.status_code, 200)
        adaptivity_payload = adaptivity_report.get_json()
        self.assertTrue(adaptivity_payload["last_adaptivity_cycle"]["created_at"])
        self.assertIn("block_threshold", adaptivity_payload["last_adaptivity_cycle"]["details"].get("changes", {}))

        runtime_settings = self.client.get("/api/admin/settings").get_json()["settings"]
        self.assertGreater(runtime_settings["block_threshold"], settings.block_threshold)

        audit_log = self.client.get("/api/admin/audit?limit=10")
        self.assertEqual(audit_log.status_code, 200)
        self.assertTrue(any(item["action"] == "settings.adaptivity" for item in audit_log.get_json()["items"]))

    def test_ml_log_training_can_preview_and_apply_new_model(self) -> None:
        self.login_as("admin", "Admin123!")

        request_ids = []
        for _ in range(2):
            request_ids.append((self.client.get("/protected?message=calm-traffic").get_json()["request_id"], "benign"))
        for _ in range(2):
            request_ids.append((self.client.get("/protected?message=bad_keyword").get_json()["request_id"], "malicious"))

        for request_id, label in request_ids:
            label_response = self.client.post(
                "/api/requests/{0}/label".format(request_id),
                data=json.dumps({"label": label, "notes": "ml logs test"}),
                content_type="application/json",
            )
            self.assertEqual(label_response.status_code, 200)

        preview = self.client.get("/api/admin/settings/ml-log-training")
        self.assertEqual(preview.status_code, 200)
        preview_payload = preview.get_json()
        self.assertEqual(preview_payload["mode"], "ready")
        self.assertTrue(preview_payload["can_apply"])

        apply_response = self.client.post(
            "/api/admin/settings/ml-log-training",
            data=json.dumps({"action": "apply", "trigger": "test-manual"}),
            content_type="application/json",
        )
        self.assertEqual(apply_response.status_code, 200)
        apply_payload = apply_response.get_json()
        self.assertTrue(apply_payload["applied"])
        self.assertTrue(apply_payload["training"]["model_version"].startswith("logs-random-forest-"))
        self.assertEqual(apply_payload["active_model"]["model_version"], apply_payload["training"]["model_version"])

    def test_enabled_ml_log_training_self_trains_after_enough_reviewed_logs(self) -> None:
        self.login_as("admin", "Admin123!")

        enable_training = self.client.patch(
            "/api/admin/settings",
            data=json.dumps({"settings": {"ml_log_training_enabled": True, "ml_log_training_cooldown_seconds": 60}}),
            content_type="application/json",
        )
        self.assertEqual(enable_training.status_code, 200)

        request_ids = []
        for _ in range(2):
            request_ids.append((self.client.get("/protected?message=baseline-traffic").get_json()["request_id"], "benign"))
        for _ in range(2):
            request_ids.append((self.client.get("/protected?message=bad_keyword").get_json()["request_id"], "malicious"))

        for request_id, label in request_ids:
            label_response = self.client.post(
                "/api/requests/{0}/label".format(request_id),
                data=json.dumps({"label": label, "notes": "auto ml logs test"}),
                content_type="application/json",
            )
            self.assertEqual(label_response.status_code, 200)

        report = self.client.get("/api/admin/settings/ml-log-training")
        self.assertEqual(report.status_code, 200)
        report_payload = report.get_json()
        self.assertTrue(report_payload["enabled"])
        self.assertTrue(report_payload["last_log_training"]["created_at"])
        self.assertTrue(str(report_payload["current_model"].get("model_version", "")).startswith("logs-random-forest-"))

    def test_adaptive_rate_limit_report_exposes_normal_and_suspicious_profiles(self) -> None:
        self.login_as("admin", "Admin123!")

        enable_adaptive = self.client.patch(
            "/api/admin/settings",
            data=json.dumps(
                {
                    "settings": {
                        "adaptive_rate_limiting_enabled": True,
                        "adaptive_rate_limit_normal_requests_per_min": 60,
                        "adaptive_rate_limit_elevated_requests_per_min": 30,
                        "adaptive_rate_limit_suspicious_requests_per_min": 10,
                        "adaptive_rate_limit_restricted_requests_per_min": 3,
                        "adaptive_rate_limit_suspicious_request_threshold": 2,
                        "adaptive_rate_limit_unique_paths_threshold": 2,
                    }
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(enable_adaptive.status_code, 200)

        self.client.get("/inspect/admin/login?username=a", headers={"User-Agent": "curl/8.0"})
        self.client.get("/inspect/admin/config?username=a", headers={"User-Agent": "curl/8.0"})

        report_response = self.client.get("/api/admin/settings/adaptive-rate-limit")
        self.assertEqual(report_response.status_code, 200)
        report = report_response.get_json()

        self.assertTrue(report["enabled"])
        self.assertEqual(report["policy"]["normal"]["requests_per_min"], 60)
        self.assertEqual(report["policy"]["elevated"]["requests_per_min"], 30)
        self.assertEqual(report["policy"]["suspicious"]["requests_per_min"], 10)
        self.assertEqual(report["policy"]["restricted"]["requests_per_min"], 3)
        self.assertIn("risk_thresholds", report["classifier"])
        self.assertIn("profile_counts", report["telemetry"])
        self.assertGreaterEqual(report["telemetry"]["suspicious_candidate_ips"], 1)

    def test_adaptive_rate_limiting_throttles_suspicious_ips_more_aggressively(self) -> None:
        self.login_as("admin", "Admin123!")

        enable_adaptive = self.client.patch(
            "/api/admin/settings",
            data=json.dumps(
                {
                    "settings": {
                        "adaptive_rate_limiting_enabled": True,
                        "adaptive_rate_limit_normal_requests_per_min": 60,
                        "adaptive_rate_limit_elevated_requests_per_min": 10,
                        "adaptive_rate_limit_suspicious_requests_per_min": 1,
                        "adaptive_rate_limit_restricted_requests_per_min": 1,
                        "adaptive_rate_limit_min_suspicion_score": 2,
                        "adaptive_rate_limit_suspicious_request_threshold": 1,
                        "adaptive_rate_limit_unique_paths_threshold": 2,
                    }
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(enable_adaptive.status_code, 200)

        first = self.client.get("/inspect/probe", headers={"User-Agent": "curl/8.0"})
        second = self.client.get("/inspect/probe", headers={"User-Agent": "curl/8.0"})
        third = self.client.get("/inspect/probe", headers={"User-Agent": "curl/8.0"})

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.get_json()["rate_limit"]["profile"], "normal")
        self.assertEqual(second.get_json()["rate_limit"]["profile"], "suspicious")
        self.assertEqual(second.get_json()["rate_limit"]["requests_per_min"], 1)
        self.assertEqual(second.get_json()["rate_limit"]["risk_band"], "high")
        self.assertEqual(third.status_code, 403)
        self.assertIn("ddos", third.get_json()["attack_types"])

    def test_risk_based_throttling_restricts_repeat_offenders_using_history(self) -> None:
        self.login_as("admin", "Admin123!")

        enable_adaptive = self.client.patch(
            "/api/admin/settings",
            data=json.dumps(
                {
                    "settings": {
                        "adaptive_rate_limiting_enabled": True,
                        "adaptive_rate_limit_normal_requests_per_min": 60,
                        "adaptive_rate_limit_elevated_requests_per_min": 12,
                        "adaptive_rate_limit_suspicious_requests_per_min": 3,
                        "adaptive_rate_limit_restricted_requests_per_min": 1,
                        "adaptive_rate_limit_min_suspicion_score": 2,
                        "adaptive_rate_limit_suspicious_request_threshold": 5,
                        "adaptive_rate_limit_unique_paths_threshold": 2,
                        "adaptive_rate_limit_block_ratio_threshold": 0.2,
                        "adaptive_rate_limit_flagged_ratio_threshold": 0.2,
                        "adaptive_rate_limit_avg_risk_threshold": 0.4,
                    }
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(enable_adaptive.status_code, 200)

        for _ in range(3):
            blocked = self.client.get("/protected?message=bad_keyword")
            self.assertEqual(blocked.status_code, 403)

        first_follow_up = self.client.get("/inspect/probe", headers={"User-Agent": "curl/8.0"})
        second_follow_up = self.client.get("/inspect/probe", headers={"User-Agent": "curl/8.0"})

        self.assertEqual(first_follow_up.status_code, 200)
        first_payload = first_follow_up.get_json()
        self.assertEqual(first_payload["rate_limit"]["profile"], "restricted")
        self.assertEqual(first_payload["rate_limit"]["requests_per_min"], 1)
        self.assertEqual(first_payload["rate_limit"]["risk_band"], "critical")
        self.assertGreaterEqual(first_payload["rate_limit"]["risk_score"], 4.0)

        self.assertEqual(second_follow_up.status_code, 403)
        self.assertIn("ddos", second_follow_up.get_json()["attack_types"])

    def test_security_scope_report_lists_builtins_and_custom_endpoint_policies(self) -> None:
        self.login_as("admin", "Admin123!")

        initial_report = self.client.get("/api/admin/security-scope")
        self.assertEqual(initial_report.status_code, 200)
        initial_payload = initial_report.get_json()
        self.assertTrue(initial_payload["ddos_protection"]["enabled"])
        self.assertIn("layer4_protection", initial_payload)
        self.assertEqual(initial_payload["layer4_protection"]["half_open_mode"], "application_approximation")
        self.assertIn("per_connection_throttling", initial_payload["layer4_protection"])
        self.assertIn("transport_awareness", initial_payload["layer4_protection"])
        self.assertIn("socket_proxy_controls", initial_payload["layer4_protection"])
        self.assertIn("volumetric_pre_app_filtering", initial_payload["layer4_protection"])
        self.assertTrue(initial_payload["layer4_protection"]["transport_awareness"]["enabled"])
        self.assertTrue(initial_payload["layer4_protection"]["volumetric_pre_app_filtering"]["enabled"])
        self.assertTrue(initial_payload["built_in_policies"])

        built_in_ids = {item["policy_id"] for item in initial_payload["built_in_policies"]}
        self.assertIn("builtin-login-surface", built_in_ids)
        self.assertIn("builtin-search-surface", built_in_ids)
        self.assertIn("builtin-admin-surface", built_in_ids)
        self.assertIn("builtin-public-api-surface", built_in_ids)

    def test_builtin_endpoint_profiles_cover_login_search_admin_and_public_api(self) -> None:
        policies = {item["policy_id"]: item for item in ep.default_endpoint_policies(settings)}

        login_policy = policies["builtin-login-surface"]
        search_policy = policies["builtin-search-surface"]
        admin_policy = policies["builtin-admin-surface"]
        public_policy = policies["builtin-public-api-surface"]
        exact_auth_policy = policies["builtin-auth-login"]

        self.assertEqual(login_policy["path_pattern"], "*/login*")
        self.assertEqual(search_policy["path_pattern"], "*/search*")
        self.assertEqual(admin_policy["path_pattern"], "*/admin*")
        self.assertEqual(public_policy["path_pattern"], "/api/public*")
        self.assertEqual(login_policy["settings"]["bucket_scope"], "ip_endpoint")
        self.assertEqual(search_policy["settings"]["bucket_scope"], "ip_endpoint")
        self.assertEqual(public_policy["settings"]["bucket_scope"], "ip_endpoint")
        self.assertLessEqual(exact_auth_policy["settings"]["requests_per_min"], login_policy["settings"]["requests_per_min"])
        self.assertLess(admin_policy["settings"]["requests_per_min"], public_policy["settings"]["requests_per_min"])
        self.assertNotEqual(search_policy["settings"]["requests_per_min"], policies["builtin-default"]["settings"]["requests_per_min"])

    def test_endpoint_policy_resolver_distinguishes_login_search_admin_and_public_api(self) -> None:
        login_policy = ep.resolve_endpoint_policy(SimpleNamespace(path="/login", method="POST", gateway_path="", remote_addr="127.0.0.1"), settings)
        auth_login_policy = ep.resolve_endpoint_policy(SimpleNamespace(path="/api/auth/login", method="POST", gateway_path="", remote_addr="127.0.0.1"), settings)
        search_policy = ep.resolve_endpoint_policy(SimpleNamespace(path="/search", method="GET", gateway_path="", remote_addr="127.0.0.1"), settings)
        admin_policy = ep.resolve_endpoint_policy(SimpleNamespace(path="/admin", method="GET", gateway_path="", remote_addr="127.0.0.1"), settings)
        public_policy = ep.resolve_endpoint_policy(SimpleNamespace(path="/api/public/items", method="GET", gateway_path="", remote_addr="127.0.0.1"), settings)

        self.assertEqual(login_policy["policy_id"], "builtin-login-surface")
        self.assertEqual(auth_login_policy["policy_id"], "builtin-auth-login")
        self.assertEqual(search_policy["policy_id"], "builtin-search-surface")
        self.assertEqual(admin_policy["policy_id"], "builtin-admin-surface")
        self.assertEqual(public_policy["policy_id"], "builtin-public-api-surface")

    def test_pre_app_volumetric_filter_blocks_before_pipeline_and_tracks_telemetry(self) -> None:
        self.login_as("admin", "Admin123!")

        update_settings = self.client.patch(
            "/api/admin/settings",
            data=json.dumps(
                {
                    "settings": {
                        "pre_app_filter_enabled": True,
                        "pre_app_filter_window_seconds": 30,
                        "pre_app_filter_ip_request_threshold": 2,
                        "pre_app_filter_ip_burst_threshold": 99,
                        "pre_app_filter_global_request_threshold": 999,
                        "pre_app_filter_ip_bytes_threshold": 1048576,
                        "pre_app_filter_block_ttl_seconds": 5,
                    }
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(update_settings.status_code, 200)

        summary_before = self.client.get("/api/dashboard/summary")
        self.assertEqual(summary_before.status_code, 200)
        total_before = summary_before.get_json()["total_requests"]

        first = self.client.get("/inspect/preapp-filter")
        second = self.client.get("/inspect/preapp-filter")
        blocked = self.client.get("/inspect/preapp-filter")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(blocked.status_code, 429)
        blocked_payload = blocked.get_json()
        self.assertTrue(blocked_payload["blocked_before_pipeline"])
        self.assertEqual(blocked_payload["layer"], "pre_app_volumetric_filter")
        self.assertIn("ddos", blocked_payload["attack_types"])
        self.assertEqual(blocked_payload["scope"], "ip_window")

        summary_after = self.client.get("/api/dashboard/summary")
        self.assertEqual(summary_after.status_code, 200)
        total_after = summary_after.get_json()["total_requests"]
        self.assertEqual(total_after - total_before, 2)

        report = self.client.get("/api/admin/security-scope")
        self.assertEqual(report.status_code, 200)
        pre_app_filter = report.get_json()["layer4_protection"]["volumetric_pre_app_filtering"]
        self.assertGreaterEqual(pre_app_filter["telemetry"]["blocked"], 1)
        self.assertGreaterEqual(pre_app_filter["telemetry"]["allowed"], 2)
        self.assertGreaterEqual(pre_app_filter["telemetry"]["active_ip_blocks"], 1)
        self.assertTrue(any(item["ip_address"] == "127.0.0.1" for item in pre_app_filter["telemetry"]["top_blocked_ips"]))

    def test_proxy_keepalive_abuse_forces_upstream_connection_close(self) -> None:
        self.login_as("admin", "Admin123!")

        update_settings = self.client.patch(
            "/api/admin/settings",
            data=json.dumps(
                {
                    "settings": {
                        "proxy_transport_controls_enabled": True,
                        "proxy_keepalive_abuse_protection_enabled": True,
                        "proxy_keepalive_monitor_score": 2,
                        "proxy_keepalive_block_score": 99,
                    }
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(update_settings.status_code, 200)

        response = self.client.get(
            "/proxy/api/keepalive-check",
            headers={
                "Connection": "keep-alive",
                "Keep-Alive": "timeout=30, max=100",
                "User-Agent": "curl/8.0",
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["proxy_connection_mode"], "close")
        self.assertEqual(payload["connection"].lower(), "close")

        report = self.client.get("/api/admin/security-scope")
        self.assertEqual(report.status_code, 200)
        proxy_controls = report.get_json()["layer4_protection"]["socket_proxy_controls"]
        self.assertTrue(proxy_controls["keepalive_abuse_protection_enabled"])
        self.assertGreaterEqual(proxy_controls["telemetry"]["keepalive_close_events"], 1)

    def test_proxy_upstream_pool_protection_blocks_when_concurrency_is_exhausted(self) -> None:
        self.login_as("admin", "Admin123!")

        update_settings = self.client.patch(
            "/api/admin/settings",
            data=json.dumps(
                {
                    "settings": {
                        "proxy_transport_controls_enabled": True,
                        "proxy_upstream_concurrency_limit": 1,
                    }
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(update_settings.status_code, 200)

        controller = self.app.config["PROXY_TRANSPORT"]
        runtime_settings = self.app.config["APP_SETTINGS"].with_overrides(
            **self.app.config["STORAGE"].get_runtime_setting_overrides()
        )
        acquired = controller.acquire_slot(runtime_settings)
        self.assertTrue(acquired)
        try:
            blocked = self.client.get("/proxy/api/pool-guard")
            self.assertEqual(blocked.status_code, 503)
            payload = blocked.get_json()
            self.assertIn("pool protection", payload["message"].lower())
        finally:
            controller.release_slot()

        report = self.client.get("/api/admin/security-scope")
        self.assertEqual(report.status_code, 200)
        proxy_controls = report.get_json()["layer4_protection"]["socket_proxy_controls"]
        self.assertGreaterEqual(proxy_controls["telemetry"]["pool_protection_blocks"], 1)

    def test_proxy_idle_recycle_refreshes_upstream_session_generation(self) -> None:
        self.login_as("admin", "Admin123!")

        update_settings = self.client.patch(
            "/api/admin/settings",
            data=json.dumps(
                {
                    "settings": {
                        "proxy_transport_controls_enabled": True,
                        "proxy_idle_pool_recycle_seconds": 1,
                    }
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(update_settings.status_code, 200)

        first = self.client.get("/proxy/api/recycle-check")
        self.assertEqual(first.status_code, 200)
        first_generation = int(first.get_json()["upstream_pool_generation"] or 0)

        time.sleep(1.2)

        second = self.client.get("/proxy/api/recycle-check")
        self.assertEqual(second.status_code, 200)
        second_generation = int(second.get_json()["upstream_pool_generation"] or 0)
        self.assertGreater(second_generation, first_generation)

        report = self.client.get("/api/admin/security-scope")
        self.assertEqual(report.status_code, 200)
        proxy_controls = report.get_json()["layer4_protection"]["socket_proxy_controls"]
        self.assertGreaterEqual(proxy_controls["telemetry"]["idle_recycles"], 1)

        create_policy = self.client.post(
            "/api/admin/security-scope/policies",
            data=json.dumps(
                {
                    "name": "Checkout API",
                    "path_pattern": "/inspect/checkout",
                    "methods": ["GET", "POST"],
                    "sensitivity": "protected",
                    "requests_per_min": 5,
                    "bucket_scope": "ip_endpoint",
                    "priority": 70,
                    "ddos_monitor_hits": 2,
                    "ddos_block_hits": 4,
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create_policy.status_code, 201)

        report = self.client.get("/api/admin/security-scope")
        self.assertEqual(report.status_code, 200)
        payload = report.get_json()
        self.assertTrue(any(item["name"] == "Checkout API" for item in payload["custom_policies"]))

    def test_connection_guard_blocks_high_concurrency_on_sensitive_endpoint(self) -> None:
        self.login_as("admin", "Admin123!")

        create_policy = self.client.post(
            "/api/admin/security-scope/policies",
            data=json.dumps(
                {
                    "name": "Socket Check",
                    "path_pattern": "/socket-check",
                    "methods": ["GET"],
                    "sensitivity": "critical",
                    "requests_per_min": 30,
                    "bucket_scope": "ip_endpoint",
                    "priority": 95,
                    "ddos_monitor_hits": 6,
                    "ddos_block_hits": 12,
                    "connection_monitor_active": 2,
                    "connection_block_active": 3,
                    "connection_burst_monitor": 3,
                    "connection_burst_block": 6,
                    "connection_stale_monitor": 2,
                    "connection_stale_block": 4,
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create_policy.status_code, 201)
        policy = create_policy.get_json()["policy"]

        tracker = self.app.config["CONNECTION_TRACKER"]
        runtime_settings = self.app.config["APP_SETTINGS"]
        held_request_ids = []
        try:
            for index in range(2):
                request_id = "held-{0}".format(index)
                tracker.register(
                    SimpleNamespace(
                        request_id=request_id,
                        remote_addr="127.0.0.1",
                        path="/socket-check",
                    ),
                    policy,
                    runtime_settings,
                )
                held_request_ids.append(request_id)

            blocked = self.client.get("/inspect/socket-check")
            self.assertEqual(blocked.status_code, 403)
            blocked_payload = blocked.get_json()
            self.assertIn("ddos", blocked_payload["attack_types"])
            self.assertTrue(any("Connection guard blocked" in reason for reason in blocked_payload["reasons"]))
        finally:
            for request_id in held_request_ids:
                tracker.release(request_id)

    def test_connection_guard_blocks_new_connections_per_second_burst(self) -> None:
        self.login_as("admin", "Admin123!")

        update_settings = self.client.patch(
            "/api/admin/settings",
            data=json.dumps(
                {
                    "settings": {
                        "connection_monitor_per_ip_threshold": 99,
                        "connection_block_per_ip_threshold": 999,
                        "connection_monitor_active_threshold": 99,
                        "connection_block_active_threshold": 999,
                        "connection_monitor_burst_threshold": 99,
                        "connection_block_burst_threshold": 999,
                        "connection_monitor_stale_threshold": 99,
                        "connection_block_stale_threshold": 999,
                        "connection_monitor_sessions_per_source": 99,
                        "connection_block_sessions_per_source": 999,
                        "connection_monitor_new_connections_per_second": 2,
                        "connection_block_new_connections_per_second": 3,
                    }
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(update_settings.status_code, 200)

        first = self.client.get("/inspect/connection-spike")
        second = self.client.get("/inspect/connection-spike")
        third = self.client.get("/inspect/connection-spike")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(third.status_code, 403)
        payload = third.get_json()
        self.assertIn("ddos", payload["attack_types"])
        self.assertTrue(any("new connections/sec" in reason for reason in payload["reasons"]))

    def test_connection_guard_blocks_concurrent_sessions_per_source(self) -> None:
        self.login_as("admin", "Admin123!")

        update_settings = self.client.patch(
            "/api/admin/settings",
            data=json.dumps(
                {
                    "settings": {
                        "connection_monitor_per_ip_threshold": 99,
                        "connection_block_per_ip_threshold": 999,
                        "connection_monitor_active_threshold": 99,
                        "connection_block_active_threshold": 999,
                        "connection_monitor_burst_threshold": 99,
                        "connection_block_burst_threshold": 999,
                        "connection_monitor_stale_threshold": 99,
                        "connection_block_stale_threshold": 999,
                        "connection_monitor_new_connections_per_second": 99,
                        "connection_block_new_connections_per_second": 999,
                        "connection_monitor_sessions_per_source": 2,
                        "connection_block_sessions_per_source": 3,
                    }
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(update_settings.status_code, 200)

        tracker = self.app.config["CONNECTION_TRACKER"]
        runtime_settings = self.app.config["APP_SETTINGS"].with_overrides(
            **self.app.config["STORAGE"].get_runtime_setting_overrides()
        )
        endpoint_policy = {
            "policy_id": "builtin-default",
            "name": "Default Gateway Scope",
            "bucket_scope": "ip",
            "matched_path": "/session-source",
            "settings": {},
        }
        held_request_ids = []
        try:
            for index, session_id in enumerate(("s1", "s2"), start=1):
                request_id = "session-held-{0}".format(index)
                tracker.register(
                    SimpleNamespace(
                        request_id=request_id,
                        remote_addr="127.0.0.1",
                        path="/session-source",
                        session_id=session_id,
                        user_agent="unit-test",
                    ),
                    endpoint_policy,
                    runtime_settings,
                )
                held_request_ids.append(request_id)

            blocked = self.client.get("/inspect/session-source", headers={"X-Session-ID": "s3"})
            self.assertEqual(blocked.status_code, 403)
            payload = blocked.get_json()
            self.assertIn("ddos", payload["attack_types"])
            self.assertTrue(any("concurrent sessions" in reason.lower() for reason in payload["reasons"]))
        finally:
            for request_id in held_request_ids:
                tracker.release(request_id)

    def test_proxy_enriched_syn_flags_trigger_transport_awareness_blocking(self) -> None:
        self.login_as("admin", "Admin123!")

        enable_transport = self.client.patch(
            "/api/admin/settings",
            data=json.dumps(
                {
                    "settings": {
                        "transport_awareness_enabled": True,
                        "transport_syn_monitor_burst_threshold": 2,
                        "transport_syn_block_burst_threshold": 3,
                    }
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(enable_transport.status_code, 200)

        headers = {
            "X-WAF-Transport-Protocol": "tcp",
            "X-TCP-Flags": "SYN",
            "Connection": "close",
            "User-Agent": "transport-probe/1.0",
        }
        first = self.client.get("/inspect/transport-syn", headers=headers)
        second = self.client.get("/inspect/transport-syn", headers=headers)
        third = self.client.get("/inspect/transport-syn", headers=headers)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(third.status_code, 403)
        third_payload = third.get_json()
        self.assertIn("ddos", third_payload["attack_types"])
        self.assertTrue(any("SYN-like" in reason for reason in third_payload["reasons"]))

        report = self.client.get("/api/admin/security-scope")
        self.assertEqual(report.status_code, 200)
        transport_awareness = report.get_json()["layer4_protection"]["transport_awareness"]
        self.assertGreaterEqual(transport_awareness["telemetry"]["syn_like_events"], 1)
        self.assertGreaterEqual(transport_awareness["telemetry"]["transport_enriched_requests"], 1)

    def test_connection_churn_transport_detection_blocks_high_churn_patterns(self) -> None:
        self.login_as("admin", "Admin123!")

        enable_transport = self.client.patch(
            "/api/admin/settings",
            data=json.dumps(
                {
                    "settings": {
                        "transport_awareness_enabled": True,
                        "transport_syn_monitor_burst_threshold": 99,
                        "transport_syn_block_burst_threshold": 999,
                        "transport_reset_monitor_stale_threshold": 99,
                        "transport_reset_block_stale_threshold": 999,
                        "transport_abnormal_session_monitor_score": 99,
                        "transport_abnormal_session_block_score": 999,
                        "transport_udp_monitor_burst_threshold": 99,
                        "transport_udp_block_burst_threshold": 999,
                        "transport_churn_monitor_ratio": 2.0,
                        "transport_churn_block_ratio": 3.0,
                        "transport_short_lived_monitor_score": 99,
                        "transport_short_lived_block_score": 999,
                        "transport_retry_monitor_score": 99,
                        "transport_retry_block_score": 999,
                        "transport_malformed_monitor_score": 99,
                        "transport_malformed_block_score": 999,
                    }
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(enable_transport.status_code, 200)

        headers = {
            "Connection": "close",
            "User-Agent": "transport-probe/1.0",
        }
        first = self.client.get("/inspect/transport-churn", headers=headers)
        second = self.client.get("/inspect/transport-churn", headers=headers)
        third = self.client.get("/inspect/transport-churn", headers=headers)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(third.status_code, 403)
        third_payload = third.get_json()
        self.assertIn("ddos", third_payload["attack_types"])
        self.assertTrue(any("Connection churn" in reason for reason in third_payload["reasons"]))

        report = self.client.get("/api/admin/security-scope")
        self.assertEqual(report.status_code, 200)
        transport_awareness = report.get_json()["layer4_protection"]["transport_awareness"]
        self.assertGreaterEqual(transport_awareness["telemetry"]["connection_churn_events"], 1)

    def test_proxy_enriched_retry_timeout_and_short_lived_transport_blocking(self) -> None:
        self.login_as("admin", "Admin123!")

        enable_transport = self.client.patch(
            "/api/admin/settings",
            data=json.dumps(
                {
                    "settings": {
                        "transport_awareness_enabled": True,
                        "transport_syn_monitor_burst_threshold": 99,
                        "transport_syn_block_burst_threshold": 999,
                        "transport_reset_monitor_stale_threshold": 99,
                        "transport_reset_block_stale_threshold": 999,
                        "transport_abnormal_session_monitor_score": 99,
                        "transport_abnormal_session_block_score": 999,
                        "transport_udp_monitor_burst_threshold": 99,
                        "transport_udp_block_burst_threshold": 999,
                        "transport_churn_monitor_ratio": 99.0,
                        "transport_churn_block_ratio": 999.0,
                        "transport_short_lived_duration_ms_threshold": 250,
                        "transport_short_lived_monitor_score": 3,
                        "transport_short_lived_block_score": 5,
                        "transport_retry_monitor_score": 3,
                        "transport_retry_block_score": 5,
                        "transport_malformed_monitor_score": 99,
                        "transport_malformed_block_score": 999,
                    }
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(enable_transport.status_code, 200)

        headers = {
            "X-WAF-Transport-Protocol": "tcp",
            "X-WAF-Connection-Duration-Ms": "80",
            "X-WAF-Retry-Count": "3",
            "X-WAF-Upstream-Timeout": "true",
            "X-WAF-Session-Established": "false",
            "Connection": "close",
            "User-Agent": "curl/8.0",
        }
        blocked = self.client.get("/inspect/transport-retry", headers=headers)

        self.assertEqual(blocked.status_code, 403)
        payload = blocked.get_json()
        self.assertIn("anomaly", payload["attack_types"])
        self.assertTrue(
            any("Short-lived" in reason or "retries/timeouts" in reason for reason in payload["reasons"])
        )

        report = self.client.get("/api/admin/security-scope")
        self.assertEqual(report.status_code, 200)
        transport_awareness = report.get_json()["layer4_protection"]["transport_awareness"]
        self.assertGreaterEqual(transport_awareness["telemetry"]["short_lived_abusive_events"], 1)
        self.assertGreaterEqual(transport_awareness["telemetry"]["retry_timeout_events"], 1)
        self.assertGreaterEqual(transport_awareness["telemetry"]["transport_enriched_requests"], 1)

    def test_proxy_enriched_malformed_transport_behavior_blocks(self) -> None:
        self.login_as("admin", "Admin123!")

        enable_transport = self.client.patch(
            "/api/admin/settings",
            data=json.dumps(
                {
                    "settings": {
                        "transport_awareness_enabled": True,
                        "transport_syn_monitor_burst_threshold": 99,
                        "transport_syn_block_burst_threshold": 999,
                        "transport_reset_monitor_stale_threshold": 99,
                        "transport_reset_block_stale_threshold": 999,
                        "transport_abnormal_session_monitor_score": 99,
                        "transport_abnormal_session_block_score": 999,
                        "transport_udp_monitor_burst_threshold": 99,
                        "transport_udp_block_burst_threshold": 999,
                        "transport_churn_monitor_ratio": 99.0,
                        "transport_churn_block_ratio": 999.0,
                        "transport_short_lived_monitor_score": 99,
                        "transport_short_lived_block_score": 999,
                        "transport_retry_monitor_score": 99,
                        "transport_retry_block_score": 999,
                        "transport_malformed_monitor_score": 2,
                        "transport_malformed_block_score": 4,
                    }
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(enable_transport.status_code, 200)

        headers = {
            "X-WAF-Transport-Protocol": "udp",
            "X-TCP-Flags": "SYN FIN",
            "X-WAF-Connection-Duration-Ms": "broken",
            "X-WAF-Retry-Count": "-1",
            "X-WAF-Transport-Valid": "maybe",
            "X-WAF-Malformed-Transport": "true",
            "X-WAF-Session-Established": "true",
            "X-WAF-Connection-Reset": "true",
            "User-Agent": "transport-probe/1.0",
        }
        blocked = self.client.get("/inspect/transport-malformed", headers=headers)

        self.assertEqual(blocked.status_code, 403)
        payload = blocked.get_json()
        self.assertIn("anomaly", payload["attack_types"])
        self.assertTrue(any("Malformed" in reason for reason in payload["reasons"]))

        report = self.client.get("/api/admin/security-scope")
        self.assertEqual(report.status_code, 200)
        transport_awareness = report.get_json()["layer4_protection"]["transport_awareness"]
        self.assertGreaterEqual(transport_awareness["telemetry"]["malformed_transport_events"], 1)
        self.assertGreaterEqual(transport_awareness["telemetry"]["transport_enriched_requests"], 1)

    def test_endpoint_specific_policy_throttles_only_the_targeted_path_scope(self) -> None:
        self.login_as("admin", "Admin123!")

        create_policy = self.client.post(
            "/api/admin/security-scope/policies",
            data=json.dumps(
                {
                    "name": "Tight Probe Policy",
                    "path_pattern": "/inspect/limited",
                    "methods": ["GET"],
                    "sensitivity": "critical",
                    "requests_per_min": 1,
                    "bucket_scope": "ip_endpoint",
                    "priority": 90,
                    "ddos_monitor_hits": 1,
                    "ddos_block_hits": 2,
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create_policy.status_code, 201)

        first = self.client.get("/inspect/limited")
        second = self.client.get("/inspect/limited")
        third = self.client.get("/inspect/open")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.get_json()["endpoint_policy"]["name"], "Tight Probe Policy")
        self.assertEqual(first.get_json()["rate_limit"]["scope"], "ip_endpoint")
        self.assertEqual(second.status_code, 403)
        self.assertIn("ddos", second.get_json()["attack_types"])
        self.assertEqual(third.status_code, 200)
        self.assertNotEqual(third.get_json()["endpoint_policy"]["name"], "Tight Probe Policy")

    def test_dynamic_threshold_report_uses_avg_plus_stddev(self) -> None:
        self.login_as("admin", "Admin123!")

        enable_dynamic = self.client.patch(
            "/api/admin/settings",
            data=json.dumps({"settings": {"dynamic_thresholds_enabled": True, "block_threshold": 0.9}}),
            content_type="application/json",
        )
        self.assertEqual(enable_dynamic.status_code, 200)

        for message in ("alpha", "beta", "gamma", "delta", "epsilon", "zeta"):
            self.client.get("/protected?message={0}".format(message))

        report_response = self.client.get("/api/admin/settings/dynamic-thresholds")
        self.assertEqual(report_response.status_code, 200)
        report = report_response.get_json()

        self.assertTrue(report["enabled"])
        self.assertTrue(report["active"])
        expected_raw = report["telemetry"]["avg_risk_score"] + (
            report["telemetry"]["stddev_risk_score"] * report["formula"]["std_multiplier"]
        )
        expected_clamped = min(max(expected_raw, report["targets"]["min_block_threshold"]), report["targets"]["max_block_threshold"])
        self.assertAlmostEqual(report["computed"]["clamped_block_threshold"], round(expected_clamped, 4), places=3)
        self.assertAlmostEqual(report["effective"]["block_threshold"], report["computed"]["clamped_block_threshold"], places=3)

    def test_dynamic_thresholds_can_promote_monitor_to_block(self) -> None:
        runtime_settings = settings.with_overrides(
            block_threshold=0.95,
            monitor_threshold=0.48,
            dynamic_thresholds_enabled=True,
            dynamic_thresholds_std_multiplier=1.0,
            dynamic_thresholds_min_samples=6,
            dynamic_thresholds_min_block_threshold=0.32,
            dynamic_thresholds_max_block_threshold=0.92,
        )
        dynamic_report = dt.analyze_dynamic_thresholds(
            runtime_settings,
            {
                "total_requests": 6,
                "blocked_requests": 0,
                "monitored_requests": 1,
                "allowed_requests": 5,
                "avg_risk_score": 0.28,
                "stddev_risk_score": 0.08,
                "min_risk_score": 0.18,
                "max_risk_score": 0.41,
            },
        )
        rule_result = SimpleNamespace(should_block=False, should_monitor=False, reasons=[], attack_types=[])
        score_result = SimpleNamespace(score=0.55, model_name="unit", model_version="unit-v1")
        history_snapshot = SimpleNamespace()

        static_decision = mi.decide_action(rule_result, score_result, history_snapshot, runtime_settings)
        dynamic_decision = mi.decide_action(
            rule_result,
            score_result,
            history_snapshot,
            runtime_settings,
            dynamic_threshold_report=dynamic_report,
        )

        self.assertEqual(static_decision.action, "monitor")
        self.assertEqual(dynamic_decision.action, "block")
        self.assertTrue(str(dynamic_decision.threshold_mode).startswith("dynamic"))
        self.assertLess(dynamic_decision.block_threshold_used, runtime_settings.block_threshold)

    def test_dynamic_thresholds_respect_endpoint_scope_and_reduce_false_positives(self) -> None:
        runtime_settings = settings.with_overrides(
            block_threshold=0.78,
            monitor_threshold=0.52,
            dynamic_thresholds_enabled=True,
            dynamic_thresholds_std_multiplier=1.0,
            dynamic_thresholds_min_samples=6,
            auto_tuning_target_false_positive_rate=0.12,
        )
        endpoint_policy = {
            "policy_id": "builtin-auth-login",
            "name": "Authentication Login",
            "matched_path": "/api/auth/login",
            "sensitivity": "critical",
            "requests_per_min": 6,
            "block_threshold": 0.72,
            "monitor_threshold": 0.48,
        }

        report = dt.analyze_dynamic_thresholds(
            runtime_settings,
            {
                "scope": "endpoint",
                "matched_path": "/api/auth/login",
                "endpoint_policy_id": "builtin-auth-login",
                "endpoint_policy_name": "Authentication Login",
                "endpoint_sensitivity": "critical",
                "target_requests_per_min": 6,
                "total_requests": 12,
                "blocked_requests": 1,
                "monitored_requests": 2,
                "allowed_requests": 9,
                "benign_labeled": 6,
                "benign_false_positive_count": 3,
                "false_positive_rate": 0.5,
                "flagged_ratio": 0.25,
                "request_rate_per_second": 0.2,
                "requests_per_minute": 12.0,
                "avg_risk_score": 0.31,
                "stddev_risk_score": 0.06,
                "min_risk_score": 0.18,
                "max_risk_score": 0.54,
            },
            endpoint_policy=endpoint_policy,
        )

        self.assertTrue(report["active"])
        self.assertEqual(report["telemetry"]["scope"], "endpoint")
        self.assertEqual(report["telemetry"]["endpoint_policy_name"], "Authentication Login")
        self.assertGreater(report["formula"]["false_positive_relief"], 0.0)
        self.assertLess(report["formula"]["sensitivity_adjustment"], 0.0)
        self.assertLess(report["effective"]["block_threshold"], runtime_settings.block_threshold)
        self.assertIn("false-positive rate", " ".join(report["reasons"]).lower())

    def test_dynamic_thresholds_harden_under_endpoint_load(self) -> None:
        runtime_settings = settings.with_overrides(
            block_threshold=0.78,
            monitor_threshold=0.52,
            dynamic_thresholds_enabled=True,
            dynamic_thresholds_std_multiplier=1.0,
            dynamic_thresholds_min_samples=6,
        )
        endpoint_policy = {
            "policy_id": "builtin-auth-login",
            "name": "Authentication Login",
            "matched_path": "/api/auth/login",
            "sensitivity": "protected",
            "requests_per_min": 8,
            "block_threshold": 0.74,
            "monitor_threshold": 0.50,
        }

        baseline_report = dt.analyze_dynamic_thresholds(
            runtime_settings,
            {
                "scope": "endpoint",
                "matched_path": "/api/auth/login",
                "endpoint_policy_id": "builtin-auth-login",
                "endpoint_policy_name": "Authentication Login",
                "endpoint_sensitivity": "protected",
                "target_requests_per_min": 8,
                "total_requests": 12,
                "blocked_requests": 1,
                "monitored_requests": 1,
                "allowed_requests": 10,
                "benign_labeled": 4,
                "benign_false_positive_count": 0,
                "false_positive_rate": 0.0,
                "flagged_ratio": 0.10,
                "request_rate_per_second": 0.1,
                "requests_per_minute": 4.0,
                "avg_risk_score": 0.36,
                "stddev_risk_score": 0.05,
                "min_risk_score": 0.2,
                "max_risk_score": 0.58,
            },
            endpoint_policy=endpoint_policy,
        )
        loaded_report = dt.analyze_dynamic_thresholds(
            runtime_settings,
            {
                "scope": "endpoint",
                "matched_path": "/api/auth/login",
                "endpoint_policy_id": "builtin-auth-login",
                "endpoint_policy_name": "Authentication Login",
                "endpoint_sensitivity": "protected",
                "target_requests_per_min": 8,
                "total_requests": 12,
                "blocked_requests": 2,
                "monitored_requests": 3,
                "allowed_requests": 7,
                "benign_labeled": 4,
                "benign_false_positive_count": 0,
                "false_positive_rate": 0.0,
                "flagged_ratio": 0.35,
                "request_rate_per_second": 0.25,
                "requests_per_minute": 18.0,
                "avg_risk_score": 0.36,
                "stddev_risk_score": 0.05,
                "min_risk_score": 0.2,
                "max_risk_score": 0.62,
            },
            endpoint_policy=endpoint_policy,
        )

        self.assertTrue(baseline_report["active"])
        self.assertTrue(loaded_report["active"])
        self.assertLess(loaded_report["formula"]["load_adjustment"], 0.0)
        self.assertLess(
            loaded_report["effective"]["block_threshold"],
            baseline_report["effective"]["block_threshold"],
        )
        self.assertGreater(
            loaded_report["telemetry"]["requests_per_minute"],
            baseline_report["telemetry"]["requests_per_minute"],
        )

    def test_progressive_blocking_hardens_repeat_offenders(self) -> None:
        runtime_settings = settings.with_overrides(
            block_threshold=0.78,
            monitor_threshold=0.56,
        )
        rule_result = SimpleNamespace(should_block=False, should_monitor=False, reasons=[], attack_types=[], severity=0.0, matched_rules=[])
        score_result = SimpleNamespace(score=0.74, model_name="unit", model_version="unit-v1")
        history_snapshot = SimpleNamespace(
            ip_request_count_window=8,
            ip_block_count_window=2,
            ip_monitor_count_window=3,
            session_request_count_window=3,
            fingerprint_reuse_count=4,
            path_hits_window=4,
            unique_paths_window=2,
            ip_block_ratio=0.4,
            ip_flagged_ratio=0.625,
        )

        decision = mi.decide_action(rule_result, score_result, history_snapshot, runtime_settings)

        self.assertEqual(decision.action, "block")
        self.assertEqual(decision.progressive_stage, "repeat_offender")
        self.assertEqual(decision.threshold_mode, "progressive")
        self.assertLess(decision.block_threshold_used, runtime_settings.block_threshold)

    def test_attack_simulation_suite_api_runs_and_updates_dashboard(self) -> None:
        self.login_as("analyst", "Analyst123!")

        run_response = self.client.post(
            "/api/simulations/attack-suite",
            data=json.dumps({"profile": "quick"}),
            content_type="application/json",
        )
        self.assertEqual(run_response.status_code, 201)
        run_payload = run_response.get_json()
        self.assertEqual(run_payload["profile"], "quick")
        self.assertGreater(run_payload["total_requests"], 0)
        self.assertTrue(run_payload["families"])
        self.assertIn("summary", run_payload)
        self.assertGreater(run_payload["summary"]["families_exercised"], 0)
        self.assertEqual(run_payload["summary"]["supported_attack_families"], len(ATTACK_FAMILIES))
        self.assertEqual(run_payload["summary"]["attack_families_exercised"], len(ATTACK_FAMILIES))
        self.assertIn("control_traffic", run_payload)
        self.assertGreater(run_payload["control_traffic"]["sent"], 0)
        self.assertEqual(
            run_payload["summary"]["blocked"] + run_payload["summary"]["monitored"] + run_payload["summary"]["allowed"],
            run_payload["total_requests"],
        )
        self.assertNotIn("benign", {item["attack_type"] for item in run_payload["families"]})
        self.assertEqual(
            {item["attack_type"] for item in run_payload["families"]},
            {family.attack_type for family in ATTACK_FAMILIES},
        )

        latest_response = self.client.get("/api/simulations/attack-suite")
        self.assertEqual(latest_response.status_code, 200)
        latest_payload = latest_response.get_json()
        self.assertEqual(latest_payload["run_id"], run_payload["run_id"])

        dashboard_summary = self.client.get("/api/dashboard/summary")
        self.assertEqual(dashboard_summary.status_code, 200)
        summary_payload = dashboard_summary.get_json()
        self.assertIn("simulation", summary_payload)
        self.assertIsNotNone(summary_payload["simulation"])
        self.assertEqual(summary_payload["simulation"]["run_id"], run_payload["run_id"])
        self.assertEqual(summary_payload["total_requests"], 0)
        self.assertEqual(sum(item["count"] for item in summary_payload["top_attack_types"]), 0)
        self.assertGreater(sum(item["count"] for item in run_payload.get("observed_attack_types", [])), 0)
        request_listing = self.client.get("/api/requests?page=1&page_size=5").get_json()
        self.assertEqual(request_listing["pagination"]["total"], 0)
        self.assertTrue(
            any(item["id"] == "attack-simulation" for item in summary_payload.get("notifications", [])),
            "Expected the dashboard notifications to include the attack simulation status.",
        )

        self.client.post("/protected", data="union select password from users", content_type="text/plain")
        live_summary = self.client.get("/api/dashboard/summary").get_json()
        live_attacks = {item["attack_type"]: item["count"] for item in live_summary["top_attack_types"]}
        self.assertGreater(live_attacks.get("sql_injection", 0), 0)

    def test_notifications_endpoint_tracks_command_activity(self) -> None:
        benign_response = self.client.get("/protected?message=notify-me")
        request_id = benign_response.get_json()["request_id"]
        self.login_as("analyst", "Analyst123!")

        label_response = self.client.post(
            "/api/requests/{0}/label".format(request_id),
            data=json.dumps({"label": "needs_review", "notes": "notification test"}),
            content_type="application/json",
        )
        self.assertEqual(label_response.status_code, 200)

        notifications = self.client.get("/api/dashboard/notifications?limit=12")
        self.assertEqual(notifications.status_code, 200)
        payload = notifications.get_json()
        self.assertIn("counts", payload)
        self.assertIn("by_category", payload["counts"])
        self.assertGreaterEqual(payload["counts"]["by_category"].get("command", 0), 1)
        self.assertTrue(
            any(item.get("action") == "request.label" and item.get("request_id") == request_id for item in payload["notifications"]),
            "Expected a command notification tied to the label action.",
        )

    def test_repeated_failed_auth_is_counted_as_brute_force(self) -> None:
        last_failure = None
        for _ in range(3):
            last_failure = self.client.post(
                "/api/auth/login",
                data=json.dumps({"username": "admin", "password": "WrongPassword!"}),
                content_type="application/json",
            )
            self.assertIn(last_failure.status_code, {401, 429})

        failure_payload = last_failure.get_json()
        self.assertIn(failure_payload["message"], {"Invalid credentials", "Authentication temporarily blocked by the AI-based WAF"})
        self.assertIn("request_id", failure_payload)
        self.assertGreaterEqual(failure_payload.get("failed_attempts_window", 0), 3)
        self.assertIn("brute_force", failure_payload.get("attack_types", []))

        self.login_as("admin", "Admin123!")
        summary = self.client.get("/api/dashboard/summary")
        self.assertEqual(summary.status_code, 200)
        attack_rows = {item["attack_type"]: item for item in summary.get_json()["top_attack_types"]}
        self.assertGreater(attack_rows["brute_force"]["count"], 0)

    def test_api_only_mode_redirects_dashboard_and_supports_cors(self) -> None:
        api_only_app = create_api_app(
            settings.with_overrides(
                db_path=Path(self.temp_dir.name) / "api-only.sqlite3",
                backend_base_url="http://127.0.0.1:{0}".format(self.backend.port),
                frontend_public_url="http://127.0.0.1:5173",
            )
        )
        api_only_app.testing = True
        api_client = api_only_app.test_client()

        home = api_client.get("/")
        self.assertEqual(home.status_code, 200)
        self.assertEqual(home.get_json()["mode"], "api-only")

        dashboard_redirect = api_client.get("/dashboard/")
        self.assertIn(dashboard_redirect.status_code, {302, 308})
        self.assertIn("http://127.0.0.1:5173", dashboard_redirect.headers["Location"])

        login = api_client.post(
            "/api/auth/login",
            data=json.dumps({"username": "admin", "password": "Admin123!"}),
            content_type="application/json",
            headers={"Origin": "http://127.0.0.1:5173"},
        )
        self.assertEqual(login.status_code, 200)
        self.assertEqual(login.headers.get("Access-Control-Allow-Origin"), "http://127.0.0.1:5173")


if __name__ == "__main__":
    unittest.main()
