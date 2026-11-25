"""Framework-agnostic HTTP/JSON API controller + Flask Blueprint adapter.

Member 1 (Backend Development) can mount `create_backup_blueprint(service, get_actor)`
directly inside the main Flask application with zero rewriting of backup logic.
All handlers validate inputs, enforce deny-by-default authorization, and return
safe structured error payloads without leaking secrets or tracebacks (Project 04 T06).
"""

from __future__ import annotations

import base64
from typing import Any, Callable

from .exceptions import BackupRecoveryError, ValidationError
from .models import ActorContext
from .service import BackupRecoveryService, new_id


class BackupAPIController:
    """Pure-Python JSON controller decoupling API contracts from Flask."""

    def __init__(self, service: BackupRecoveryService) -> None:
        self.service = service

    @staticmethod
    def _ok(data: Any, *, correlation_id: str, status_code: int = 200) -> tuple[int, dict[str, Any]]:
        return status_code, {
            "ok": True,
            "correlation_id": correlation_id,
            "data": data,
        }

    def _handle_exception(
        self,
        exc: Exception,
        *,
        correlation_id: str,
        actor: ActorContext | None,
        action: str,
        student_id: str | None = None,
        file_id: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        if isinstance(exc, BackupRecoveryError):
            corr = exc.correlation_id or correlation_id
            return exc.http_status, {
                "ok": False,
                "correlation_id": corr,
                "error": {
                    "code": exc.error_code,
                    "message": exc.safe_message,
                },
            }

        # Controlled unexpected error path (Project 04 T06): never expose stack trace or secrets
        self.service.logger.log_event(
            event_type="UNEXPECTED_ERROR",
            outcome="ERROR",
            correlation_id=correlation_id,
            actor_id=actor.actor_id if actor else "anonymous",
            student_id=student_id,
            file_id=file_id,
            details={
                "action": action,
                "exception_class": type(exc).__name__,
            },
        )
        return 500, {
            "ok": False,
            "correlation_id": correlation_id,
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected internal error occurred. Reference correlation_id for support.",
            },
        }

    def handle_status(self, *, correlation_id: str | None = None) -> tuple[int, dict[str, Any]]:
        corr = correlation_id or new_id("corr")
        try:
            return self._ok(self.service.get_system_readiness(), correlation_id=corr)
        except Exception as exc:
            return self._handle_exception(exc, correlation_id=corr, actor=None, action="status")

    def handle_dashboard(
        self, actor: ActorContext, *, student_id: str, correlation_id: str | None = None
    ) -> tuple[int, dict[str, Any]]:
        corr = correlation_id or new_id("corr")
        try:
            data = self.service.get_dashboard_summary(actor, student_id=student_id, correlation_id=corr)
            return self._ok(data, correlation_id=corr)
        except Exception as exc:
            return self._handle_exception(
                exc, correlation_id=corr, actor=actor, action="dashboard", student_id=student_id
            )

    def handle_list_files(
        self, actor: ActorContext, *, student_id: str, correlation_id: str | None = None
    ) -> tuple[int, dict[str, Any]]:
        corr = correlation_id or new_id("corr")
        try:
            files = self.service.list_student_files(actor, student_id=student_id, correlation_id=corr)
            return self._ok({"files": [f.to_dict() for f in files]}, correlation_id=corr)
        except Exception as exc:
            return self._handle_exception(
                exc, correlation_id=corr, actor=actor, action="list_files", student_id=student_id
            )

    def handle_upload(
        self,
        actor: ActorContext,
        *,
        payload: dict[str, Any],
        file_bytes: bytes | None = None,
        correlation_id: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        corr = correlation_id or new_id("corr")
        student_id = str(payload.get("student_id") or actor.actor_id)
        try:
            filename = payload.get("filename")
            if not isinstance(filename, str) or not filename.strip():
                raise ValidationError("Missing required field 'filename'.")

            content = file_bytes
            if content is None:
                b64 = payload.get("content_b64")
                if not isinstance(b64, str):
                    raise ValidationError("Provide uploaded file bytes or 'content_b64'.")
                try:
                    content = base64.b64decode(b64, validate=True)
                except Exception as exc:
                    raise ValidationError("Invalid base64 encoding in 'content_b64'.") from exc

            res = self.service.register_and_backup_upload(
                actor,
                student_id=student_id,
                filename=filename,
                content=content,
                relative_path=payload.get("relative_path"),
                file_id=payload.get("file_id"),
                mime_type=str(payload.get("mime_type") or "application/octet-stream"),
                correlation_id=corr,
            )
            return self._ok(res.to_dict(), correlation_id=corr, status_code=201)
        except Exception as exc:
            return self._handle_exception(
                exc, correlation_id=corr, actor=actor, action="upload", student_id=student_id
            )

    def handle_create_backup(
        self,
        actor: ActorContext,
        *,
        payload: dict[str, Any],
        correlation_id: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        corr = correlation_id or new_id("corr")
        file_id = str(payload.get("file_id") or "")
        try:
            if not file_id:
                raise ValidationError("Missing required field 'file_id'.")
            trigger_reason = str(payload.get("trigger_reason") or "manual")
            force = payload.get("force")
            res = self.service.create_backup(
                actor,
                file_id=file_id,
                trigger_reason=trigger_reason,
                force=bool(force) if force is not None else None,
                correlation_id=corr,
            )
            return self._ok(res.to_dict(), correlation_id=corr, status_code=201 if res.created else 200)
        except Exception as exc:
            return self._handle_exception(
                exc, correlation_id=corr, actor=actor, action="create_backup", file_id=file_id or None
            )

    def handle_update_file(
        self,
        actor: ActorContext,
        *,
        file_id: str,
        file_bytes: bytes,
        correlation_id: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        corr = correlation_id or new_id("corr")
        try:
            res = self.service.update_file_with_auto_backup(
                actor, file_id=file_id, new_content=file_bytes, correlation_id=corr
            )
            return self._ok(res.to_dict(), correlation_id=corr)
        except Exception as exc:
            return self._handle_exception(
                exc, correlation_id=corr, actor=actor, action="update_file", file_id=file_id
            )

    def handle_list_versions(
        self,
        actor: ActorContext,
        *,
        file_id: str,
        include_pruned: bool = False,
        correlation_id: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        corr = correlation_id or new_id("corr")
        try:
            versions = self.service.list_file_versions(
                actor, file_id=file_id, include_pruned=include_pruned, correlation_id=corr
            )
            return self._ok(
                {"file_id": file_id, "versions": [v.to_dict() for v in versions]},
                correlation_id=corr,
            )
        except Exception as exc:
            return self._handle_exception(
                exc, correlation_id=corr, actor=actor, action="list_versions", file_id=file_id
            )

    def handle_pin_version(
        self,
        actor: ActorContext,
        *,
        file_id: str,
        version_id: str,
        pinned: bool = True,
        correlation_id: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        corr = correlation_id or new_id("corr")
        try:
            ver = self.service.pin_version(
                actor, file_id=file_id, version_id=version_id, pinned=pinned, correlation_id=corr
            )
            return self._ok({"version": ver.to_dict()}, correlation_id=corr)
        except Exception as exc:
            return self._handle_exception(
                exc, correlation_id=corr, actor=actor, action="pin_version", file_id=file_id
            )

    def handle_backup_history(
        self,
        actor: ActorContext,
        *,
        student_id: str,
        limit: int = 100,
        correlation_id: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        corr = correlation_id or new_id("corr")
        try:
            history = self.service.get_backup_history(
                actor, student_id=student_id, limit=limit, correlation_id=corr
            )
            return self._ok({"backups": [v.to_dict() for v in history]}, correlation_id=corr)
        except Exception as exc:
            return self._handle_exception(
                exc, correlation_id=corr, actor=actor, action="backup_history", student_id=student_id
            )

    def handle_verify_integrity(
        self,
        actor: ActorContext,
        *,
        file_id: str,
        version_id: str | None = None,
        correlation_id: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        corr = correlation_id or new_id("corr")
        try:
            report = self.service.verify_integrity(
                actor, file_id=file_id, version_id=version_id, correlation_id=corr
            )
            return self._ok(report.to_dict(), correlation_id=corr)
        except Exception as exc:
            return self._handle_exception(
                exc, correlation_id=corr, actor=actor, action="verify_integrity", file_id=file_id
            )

    def handle_verify_all(
        self,
        actor: ActorContext,
        *,
        student_id: str,
        correlation_id: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        corr = correlation_id or new_id("corr")
        try:
            reports = self.service.verify_all_files(
                actor, student_id=student_id, correlation_id=corr
            )
            return self._ok({"reports": [r.to_dict() for r in reports]}, correlation_id=corr)
        except Exception as exc:
            return self._handle_exception(
                exc, correlation_id=corr, actor=actor, action="verify_all", student_id=student_id
            )

    def handle_recover(
        self,
        actor: ActorContext,
        *,
        payload: dict[str, Any],
        correlation_id: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        corr = correlation_id or new_id("corr")
        file_id = str(payload.get("file_id") or "")
        try:
            if not file_id:
                raise ValidationError("Missing required field 'file_id'.")
            rec = self.service.recover_version(
                actor,
                file_id=file_id,
                version_id=payload.get("version_id"),
                target_relative_path=payload.get("target_relative_path"),
                quarantine_corrupted=bool(payload.get("quarantine_corrupted", True)),
                trigger_source=str(payload.get("trigger_source") or "manual_recovery"),
                clear_threat_lock=bool(payload.get("clear_threat_lock", True)),
                correlation_id=corr,
            )
            return self._ok(rec.to_dict(), correlation_id=corr)
        except Exception as exc:
            return self._handle_exception(
                exc, correlation_id=corr, actor=actor, action="recover", file_id=file_id or None
            )

    def handle_restoration_history(
        self,
        actor: ActorContext,
        *,
        student_id: str,
        file_id: str | None = None,
        limit: int = 100,
        correlation_id: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        corr = correlation_id or new_id("corr")
        try:
            records = self.service.get_restoration_history(
                actor, student_id=student_id, file_id=file_id, limit=limit, correlation_id=corr
            )
            return self._ok({"restorations": [r.to_dict() for r in records]}, correlation_id=corr)
        except Exception as exc:
            return self._handle_exception(
                exc,
                correlation_id=corr,
                actor=actor,
                action="restoration_history",
                student_id=student_id,
                file_id=file_id,
            )

    def handle_scheduled_sweep(
        self,
        actor: ActorContext,
        *,
        student_id: str | None = None,
        correlation_id: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        corr = correlation_id or new_id("corr")
        try:
            summary = self.service.run_scheduled_backup_sweep(
                actor, student_id=student_id, correlation_id=corr
            )
            return self._ok(summary.to_dict(), correlation_id=corr)
        except Exception as exc:
            return self._handle_exception(
                exc, correlation_id=corr, actor=actor, action="scheduled_sweep", student_id=student_id
            )

    def handle_threat_alert(
        self,
        actor: ActorContext,
        *,
        payload: dict[str, Any],
        correlation_id: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        corr = correlation_id or new_id("corr")
        student_id = str(payload.get("student_id") or "")
        try:
            if not student_id:
                raise ValidationError("Missing required field 'student_id'.")
            affected = payload.get("affected_file_ids")
            if not isinstance(affected, list) or not affected:
                raise ValidationError("'affected_file_ids' must be a non-empty list.")
            alert_id = str(payload.get("alert_id") or new_id("alert"))
            reason = str(payload.get("reason") or "Suspicious file activity reported.")
            auto_recover = bool(payload.get("auto_recover", False))
            res = self.service.handle_ransomware_alert(
                actor,
                student_id=student_id,
                affected_file_ids=[str(f) for f in affected],
                alert_id=alert_id,
                reason=reason,
                auto_recover=auto_recover,
                correlation_id=corr,
            )
            return self._ok(res, correlation_id=corr)
        except Exception as exc:
            return self._handle_exception(
                exc, correlation_id=corr, actor=actor, action="threat_alert", student_id=student_id or None
            )

    def handle_security_events(
        self,
        actor: ActorContext,
        *,
        student_id: str,
        limit: int = 100,
        correlation_id: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        corr = correlation_id or new_id("corr")
        try:
            self.service._authorize_student_scope(  # noqa: SLF001
                actor, student_id, action="read_security_events", correlation_id=corr
            )
            raw_events = self.service.logger.read_events(limit=limit * 3)
            scoped = [
                ev
                for ev in raw_events
                if actor.is_admin() or ev.get("student_id") == student_id
            ][:limit]
            return self._ok({"events": scoped}, correlation_id=corr)
        except Exception as exc:
            return self._handle_exception(
                exc, correlation_id=corr, actor=actor, action="security_events", student_id=student_id
            )


def create_backup_blueprint(
    service: BackupRecoveryService,
    get_current_actor: Callable[[], ActorContext],
    url_prefix: str = "/api/backup",
) -> Any:
    """Create a Flask Blueprint wired to `BackupAPIController`.

    Requires `Flask` in Member 1's backend runtime. Imported lazily so the core
    module and unit tests run without requiring Flask to be installed standalone.
    """
    try:
        from flask import Blueprint, jsonify, request
    except ImportError as exc:
        raise ImportError(
            "Flask is required only when mounting create_backup_blueprint into Member 1's app."
        ) from exc

    controller = BackupAPIController(service)
    bp = Blueprint("backup_recovery", __name__, url_prefix=url_prefix)

    def _corr() -> str | None:
        return request.headers.get("X-Correlation-ID")

    @bp.get("/status")
    def status_route() -> Any:
        code, body = controller.handle_status(correlation_id=_corr())
        return jsonify(body), code

    @bp.get("/dashboard")
    def dashboard_route() -> Any:
        actor = get_current_actor()
        student_id = request.args.get("student_id", actor.actor_id)
        code, body = controller.handle_dashboard(actor, student_id=student_id, correlation_id=_corr())
        return jsonify(body), code

    @bp.get("/files")
    def list_files_route() -> Any:
        actor = get_current_actor()
        student_id = request.args.get("student_id", actor.actor_id)
        code, body = controller.handle_list_files(actor, student_id=student_id, correlation_id=_corr())
        return jsonify(body), code

    @bp.post("/upload")
    def upload_route() -> Any:
        actor = get_current_actor()
        if "file" in request.files:
            uploaded = request.files["file"]
            payload = {
                "student_id": request.form.get("student_id", actor.actor_id),
                "filename": uploaded.filename or request.form.get("filename", ""),
                "relative_path": request.form.get("relative_path"),
                "file_id": request.form.get("file_id"),
                "mime_type": uploaded.mimetype or "application/octet-stream",
            }
            code, body = controller.handle_upload(
                actor, payload=payload, file_bytes=uploaded.read(), correlation_id=_corr()
            )
        else:
            payload = request.get_json(silent=True) or {}
            code, body = controller.handle_upload(actor, payload=payload, correlation_id=_corr())
        return jsonify(body), code

    @bp.post("/create")
    def create_backup_route() -> Any:
        actor = get_current_actor()
        payload = request.get_json(silent=True) or {}
        code, body = controller.handle_create_backup(actor, payload=payload, correlation_id=_corr())
        return jsonify(body), code

    @bp.put("/files/<file_id>")
    def update_file_route(file_id: str) -> Any:
        actor = get_current_actor()
        if "file" in request.files:
            raw = request.files["file"].read()
        else:
            payload = request.get_json(silent=True) or {}
            b64 = payload.get("content_b64", "")
            raw = base64.b64decode(b64) if isinstance(b64, str) and b64 else request.get_data()
        code, body = controller.handle_update_file(
            actor, file_id=file_id, file_bytes=raw, correlation_id=_corr()
        )
        return jsonify(body), code

    @bp.get("/versions/<file_id>")
    def list_versions_route(file_id: str) -> Any:
        actor = get_current_actor()
        include_pruned = request.args.get("include_pruned", "false").lower() == "true"
        code, body = controller.handle_list_versions(
            actor, file_id=file_id, include_pruned=include_pruned, correlation_id=_corr()
        )
        return jsonify(body), code

    @bp.post("/versions/<file_id>/<version_id>/pin")
    def pin_version_route(file_id: str, version_id: str) -> Any:
        actor = get_current_actor()
        payload = request.get_json(silent=True) or {}
        pinned = bool(payload.get("pinned", True))
        code, body = controller.handle_pin_version(
            actor, file_id=file_id, version_id=version_id, pinned=pinned, correlation_id=_corr()
        )
        return jsonify(body), code

    @bp.get("/history")
    def backup_history_route() -> Any:
        actor = get_current_actor()
        student_id = request.args.get("student_id", actor.actor_id)
        limit = int(request.args.get("limit", "100"))
        code, body = controller.handle_backup_history(
            actor, student_id=student_id, limit=limit, correlation_id=_corr()
        )
        return jsonify(body), code

    @bp.post("/verify/<file_id>")
    def verify_integrity_route(file_id: str) -> Any:
        actor = get_current_actor()
        payload = request.get_json(silent=True) or {}
        code, body = controller.handle_verify_integrity(
            actor, file_id=file_id, version_id=payload.get("version_id"), correlation_id=_corr()
        )
        return jsonify(body), code

    @bp.post("/verify-all")
    def verify_all_route() -> Any:
        actor = get_current_actor()
        payload = request.get_json(silent=True) or {}
        student_id = str(payload.get("student_id") or actor.actor_id)
        code, body = controller.handle_verify_all(actor, student_id=student_id, correlation_id=_corr())
        return jsonify(body), code

    @bp.post("/recover")
    def recover_route() -> Any:
        actor = get_current_actor()
        payload = request.get_json(silent=True) or {}
        code, body = controller.handle_recover(actor, payload=payload, correlation_id=_corr())
        return jsonify(body), code

    @bp.get("/restorations")
    def restorations_route() -> Any:
        actor = get_current_actor()
        student_id = request.args.get("student_id", actor.actor_id)
        file_id = request.args.get("file_id")
        limit = int(request.args.get("limit", "100"))
        code, body = controller.handle_restoration_history(
            actor, student_id=student_id, file_id=file_id, limit=limit, correlation_id=_corr()
        )
        return jsonify(body), code

    @bp.post("/sweep")
    def sweep_route() -> Any:
        actor = get_current_actor()
        payload = request.get_json(silent=True) or {}
        code, body = controller.handle_scheduled_sweep(
            actor, student_id=payload.get("student_id"), correlation_id=_corr()
        )
        return jsonify(body), code

    @bp.post("/threat-alert")
    def threat_alert_route() -> Any:
        actor = get_current_actor()
        payload = request.get_json(silent=True) or {}
        code, body = controller.handle_threat_alert(actor, payload=payload, correlation_id=_corr())
        return jsonify(body), code

    @bp.get("/events")
    def events_route() -> Any:
        actor = get_current_actor()
        student_id = request.args.get("student_id", actor.actor_id)
        limit = int(request.args.get("limit", "100"))
        code, body = controller.handle_security_events(
            actor, student_id=student_id, limit=limit, correlation_id=_corr()
        )
        return jsonify(body), code

    return bp
