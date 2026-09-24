"""Continuous learning: user reports, model status, retraining and rollback."""
import threading

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from ...core.config import Settings
from ...engine.detectors import entities as entity_detector
from ...engine.detectors.base import DetectionContext
from ...engine.explain import categorise
from ...engine.pipeline import identifiers, sender_identifier
from ...engine.redaction import redact
from ...schemas.analysis import ReportRequest, ReportResponse
from ...services.store import Store
from ..deps import get_ml, get_store, settings_dep
from ..security import require_admin, source_id

router = APIRouter()
_training = {"running": False, "last": None, "error": None}

MESSAGES = {
    "pending": "Thanks! Your report is saved. It joins the scam memory once {needed} people report it.",
    "confirmed": "Confirmed. This scam is now in FraudLens memory: similar messages will be caught right away.",
    "reinforced": "Thanks! This scam was already known. It has now been reported {reports} times.",
    "rejected": "This message matches a confirmed scam, so it can't be marked as genuine.",
    "disabled": "Reports are unavailable because the ML layer is switched off.",
}


@router.post("/report", response_model=ReportResponse, tags=["Learning"],
             summary="Report a message as scam or genuine (teaches the scam memory)")
async def report(req: ReportRequest, request: Request, ml=Depends(get_ml), store: Store = Depends(get_store)) -> dict:
    if ml is None:
        return {"status": "disabled", "message": MESSAGES["disabled"]}
    ctx = DetectionContext.from_text(req.text, sender=req.sender)
    entity_detector.detect(ctx)
    category = req.category or (categorise(req.text, set(), ctx.entities, "high") if req.label == "scam" else "none")
    # Independent reporters are counted per device, not per self-declared reporter_id,
    # so one client can't confirm (or whitelist) a message on its own by inventing ids.
    result = ml.report(redact(req.text).text, req.label, source_id(request), category)
    if result["status"] in ("confirmed", "reinforced") and req.label == "scam":
        ids = identifiers(ctx.entities)
        sender_id = sender_identifier(req.sender)
        if sender_id and sender_id not in ids:
            ids.append(sender_id)
        store.flag_identifiers(ids, category, 90, source=source_id(request))
    return {
        "status": result["status"],
        "message": MESSAGES[result["status"]].format(needed=result.get("needed", 0), reports=result.get("reports", 0)),
        "reports": result.get("reports", 0),
        "needed": result.get("needed", 0),
        "match": result.get("match"),
    }


@router.get("/models", tags=["Learning"], summary="Which models are loaded, memory size, training history")
async def models(ml=Depends(get_ml)) -> dict:
    if ml is None:
        return {"enabled": False}
    return {"enabled": True, **ml.status(), "versions": ml.registry.versions()[:10], "training": _training}


def _check(token: str | None, settings: Settings) -> None:
    require_admin(token, settings.admin_token)


@router.post("/admin/retrain", tags=["Learning"], summary="Retrain on the dataset + confirmed reports")
async def retrain(force: bool = False, x_admin_token: str | None = Header(None), ml=Depends(get_ml),
                  settings: Settings = Depends(settings_dep)) -> dict:
    _check(x_admin_token, settings)
    if ml is None:
        raise HTTPException(409, "ML layer is disabled")
    if _training["running"]:
        return {"status": "already running"}

    def job():
        from ...ml.training import train
        _training.update(running=True, error=None)
        try:
            report = train(settings, force_promote=force, embedder=ml.embedder, progress=lambda m: None)
            _training["last"] = {k: report[k] for k in ("version", "promoted", "test", "champion_f1", "seconds")}
            ml.reload()
        except Exception as exc:
            _training["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            _training["running"] = False

    threading.Thread(target=job, daemon=True).start()
    return {"status": "started", "poll": "/api/v1/models"}


@router.post("/admin/rollback", tags=["Learning"], summary="Switch back to the previous model version")
async def rollback(x_admin_token: str | None = Header(None), ml=Depends(get_ml),
                   settings: Settings = Depends(settings_dep)) -> dict:
    _check(x_admin_token, settings)
    if ml is None:
        raise HTTPException(409, "ML layer is disabled")
    prev = ml.registry.rollback()
    if not prev:
        raise HTTPException(409, "No previous version to roll back to")
    ml.reload()
    return {"status": "rolled back", "version": prev}
