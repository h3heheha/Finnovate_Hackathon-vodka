"""Continuous learning: user reports, model status, retraining and rollback."""
import threading

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from ...core.config import Settings
import asyncio

from ...core.security import check_admin, client_ip, client_key, client_net
from ...engine.detectors import entities as entity_detector
from ...engine.detectors.base import DetectionContext
from ...engine.explain import categorise
from ...engine.pipeline import identifiers, sender_identifier
from ...engine.redaction import redact
from ...schemas.analysis import ReportRequest, ReportResponse
from ...services.store import Store
from ..deps import get_ml, get_store, settings_dep

router = APIRouter()
_training = {"running": False, "last": None, "error": None}

MESSAGES = {
    "pending": "Thanks! Your report is saved. It joins the scam memory once {needed} people report it.",
    "confirmed": "Learned! FraudLens now catches similar messages right away for you. It protects everyone "
                 "once people on {community} different networks have reported it.",
    "confirmed_community": "Learned! FraudLens now catches similar messages right away, for everyone.",
    "reinforced": "Thanks! This scam was already known. It has now been reported {reports} times.",
    "rejected": "This message matches a confirmed scam, so it can't be marked as genuine.",
    "noted": "Thanks, your answer is saved. \"It's genuine\" answers are checked by the FraudLens team before "
             "they change any warning, so scammers can't use them to hide a scam.",
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
    # Who reported is decided by the SERVER: a signed install token (ext:<id>) or the IP address.
    # The reporter_id in the body is ignored, so restarting an app or sending made-up ids can't
    # count as several different people.
    reporter = client_key(request)
    result = await asyncio.to_thread(ml.report, redact(req.text).text, req.label, reporter, category,
                                     client_net(client_ip(request)))
    if result["status"] in ("confirmed", "reinforced") and req.label == "scam":
        ids = identifiers(ctx.entities)
        sender_id = sender_identifier(req.sender)  # normalised; official numbers are never flagged
        if sender_id and sender_id not in ids:
            ids.append(sender_id)
        # Always for the reporter; for everyone only when enough different networks reported it.
        store.flag_personal(reporter, ids, category, 90)
        if result.get("community") and result.get("new_reporter"):
            store.flag_identifiers(ids, category, 90)
    status = result["status"]
    key = "confirmed_community" if status == "confirmed" and result.get("community") else status
    return {
        "status": status,
        "message": MESSAGES[key].format(needed=result.get("needed", 0), reports=result.get("reports", 0),
                                        community=result.get("community_needed", 0)),
        "reports": result.get("reports", 0),
        "needed": result.get("needed", 0),
        "match": result.get("match"),
    }


@router.get("/models", tags=["Learning"], summary="Which models are loaded, memory size, training history")
async def models(ml=Depends(get_ml)) -> dict:
    if ml is None:
        return {"enabled": False}
    return {"enabled": True, **ml.status(), "versions": ml.registry.versions()[:10], "training": _training}


@router.post("/admin/retrain", tags=["Learning"], summary="Retrain on the dataset + confirmed reports")
async def retrain(force: bool = False, x_admin_token: str | None = Header(None), ml=Depends(get_ml),
                  settings: Settings = Depends(settings_dep)) -> dict:
    check_admin(x_admin_token, settings)
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
    check_admin(x_admin_token, settings)
    if ml is None:
        raise HTTPException(409, "ML layer is disabled")
    prev = ml.registry.rollback()
    if not prev:
        raise HTTPException(409, "No previous version to roll back to")
    ml.reload()
    return {"status": "rolled back", "version": prev}
