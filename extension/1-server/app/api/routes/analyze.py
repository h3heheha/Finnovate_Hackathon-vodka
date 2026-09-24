from fastapi import APIRouter, Depends, HTTPException, Request

from ...core.config import Settings
from ...core.budget import PerKeyAllowance
from ...core.security import client_ip, client_key, client_net
from ...engine.pipeline import Analyzer
from ...schemas.analysis import AnalyzeRequest, AnalyzeResponse, FeedbackRequest
from ...services.store import Store
from ..deps import get_analyzer, get_store, settings_dep

router = APIRouter(tags=["Scam X-Ray"])
_ai_per_client: PerKeyAllowance | None = None
_ai_per_network: PerKeyAllowance | None = None


def ai_allowed(request: Request, settings: Settings) -> bool:
    """Free AI quotas are shared: one browser or one network can't use them all up."""
    global _ai_per_client, _ai_per_network
    if _ai_per_client is None:
        _ai_per_client = PerKeyAllowance(settings.ai_per_client_daily)
        _ai_per_network = PerKeyAllowance(settings.ai_per_network_daily)
    return _ai_per_client.take(client_key(request)) and _ai_per_network.take(client_net(client_ip(request)))


@router.post("/analyze", response_model=AnalyzeResponse, summary="Analyse a message for scam warning signs")
async def analyze(req: AnalyzeRequest, request: Request, analyzer: Analyzer = Depends(get_analyzer),
                  store: Store = Depends(get_store), settings: Settings = Depends(settings_dep)) -> dict:
    client = client_key(request)
    use_ai = bool(req.use_ai) and analyzer.ai.name != "none" and ai_allowed(request, settings)
    result = await analyzer.analyze(req.text, channel=req.channel, sender=req.sender,
                                    language=req.language, use_ai=use_ai, use_intel=req.use_intel,
                                    client=client)
    # A high-risk scan flags its accounts / numbers / links for THIS client only (anti-poisoning).
    store.save_analysis(result, result["identifiers"], client=client, scope=settings.scan_flag_scope)
    return result


@router.post("/feedback", summary="Tell us whether a verdict was right (feeds model improvement)")
async def feedback(req: FeedbackRequest, request: Request, store: Store = Depends(get_store)) -> dict:
    if not store.get_analysis(req.analysis_id):
        raise HTTPException(404, "Unknown analysis_id")
    store.add_feedback({**req.model_dump(), "client": client_key(request)})
    return {"status": "thanks"}
