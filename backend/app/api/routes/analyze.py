from fastapi import APIRouter, Depends, HTTPException, Request

from ...engine.pipeline import Analyzer
from ...schemas.analysis import AnalyzeRequest, AnalyzeResponse, FeedbackRequest
from ...services.store import Store
from ..deps import get_analyzer, get_store
from ..security import source_id

router = APIRouter(tags=["Scam X-Ray"])


@router.post("/analyze", response_model=AnalyzeResponse, summary="Analyse a message for scam warning signs")
async def analyze(req: AnalyzeRequest, request: Request, analyzer: Analyzer = Depends(get_analyzer),
                  store: Store = Depends(get_store)) -> dict:
    result = await analyzer.analyze(req.text, channel=req.channel, sender=req.sender,
                                    language=req.language, use_ai=req.use_ai, use_intel=req.use_intel)
    store.save_analysis(result, result["identifiers"], source=source_id(request))
    return result


@router.post("/feedback", summary="Tell us whether a verdict was right (feeds model improvement)")
async def feedback(req: FeedbackRequest, store: Store = Depends(get_store)) -> dict:
    if not store.get_analysis(req.analysis_id):
        raise HTTPException(404, "Unknown analysis_id")
    store.add_feedback(req.model_dump())
    return {"status": "thanks"}
