"""Chrome extension support: one-time registration that issues a signed install token."""
from fastapi import APIRouter, Depends

from ...core.config import Settings
from ...core.security import issue_token
from ..deps import settings_dep

router = APIRouter(prefix="/extension", tags=["Chrome extension"])


@router.post("/register", summary="Get a signed install token (rate-limited per IP address)")
async def register(settings: Settings = Depends(settings_dep)) -> dict:
    return issue_token(settings)
