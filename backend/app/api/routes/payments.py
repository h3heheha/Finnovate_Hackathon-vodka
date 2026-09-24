from fastapi import APIRouter, Depends

from ...core.config import Settings
from ...schemas.payment import PaymentCheckRequest, PaymentCheckResponse
from ...services.payment_guard import check_payment
from ...services.store import Store
from ..deps import get_store, settings_dep

router = APIRouter(prefix="/payments", tags=["Pause-Before-Pay"])


@router.post("/check", response_model=PaymentCheckResponse,
             summary="Risk-check a payment just before it is sent")
async def payment_check(req: PaymentCheckRequest, store: Store = Depends(get_store),
                        settings: Settings = Depends(settings_dep)) -> dict:
    return check_payment(req, store, settings)
