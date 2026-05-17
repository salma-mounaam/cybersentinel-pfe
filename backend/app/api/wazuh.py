# ============================================================
# M11 — API Wazuh CyberSentinel
# ============================================================

from fastapi import APIRouter

from app.services.wazuh_service import WazuhConsumer

router = APIRouter(prefix="/wazuh", tags=["M11 - Wazuh"])

consumer = WazuhConsumer()


@router.get("/health")
async def wazuh_health():
    info = await consumer.get_manager_info()

    return {
        "success": info is not None and info.get("error") == 0,
        "manager": info,
    }


@router.get("/manager/info")
async def wazuh_manager_info():
    return await consumer.get_manager_info()


@router.get("/agents")
async def wazuh_agents():
    return await consumer.get_agents()