# ============================================================
# M5 — API REST DAST
# Modes : cible prédéfinie / URL custom / upload ZIP projet
# ============================================================

import json
import logging
import tempfile
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, HTTPException, UploadFile, File

from app.services.dast_service import (
    DASTOrchestrator,
    HOST_PCAP_STORAGE,
    ALLOWED_TARGETS,
)

logger = logging.getLogger(__name__)
router = APIRouter()

orchestrator = DASTOrchestrator()


# ============================================================
# Lancer une session DAST en arrière-plan
# ============================================================
@router.post("/start")
async def start_dast_session(payload: dict, background_tasks: BackgroundTasks):
    target = payload.get("target", "webgoat")
    target_url = payload.get("target_url")
    deploy_target = payload.get("deploy_target", True)

    if orchestrator.get_status()["active"]:
        raise HTTPException(
            status_code=409,
            detail=f"Session DAST déjà active : {orchestrator.get_status()['session_id']}",
        )

    # Vérification simple si cible prédéfinie
    if not target_url and target not in ALLOWED_TARGETS:
        raise HTTPException(
            status_code=400,
            detail=f"Cible non autorisée. Cibles valides : {list(ALLOWED_TARGETS.keys())}",
        )

    background_tasks.add_task(
        orchestrator.run_session,
        target,
        target_url,
        deploy_target,
    )

    return {
        "status": "started",
        "target": target if not target_url else "custom",
        "target_url": target_url,
        "message": "Session DAST lancée.",
    }


# ============================================================
# Lancer une session DAST en synchrone
# ============================================================
@router.post("/start/sync")
async def start_dast_session_sync(payload: dict):
    target = payload.get("target", "webgoat")
    target_url = payload.get("target_url")
    deploy_target = payload.get("deploy_target", True)

    if orchestrator.get_status()["active"]:
        raise HTTPException(status_code=409, detail="Session DAST déjà active.")

    if not target_url and target not in ALLOWED_TARGETS:
        raise HTTPException(
            status_code=400,
            detail=f"Cible non autorisée. Cibles valides : {list(ALLOWED_TARGETS.keys())}",
        )

    return await orchestrator.run_session(
        target=target,
        target_url=target_url,
        deploy_target=deploy_target,
    )


# ============================================================
# Upload ZIP projet → build → scan → teardown
# ============================================================
@router.post("/start/from-upload")
async def start_dast_from_upload(file: UploadFile = File(...)):
    """
    Reçoit un .zip du projet utilisateur.
    Détecte la stack (Spring Boot / Node / Python / PHP).
    Build une image Docker, lance dans sandbox-net, scan ZAP, teardown.

    Support V1 :
    - Spring Boot (pom.xml)
    - Node/Express (package.json)
    - Python Flask/FastAPI simple (requirements.txt)
    - PHP Apache (composer.json ou *.php)
    """
    if orchestrator.get_status()["active"]:
        raise HTTPException(status_code=409, detail="Session DAST déjà active.")

    filename = file.filename or "project.zip"
    suffix = Path(filename).suffix.lower()

    if suffix != ".zip":
        raise HTTPException(
            status_code=400,
            detail="Format non supporté. Utilise un fichier .zip",
        )

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Fichier vide.")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    logger.info(
        "Upload DAST reçu : %s (%.0f KB) → %s",
        filename,
        len(content) / 1024,
        tmp_path,
    )

    return await orchestrator.run_uploaded_project(
        zip_path=tmp_path,
        original_name=filename,
    )


# ============================================================
# Statut session DAST
# ============================================================
@router.get("/status")
async def get_dast_status():
    return orchestrator.get_status()


# ============================================================
# Vérification isolation sandbox (C-05 / CA09)
# ============================================================
@router.get("/isolation/verify")
async def verify_sandbox_isolation():
    import asyncio

    try:
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "network",
            "inspect",
            "cybersentinel_sandbox-net",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)

        if proc.returncode != 0:
            return {
                "sandbox_net_exists": False,
                "sandbox_net_internal": None,
                "ca09_passed": False,
                "constraint_c05": "PENDING",
                "message": "sandbox-net non créé pour le moment (profil DAST inactif)",
                "error": stderr.decode().strip(),
            }

        info = json.loads(stdout.decode())
        is_internal = info[0].get("Internal", False) if info else False

        return {
            "sandbox_net_exists": True,
            "sandbox_net_internal": is_internal,
            "ca09_passed": is_internal,
            "constraint_c05": "RESPECTED" if is_internal else "VIOLATED",
            "message": (
                "sandbox-net isolé avec internal:true"
                if is_internal
                else "sandbox-net existe mais n'est pas isolé"
            ),
        }

    except Exception as e:
        return {
            "sandbox_net_exists": False,
            "sandbox_net_internal": None,
            "ca09_passed": False,
            "constraint_c05": "ERROR",
            "message": "Erreur pendant la vérification",
            "error": str(e),
        }


# ============================================================
# Findings et preuves collectés
# ============================================================
@router.get("/findings")
async def get_dast_findings(limit: int = 50):
    if not HOST_PCAP_STORAGE.exists():
        return {
            "total_proofs": 0,
            "total_pcaps": 0,
            "pcap_files": [],
            "findings": [],
        }

    proof_files = sorted(HOST_PCAP_STORAGE.glob("*_proof_*.json"), reverse=True)
    pcap_files = list(HOST_PCAP_STORAGE.glob("*.pcap"))

    findings = []
    for pf in proof_files[:limit]:
        try:
            with open(pf, "r", encoding="utf-8") as f:
                findings.append(json.load(f))
        except Exception:
            pass

    return {
        "total_proofs": len(proof_files),
        "total_pcaps": len(pcap_files),
        "pcap_files": [p.name for p in pcap_files],
        "findings": findings,
    }