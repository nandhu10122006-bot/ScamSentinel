from fastapi import APIRouter, HTTPException, status
from ..schemas.scan import (
    UrlScanRequest,
    QrScanRequest,
    ScanResponse,
    HealthResponse
)
from ..services.url_analyzer import url_analyzer_service
from ..services.threat_intelligence import threat_intel_service

router = APIRouter(prefix="/api", tags=["Scanner"])


@router.get("/health", response_model=HealthResponse)
async def get_health() -> HealthResponse:
    """
    Health check endpoint returning system status and threat intelligence provider status.
    """
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        threat_intelligence_configured=threat_intel_service.is_configured,
        configured_providers=threat_intel_service.configured_providers
    )


@router.post("/scan/url", response_model=ScanResponse)
async def scan_url(request: UrlScanRequest) -> ScanResponse:
    """
    Accepts a URL string, runs comprehensive heuristic and threat intelligence checks,
    and returns risk classification, score, indicators, and explanations.
    """
    try:
        result = await url_analyzer_service.analyze(request.url)
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during URL analysis: {str(e)}"
        )


@router.post("/scan/qr", response_model=ScanResponse)
async def scan_qr(request: QrScanRequest) -> ScanResponse:
    """
    Accepts decoded QR code content (URL or payload), processes it using the unified
    URL analysis service, and returns structured risk analysis.
    """
    try:
        result = await url_analyzer_service.analyze(request.qr_content)
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during QR payload analysis: {str(e)}"
        )

