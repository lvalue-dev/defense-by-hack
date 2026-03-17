from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from models.schemas import AnalyzeRequest
from services.semgrep_service import stream_vulnerability_analysis

router = APIRouter()


@router.post("/analyze")
async def analyze_code(req: AnalyzeRequest):
    return StreamingResponse(
        stream_vulnerability_analysis(req.code, req.language),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
