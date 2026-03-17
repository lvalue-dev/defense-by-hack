from fastapi import APIRouter, HTTPException
from models.schemas import FixRequest
from services.knowledge_base import get_fix

router = APIRouter()


@router.post("/fix")
async def get_fix_endpoint(req: FixRequest):
    try:
        result = get_fix(
            code=req.code,
            vulnerability_type=req.vulnerability_type,
            description=req.description,
            affected_lines=req.affected_lines,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
