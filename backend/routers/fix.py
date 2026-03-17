from fastapi import APIRouter, HTTPException
from models.schemas import FixRequest
from services.claude_service import get_code_fix
import json

router = APIRouter()


@router.post("/fix")
async def get_fix(req: FixRequest):
    try:
        result = get_code_fix(
            code=req.code,
            vulnerability_type=req.vulnerability_type,
            description=req.description,
            affected_lines=req.affected_lines,
        )
        return result
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Failed to parse fix response from AI")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
