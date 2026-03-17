from fastapi import APIRouter, HTTPException
from models.schemas import SimulateRequest
from services.knowledge_base import get_simulation

router = APIRouter()


@router.post("/simulate")
async def simulate_attack(req: SimulateRequest):
    try:
        result = get_simulation(
            vulnerability_type=req.vulnerability_type,
            vulnerability_title=req.vulnerability_title,
            code_snippet=req.code_snippet,
            description=req.description,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
