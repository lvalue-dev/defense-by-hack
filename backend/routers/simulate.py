from fastapi import APIRouter, HTTPException
from models.schemas import SimulateRequest
from services.claude_service import generate_simulation
import json

router = APIRouter()


@router.post("/simulate")
async def simulate_attack(req: SimulateRequest):
    try:
        result = generate_simulation(
            vulnerability_type=req.vulnerability_type,
            vulnerability_title=req.vulnerability_title,
            code_snippet=req.code_snippet,
            description=req.description,
        )
        return result
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Failed to parse simulation response from AI")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
