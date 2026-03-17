from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import analyze, fix, simulate, report

app = FastAPI(
    title="Defense by Hack - Vulnerability Analysis API",
    description="AI-powered web application vulnerability analysis and simulation",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze.router, prefix="/api", tags=["Analysis"])
app.include_router(fix.router, prefix="/api", tags=["Fix"])
app.include_router(simulate.router, prefix="/api", tags=["Simulation"])
app.include_router(report.router, prefix="/api", tags=["Report"])


@app.get("/health")
async def health():
    return {"status": "ok", "service": "defense-by-hack"}
