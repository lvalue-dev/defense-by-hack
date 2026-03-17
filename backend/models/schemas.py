from pydantic import BaseModel
from typing import Optional


class AnalyzeRequest(BaseModel):
    code: str
    language: str = "javascript"


class FixRequest(BaseModel):
    code: str
    vulnerability_id: str
    vulnerability_type: str
    description: str
    affected_lines: list[int]


class SimulateRequest(BaseModel):
    vulnerability_type: str
    vulnerability_title: str
    code_snippet: str
    description: str


class ReportRequest(BaseModel):
    code: str
    language: str
    vulnerabilities: list[dict]
    format: str = "json"  # "json" or "html"
