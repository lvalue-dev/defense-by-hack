from fastapi import APIRouter
from fastapi.responses import JSONResponse, HTMLResponse
from models.schemas import ReportRequest
from datetime import datetime

router = APIRouter()

SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#6b7280",
}


def generate_html_report(code: str, language: str, vulnerabilities: list) -> str:
    vuln_items = ""
    for v in vulnerabilities:
        color = SEVERITY_COLORS.get(v.get("severity", "info"), "#6b7280")
        affected = ", ".join(str(l) for l in v.get("affected_lines", []))
        vuln_items += f"""
        <div class="vuln-card" style="border-left: 4px solid {color}">
          <div class="vuln-header">
            <span class="badge" style="background:{color}">{v.get('severity','').upper()}</span>
            <span class="vuln-title">{v.get('title', '')}</span>
            <span class="vuln-type">{v.get('type', '')}</span>
          </div>
          <p class="vuln-desc">{v.get('description', '')}</p>
          <div class="vuln-meta">
            <span>Lines: {affected}</span>
            <span>{v.get('owasp_category', '')}</span>
            <span>{v.get('cwe_id', '')}</span>
          </div>
          <pre class="code-snippet"><code>{v.get('code_snippet', '')}</code></pre>
        </div>
        """

    stats = {s: sum(1 for v in vulnerabilities if v.get("severity") == s)
             for s in ["critical", "high", "medium", "low", "info"]}

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Analysis Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', monospace, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
    .header {{ border-bottom: 1px solid #334155; padding-bottom: 1rem; margin-bottom: 2rem; }}
    h1 {{ font-size: 1.8rem; color: #38bdf8; }}
    .meta {{ color: #94a3b8; font-size: 0.85rem; margin-top: 0.5rem; }}
    .stats {{ display: flex; gap: 1rem; margin: 1.5rem 0; flex-wrap: wrap; }}
    .stat {{ padding: 0.5rem 1rem; border-radius: 6px; font-size: 0.85rem; font-weight: 600; }}
    .vuln-card {{ background: #1e293b; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }}
    .vuln-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }}
    .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; color: white; }}
    .vuln-title {{ font-weight: 600; font-size: 1rem; }}
    .vuln-type {{ color: #94a3b8; font-size: 0.8rem; margin-left: auto; }}
    .vuln-desc {{ color: #94a3b8; font-size: 0.875rem; margin: 0.5rem 0; }}
    .vuln-meta {{ display: flex; gap: 1rem; font-size: 0.75rem; color: #64748b; margin: 0.5rem 0; }}
    .code-snippet {{ background: #0f172a; border-radius: 4px; padding: 0.75rem; font-size: 0.8rem; overflow-x: auto; margin-top: 0.5rem; color: #f1f5f9; }}
    .total {{ color: #94a3b8; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Analysis Report</h1>
    <div class="meta">
      Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; Language: {language} &nbsp;|&nbsp;
      Total Vulnerabilities: <strong>{len(vulnerabilities)}</strong>
    </div>
  </div>
  <div class="stats">
    <div class="stat" style="background:#ef444420;color:#ef4444">Critical: {stats['critical']}</div>
    <div class="stat" style="background:#f9731620;color:#f97316">High: {stats['high']}</div>
    <div class="stat" style="background:#eab30820;color:#eab308">Medium: {stats['medium']}</div>
    <div class="stat" style="background:#3b82f620;color:#3b82f6">Low: {stats['low']}</div>
    <div class="stat" style="background:#6b728020;color:#6b7280">Info: {stats['info']}</div>
  </div>
  <div class="vulnerabilities">
    {vuln_items if vuln_items else '<p style="color:#64748b">No vulnerabilities found.</p>'}
  </div>
</body>
</html>"""


@router.post("/report")
async def generate_report(req: ReportRequest):
    if req.format == "html":
        html = generate_html_report(req.code, req.language, req.vulnerabilities)
        return HTMLResponse(content=html)
    else:
        return JSONResponse(content={
            "generated_at": datetime.now().isoformat(),
            "language": req.language,
            "total_vulnerabilities": len(req.vulnerabilities),
            "summary": {
                s: sum(1 for v in req.vulnerabilities if v.get("severity") == s)
                for s in ["critical", "high", "medium", "low", "info"]
            },
            "vulnerabilities": req.vulnerabilities,
        })
