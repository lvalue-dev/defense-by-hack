import os
import json
import anthropic
from typing import AsyncGenerator

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))

ANALYSIS_SYSTEM_PROMPT = """You are a senior security researcher and penetration tester specializing in web application vulnerabilities.
Your task is to analyze code for security vulnerabilities, focusing on OWASP Top 10 and common security issues.

Respond ONLY with a valid JSON array of vulnerabilities found. Each vulnerability object must have exactly these fields:
{
  "id": "vuln_<number>",
  "type": "<vulnerability type, e.g. SQL_INJECTION>",
  "owasp_category": "<OWASP category, e.g. A03:2021>",
  "cwe_id": "<CWE ID, e.g. CWE-89>",
  "severity": "<critical|high|medium|low|info>",
  "title": "<short title>",
  "description": "<detailed description of the vulnerability>",
  "affected_lines": [<line numbers as integers>],
  "code_snippet": "<the vulnerable code snippet>"
}

If no vulnerabilities are found, return an empty array [].
Return ONLY the JSON array, no markdown fences, no explanation text."""

FIX_SYSTEM_PROMPT = """You are a senior security engineer. Your task is to provide a secure code fix for a given vulnerability.

Respond ONLY with a valid JSON object with these exact fields:
{
  "vulnerable_code": "<the original vulnerable code snippet>",
  "fixed_code": "<the complete fixed code snippet>",
  "explanation": "<detailed explanation of what was wrong and how the fix addresses it>",
  "additional_notes": "<any additional security recommendations>"
}

Return ONLY the JSON object, no markdown fences, no explanation text."""

SIMULATION_SYSTEM_PROMPT = """You are an ethical hacker and security educator. Your task is to create an educational attack simulation for a specific vulnerability.
This is for educational/CTF purposes to help developers understand how attacks work so they can better defend against them.

Respond ONLY with a valid JSON object with these exact fields:
{
  "attack_vector": "<how the attacker would target this vulnerability>",
  "prerequisites": ["<prerequisite 1>", "<prerequisite 2>"],
  "steps": [
    {
      "step": 1,
      "action": "<what the attacker does>",
      "payload": "<example payload or input>",
      "result": "<what happens>"
    }
  ],
  "impact": "<what damage could be caused>",
  "real_world_example": "<a real-world case or CVE reference>",
  "detection_methods": ["<how to detect this attack>"],
  "prevention_tips": ["<prevention tip 1>", "<prevention tip 2>"]
}

Return ONLY the JSON object, no markdown fences, no explanation text."""


async def stream_vulnerability_analysis(code: str, language: str) -> AsyncGenerator[str, None]:
    """Stream vulnerability analysis using Claude SSE."""
    prompt = f"""Analyze the following {language} code for security vulnerabilities:

```{language}
{code}
```

Return a JSON array of all vulnerabilities found."""

    try:
        full_response = ""
        with client.messages.stream(
            model="claude-sonnet-4-6",
            max_tokens=4096,
            system=ANALYSIS_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        ) as stream:
            for text in stream.text_stream:
                full_response += text
                yield f"data: {json.dumps({'type': 'chunk', 'text': text})}\n\n"

        # Parse and send the complete result
        try:
            # Clean up response - remove potential markdown fences
            clean_response = full_response.strip()
            if clean_response.startswith("```"):
                lines = clean_response.split("\n")
                clean_response = "\n".join(lines[1:-1])

            vulnerabilities = json.loads(clean_response)
            yield f"data: {json.dumps({'type': 'complete', 'vulnerabilities': vulnerabilities})}\n\n"
        except json.JSONDecodeError:
            yield f"data: {json.dumps({'type': 'error', 'message': 'Failed to parse analysis results'})}\n\n"

    except anthropic.APIError as e:
        yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    yield "data: [DONE]\n\n"


def get_code_fix(code: str, vulnerability_type: str, description: str, affected_lines: list) -> dict:
    """Get a secure code fix for a vulnerability."""
    prompt = f"""The following code has a {vulnerability_type} vulnerability:

Description: {description}
Affected lines: {affected_lines}

Code:
{code}

Provide a secure fix for this vulnerability."""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        system=FIX_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = response.content[0].text.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1])

    return json.loads(raw)


def generate_simulation(vulnerability_type: str, vulnerability_title: str, code_snippet: str, description: str) -> dict:
    """Generate an educational attack simulation."""
    prompt = f"""Create an educational attack simulation for this vulnerability:

Type: {vulnerability_type}
Title: {vulnerability_title}
Description: {description}

Vulnerable code:
{code_snippet}

Provide step-by-step educational simulation of how this vulnerability could be exploited."""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        system=SIMULATION_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = response.content[0].text.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1])

    return json.loads(raw)
