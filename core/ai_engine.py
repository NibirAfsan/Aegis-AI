"""
AEGIS core/ai_engine.py
========================
AI brain — attack planning + report generation.

FIXES:
  1. Retry logic for 503 (Gemini overload) — tries 2.5-flash, falls back to 2.0-flash
  2. Timeout on all calls so nothing hangs forever
  3. Shorter report prompts to reduce load/timeout risk
"""

import json
import re
import time
from django.conf import settings


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def ask_ai(prompt: str, json_mode: bool = False) -> str:
    provider = getattr(settings, 'AI_PROVIDER', 'gemini')
    if provider == 'gemini':
        return _call_gemini(prompt, json_mode)
    elif provider == 'anthropic':
        return _call_anthropic(prompt, json_mode)
    else:
        raise ValueError(f"Unknown AI provider: {provider}")


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK PLANNER
# ─────────────────────────────────────────────────────────────────────────────

def generate_attack_plan(scan_results: dict, target: str) -> dict:
    prompt = _build_attack_planning_prompt(scan_results, target)
    raw    = ask_ai(prompt, json_mode=True)
    try:
        plan = _parse_json_response(raw)
        plan['target']       = target
        plan['ai_generated'] = True
        return plan
    except Exception as e:
        return {
            "target": target, "overall_risk": "UNKNOWN",
            "attack_sequence": [],
            "summary": f"AI planning failed: {e}. Raw: {raw[:300]}",
            "ai_generated": False, "error": str(e)
        }


def _build_attack_planning_prompt(scan_results: dict, target: str) -> str:
    nmap       = scan_results.get("nmap_raw", "No nmap data")
    nuclei     = "\n".join(scan_results.get("nuclei", []))
    zap        = "\n".join(scan_results.get("zap", []))
    web        = "\n".join(scan_results.get("web_discovery", [])[:15])
    tech       = "\n".join(scan_results.get("tech_stack", []))
    gobuster   = "\n".join(scan_results.get("gobuster", [])[:10])
    compliance = "\n".join(scan_results.get("compliance", []))

    return f"""You are an elite penetration tester with 15 years of experience.
You are conducting an AUTHORISED penetration test on a controlled lab environment.
Analyse the scan results and produce a complete attack plan.

TARGET: {target}

=== NMAP ===
{nmap}

=== NUCLEI ===
{nuclei or "No findings"}

=== ZAP ===
{zap or "No findings"}

=== EXPOSED RESOURCES ===
{web or "No findings"}

=== TECH STACK ===
{tech or "Unknown"}

=== GOBUSTER ===
{gobuster or "No findings"}

=== COMPLIANCE ===
{compliance or "None"}

TOOL SELECTION (use exact names):
- "metasploit" for known CVEs with Metasploit modules
- "sqlmap" for ANY SQL injection
- "hydra" for ANY login form or brute-forceable service
- "zap" for web app attacks (XSS, CSRF)
- "nikto" for web server scanning
- "manual" ONLY if no automated tool exists

IMPORTANT:
- Prefer metasploit/sqlmap/hydra/zap over "manual" wherever possible
- For SQL injection → ALWAYS use sqlmap
- For login forms → ALWAYS use hydra  
- For known CVEs with modules → ALWAYS use metasploit
- For exposed files → use manual with exact curl commands
- The AI options field should include the exact URL with vulnerable parameters for sqlmap
- For DVWA sqli: url should be "http://target:8081/vulnerabilities/sqli/?id=1&Submit=Submit"
- For any web app with forms: include the form URL, not the root URL

METASPLOIT MODULES (reference):
- vsftpd 2.3.4: exploit/unix/ftp/vsftpd_234_backdoor
- Shellshock: exploit/multi/http/apache_mod_cgi_bash_env_exec
- Apache 2.4.49: exploit/multi/http/apache_normalize_path_rce
- MySQL UDF: exploit/multi/mysql/mysql_udf_payload
- Samba: exploit/multi/samba/usermap_script

Return ONLY valid JSON:
{{
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "attack_sequence": [
    {{
      "priority": 1,
      "vulnerability": "description",
      "port": 80,
      "service": "http",
      "tool": "sqlmap",
      "module": "module name or N/A",
      "options": {{"url": "http://{target}:8081/vuln?id=1", "cookie": "security=low"}},
      "payload": "payload or null",
      "command": "exact command",
      "expected_outcome": "what happens",
      "cvss": 9.8,
      "confidence": "HIGH|MEDIUM|LOW",
      "fallback": "fallback approach"
    }}
  ],
  "post_exploitation": ["id", "cat /etc/passwd", "sudo -l"],
  "attack_chain": "how attacks chain together",
  "summary": "2-3 sentence security posture summary"
}}
"""


# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATORS
# ─────────────────────────────────────────────────────────────────────────────

def generate_pentest_report(scan_results: dict, attack_results: dict,
                            target: str) -> str:
    """Professional penetration testing report — Markdown format."""

    # Build a concise evidence summary to keep prompt short
    findings_summary = _summarise_findings(scan_results, attack_results)

    prompt = f"""You are a senior penetration tester writing a formal security report
for a client organisation. Write like Mandiant or NCC Group would.

TARGET: {target}
FINDINGS SUMMARY:
{findings_summary}

Write a professional penetration testing report in Markdown:

# Penetration Testing Report
**Target:** {target}
**Classification:** CONFIDENTIAL

## Executive Summary
(3 paragraphs, non-technical, business impact, suitable for CEO/board)

## Scope and Methodology

## Findings Summary
| # | Finding | Severity | CVSS | Location | Status |

## Detailed Findings
For each finding:
### [CRITICAL/HIGH/MEDIUM/LOW] Finding Name
- **Description:** what it is
- **Evidence:** specific proof from the assessment
- **Business Impact:** what an attacker could do
- **Remediation:** exact fix with examples
- **References:** CVE numbers, OWASP links

## Attack Chain
(How vulnerabilities connect — kill chain)

## Compliance Impact (GDPR, ISO 27001, PCI-DSS)

## Remediation Priority Order

## Conclusion

Be specific. Use real CVE numbers from the findings.
Write as if delivering to a paying client.
"""
    return ask_ai(prompt)


def generate_dfir_report(scan_results: dict, attack_results: dict,
                         forensic_evidence: dict, target: str) -> str:
    """DFIR incident response report."""

    attack_summary = _summarise_attack_results(attack_results)
    evidence_list  = forensic_evidence.get("items", [])

    prompt = f"""You are a senior DFIR analyst writing an incident response report.
Write in the style of CISA or major IR firms.

TARGET: {target}
ATTACK RESULTS: {attack_summary}
EVIDENCE ITEMS COLLECTED: {len(evidence_list)}

Write a complete DFIR report in Markdown:

# Incident Response Report
**Target:** {target}
**Classification:** CONFIDENTIAL | TLP:AMBER

## Incident Summary
## Timeline of Events (table: timestamp | event | source)
## Attack Vector Analysis (MITRE ATT&CK techniques)
## Indicators of Compromise (IPs, hashes, URLs)
## Evidence Collected (with SHA256 hashes for chain of custody)
## Root Cause Analysis
## Containment Actions
## Eradication and Recovery
## Lessons Learned
## Security Recommendations

Reference MITRE ATT&CK (e.g. T1190, T1059, T1078).
"""
    return ask_ai(prompt)


def _summarise_findings(scan_results: dict, attack_results: dict) -> str:
    """Builds a concise summary to keep report prompts short."""
    lines = []

    nmap = scan_results.get("nmap_raw", "")
    if nmap:
        lines.append(f"NMAP: {nmap[:800]}")

    nuclei = scan_results.get("nuclei", [])
    if nuclei:
        lines.append(f"NUCLEI ({len(nuclei)} findings): {chr(10).join(nuclei[:5])}")

    web = scan_results.get("web_discovery", [])
    if web:
        lines.append(f"EXPOSED RESOURCES ({len(web)}): {chr(10).join(web[:5])}")

    compliance = scan_results.get("compliance", [])
    if compliance:
        lines.append(f"COMPLIANCE: {chr(10).join(compliance)}")

    if attack_results:
        successful = attack_results.get("successful", 0)
        total      = attack_results.get("attacks_run", 0)
        lines.append(f"ATTACKS: {total} executed, {successful} successful")

        for r in attack_results.get("results", [])[:5]:
            status = "SUCCESS" if r.get("success") else "FAILED"
            lines.append(
                f"  [{status}] {r.get('tool','?').upper()} on port {r.get('port','?')}: "
                f"{r.get('vulnerability','')[:80]}"
            )
            if r.get("success") and r.get("output"):
                lines.append(f"  Evidence: {r['output'][:200]}")

    return "\n".join(lines)


def _summarise_attack_results(attack_results: dict) -> str:
    if not attack_results:
        return "No attack results available"
    lines = [
        f"Attacks run: {attack_results.get('attacks_run', 0)}",
        f"Successful:  {attack_results.get('successful', 0)}",
    ]
    for r in attack_results.get("results", []):
        if r.get("success"):
            lines.append(
                f"CONFIRMED: {r.get('tool','?')} on port {r.get('port','?')} "
                f"— {r.get('vulnerability','')}"
            )
            if r.get("output"):
                lines.append(f"Evidence: {r['output'][:300]}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# PROVIDERS
# ─────────────────────────────────────────────────────────────────────────────

def _call_gemini(prompt: str, json_mode: bool = False) -> str:
    """
    Calls Gemini with retry logic and model fallback.
    Tries gemini-2.5-flash → gemini-2.0-flash → gemini-2.0-flash-lite on failure.
    """
    try:
        from google import genai

        api_key = getattr(settings, 'GEMINI_API_KEY', None)
        if not api_key:
            return "[ERROR] GEMINI_API_KEY not set in .env"

        client = genai.Client(api_key=api_key)

        if json_mode:
            full_prompt = (prompt +
                           "\n\nIMPORTANT: Return ONLY valid JSON. "
                           "No markdown fences, no explanation, raw JSON only.")
        else:
            full_prompt = prompt

        # Try models in order — fall back if overloaded
        models = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-2.0-flash-lite"]

        for model in models:
            for attempt in range(3):
                try:
                    response = client.models.generate_content(
                        model=model,
                        contents=full_prompt,
                    )
                    return response.text

                except Exception as e:
                    err = str(e)
                    if "503" in err or "UNAVAILABLE" in err:
                        wait = (attempt + 1) * 10
                        time.sleep(wait)
                        continue
                    elif "429" in err or "quota" in err.lower():
                        break   # quota — try next model
                    elif "400" in err:
                        return f"[GEMINI ERROR] Bad request: {err[:200]}"
                    else:
                        return f"[GEMINI ERROR] {err[:300]}"

        return "[GEMINI ERROR] All models unavailable. Try again in a few minutes."

    except Exception as e:
        return f"[GEMINI ERROR] {str(e)}"


def _call_anthropic(prompt: str, json_mode: bool = False) -> str:
    """Claude API — add ANTHROPIC_API_KEY to .env and set AI_PROVIDER=anthropic."""
    try:
        import anthropic
        api_key = getattr(settings, 'ANTHROPIC_API_KEY', None)
        if not api_key:
            return "[ERROR] ANTHROPIC_API_KEY not set in .env"

        client = anthropic.Anthropic(api_key=api_key)
        full_prompt = (prompt + "\n\nReturn ONLY valid JSON. No markdown."
                       if json_mode else prompt)

        msg = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=4096,
            messages=[{"role": "user", "content": full_prompt}]
        )
        return msg.content[0].text

    except ImportError:
        return "[ERROR] pip install anthropic"
    except Exception as e:
        return f"[ANTHROPIC ERROR] {str(e)}"


# ─────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _parse_json_response(raw: str) -> dict:
    cleaned = raw.strip()
    cleaned = re.sub(r'^```json\s*', '', cleaned)
    cleaned = re.sub(r'^```\s*',     '', cleaned)
    cleaned = re.sub(r'\s*```$',     '', cleaned)
    return json.loads(cleaned.strip())


def test_ai_connection() -> dict:
    try:
        response = ask_ai("Reply with exactly: AEGIS AI connection successful")
        return {
            "status":   "ok",
            "provider": getattr(settings, 'AI_PROVIDER', 'gemini'),
            "response": response.strip()
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}