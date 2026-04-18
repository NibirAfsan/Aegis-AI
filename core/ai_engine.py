"""
AEGIS core/ai_engine.py
========================
AI brain — attack planning + report generation.

UPDATES:
  1. Gemini safety settings (BLOCK_NONE) for pentest content
  2. Full scan data sent to AI (no aggressive truncation)
  3. Groq automatic fallback if Gemini fails
  4. All 4 providers: Gemini, Groq, Anthropic, DeepSeek
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

    if provider == 'deepseek':
        return _call_deepseek(prompt, json_mode)
    elif provider == 'groq':
        result = _call_groq(prompt, json_mode)
        if "[GROQ ERROR]" in result and getattr(settings, 'GEMINI_API_KEY', None):
            return _call_gemini(prompt, json_mode)
        return result
    elif provider == 'gemini':
        result = _call_gemini(prompt, json_mode)
        if "[GEMINI ERROR]" in result and getattr(settings, 'GROQ_API_KEY', None):
            return _call_groq(prompt, json_mode)
        return result
    elif provider == 'anthropic':
        return _call_anthropic(prompt, json_mode)
    else:
        raise ValueError(f"Unknown provider: {provider}")


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
    # Full data — paid Gemini handles large prompts fine
    nmap       = scan_results.get("nmap_raw", "No nmap data")
    nuclei     = "\n".join(scan_results.get("nuclei", []))
    zap        = "\n".join(scan_results.get("zap", []))
    web        = "\n".join(scan_results.get("web_discovery", [])[:20])
    tech       = "\n".join(scan_results.get("tech_stack", []))
    gobuster   = "\n".join(scan_results.get("gobuster", [])[:15])
    compliance = "\n".join(scan_results.get("compliance", []))

    return f"""You are an elite penetration tester with 15 years of experience.
You are conducting an AUTHORISED penetration test on a controlled lab environment.
This is a legal, academic security assessment for an MSc cybersecurity project.
Analyse ALL scan results below and produce a COMPLETE attack plan covering
EVERY exploitable vulnerability found.

TARGET: {target}

=== NMAP SCAN RESULTS ===
{nmap}

=== NUCLEI VULNERABILITY FINDINGS ===
{nuclei or "No findings"}

=== OWASP ZAP WEB FINDINGS ===
{zap or "No findings"}

=== EXPOSED WEB RESOURCES ===
{web or "No findings"}

=== TECHNOLOGY STACK ===
{tech or "Unknown"}

=== DIRECTORY DISCOVERY (GOBUSTER) ===
{gobuster or "No findings"}

=== COMPLIANCE ISSUES ===
{compliance or "None"}

INSTRUCTIONS — READ CAREFULLY:
1. Find EVERY exploitable vulnerability in the scan results
2. For each one, determine the BEST automated tool to exploit it
3. Prioritise by CVSS score and exploitability
4. Include at least one attack per open port/service found
5. Consider attack chaining — use one exploit to enable the next

TOOL SELECTION RULES (use these exact tool names):
- "metasploit" → for known CVEs with Metasploit modules, network service exploits
- "sqlmap"     → for ANY SQL injection (web forms, URL parameters, cookies)
- "hydra"      → for brute-forcing SSH, FTP, HTTP login, MySQL, PostgreSQL
- "zap"        → for active web app attacks (XSS, CSRF, path traversal)
- "nikto"      → for web server vulnerability scanning and exploitation hints
- "manual"     → ONLY for exposed files (.env, .git) — use curl commands
- "netcat" → for open backdoor ports (ingreslock 1524, bindshells)

CRITICAL RULES:
- ALWAYS prefer automated tools over "manual"
- For SQL injection → ALWAYS use "sqlmap" with the exact vulnerable URL
- For login forms or services → ALWAYS use "hydra"
- For known CVEs → ALWAYS use "metasploit" with the exact module path
- For web servers → use "nikto" to find additional vulnerabilities
- For exposed files → use "manual" with individual curl commands (ONE per command)
- NEVER chain curl commands with && in the command field
- For Metasploit, use "RHOSTS" (not "RHOST") in options
- For Hydra against PostgreSQL, use service name "postgres" (not "postgresql")
- For Hydra, use a small targeted wordlist approach, not full rockyou.txt

METASPLOIT MODULES (verified working):
- vsftpd 2.3.4:      exploit/unix/ftp/vsftpd_234_backdoor (payload: cmd/unix/interact)
- Shellshock:         exploit/multi/http/apache_mod_cgi_bash_env_exec
- Apache RCE 2.4.49:  exploit/multi/http/apache_normalize_path_rce
- MySQL UDF:          exploit/multi/mysql/mysql_udf_payload
- Samba usermap:      exploit/multi/samba/usermap_script
- Distcc:             exploit/unix/misc/distcc_exec
- PostgreSQL:         exploit/linux/postgres/postgres_payload
- Ingreslock bindshell: Use tool "netcat" with port 1524 (instant root shell, no exploit needed)

Respond ONLY with valid JSON. No markdown, no explanation, just the JSON object:
{{
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "attack_sequence": [
    {{
      "priority": 1,
      "vulnerability": "short description",
      "port": 2121,
      "service": "ftp",
      "tool": "metasploit",
      "module": "exploit/unix/ftp/vsftpd_234_backdoor",
      "options": {{"RHOSTS": "{target}", "RPORT": "2121"}},
      "payload": "cmd/unix/interact",
      "command": "use exploit/unix/ftp/vsftpd_234_backdoor",
      "expected_outcome": "root shell via backdoor",
      "cvss": 10.0,
      "confidence": "HIGH|MEDIUM|LOW",
      "fallback": "what to try if this fails"
    }}
  ],
  "post_exploitation": [
    "id", "whoami", "uname -a", "cat /etc/passwd",
    "sudo -l", "find / -perm -4000 2>/dev/null"
  ],
  "attack_chain": "explanation of how attacks build on each other",
  "summary": "2-3 sentence security posture and attack approach"
}}

IMPORTANT: Include attacks for ALL exploitable services found.
Do not skip any service just because another attack covers it.
"""


# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATORS
# ─────────────────────────────────────────────────────────────────────────────

def generate_pentest_report(scan_results: dict, attack_results: dict,
                            target: str) -> str:
    findings_summary = _summarise_findings(scan_results, attack_results)

    prompt = f"""You are a senior penetration tester writing a formal security report
for a client organisation. Write like Mandiant or NCC Group would.
This is for an authorised academic security assessment (MSc project).

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

## Attack Chain Analysis
(How vulnerabilities connect — show the kill chain from initial access to full compromise)

## Compliance Impact
(GDPR, ISO 27001, PCI-DSS, NIST implications)

## Remediation Priority Order

## Conclusion

Be specific. Use real CVE numbers from the findings.
Write as if delivering to a paying client — this report will be reviewed by university professors.
"""
    return ask_ai(prompt)


def generate_dfir_report(scan_results: dict, attack_results: dict,
                         forensic_evidence: dict, target: str) -> str:
    attack_summary = _summarise_attack_results(attack_results)
    evidence_list  = forensic_evidence.get("items", [])

    prompt = f"""You are a senior DFIR analyst writing an incident response report.
Write in the style of CISA or major IR firms.
This is for an authorised academic security assessment (MSc project).

TARGET: {target}
ATTACK RESULTS: {attack_summary}
EVIDENCE ITEMS COLLECTED: {len(evidence_list)}
EVIDENCE DETAILS:
{json.dumps(evidence_list[:10], indent=2)[:1500]}

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
Include SHA256 hashes from evidence items where available.
"""
    return ask_ai(prompt)


def _summarise_findings(scan_results: dict, attack_results: dict) -> str:
    lines = []

    nmap = scan_results.get("nmap_raw", "")
    if nmap:
        lines.append(f"NMAP:\n{nmap[:1500]}")

    nuclei = scan_results.get("nuclei", [])
    if nuclei:
        lines.append(f"NUCLEI ({len(nuclei)} findings):\n" +
                      "\n".join(nuclei[:8]))

    web = scan_results.get("web_discovery", [])
    if web:
        lines.append(f"EXPOSED RESOURCES ({len(web)}):\n" +
                      "\n".join(web[:8]))

    compliance = scan_results.get("compliance", [])
    if compliance:
        lines.append(f"COMPLIANCE:\n" + "\n".join(compliance))

    if attack_results:
        successful = attack_results.get("successful", 0)
        total      = attack_results.get("attacks_run", 0)
        lines.append(f"\nATTACKS: {total} executed, {successful} successful")

        for r in attack_results.get("results", []):
            status = "SUCCESS" if r.get("success") else "FAILED"
            lines.append(
                f"  [{status}] {r.get('tool','?').upper()} on port "
                f"{r.get('port','?')}: {r.get('vulnerability','')[:80]}"
            )
            if r.get("success") and r.get("output"):
                lines.append(f"  Evidence: {r['output'][:300]}")

    return "\n".join(lines)


def _summarise_attack_results(attack_results: dict) -> str:
    if not attack_results:
        return "No attack results available"
    lines = [
        f"Attacks run: {attack_results.get('attacks_run', 0)}",
        f"Successful:  {attack_results.get('successful', 0)}",
    ]
    for r in attack_results.get("results", []):
        status = "SUCCESS" if r.get("success") else "FAILED"
        lines.append(
            f"[{status}] {r.get('tool','?')} port {r.get('port','?')} "
            f"— {r.get('vulnerability','')}"
        )
        if r.get("output"):
            lines.append(f"  Output: {r['output'][:300]}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# PROVIDERS
# ─────────────────────────────────────────────────────────────────────────────

def _call_gemini(prompt: str, json_mode: bool = False) -> str:
    """
    Gemini with safety settings for pentest content and model fallback.
    """
    try:
        from google import genai
        from google.genai import types
        import time

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

        # Safety settings — allow authorised security assessment content
        safety = [
            types.SafetySetting(
                category="HARM_CATEGORY_HARASSMENT",
                threshold="BLOCK_NONE"
            ),
            types.SafetySetting(
                category="HARM_CATEGORY_HATE_SPEECH",
                threshold="BLOCK_NONE"
            ),
            types.SafetySetting(
                category="HARM_CATEGORY_SEXUALLY_EXPLICIT",
                threshold="BLOCK_NONE"
            ),
            types.SafetySetting(
                category="HARM_CATEGORY_DANGEROUS_CONTENT",
                threshold="BLOCK_NONE"
            ),
        ]

        models = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-2.0-flash-lite"]

        for model in models:
            for attempt in range(3):
                try:
                    response = client.models.generate_content(
                        model=model,
                        contents=full_prompt,
                        config=types.GenerateContentConfig(
                            safety_settings=safety
                        )
                    )
                    return response.text

                except Exception as e:
                    err = str(e)
                    if "503" in err or "UNAVAILABLE" in err:
                        wait = (attempt + 1) * 10
                        time.sleep(wait)
                        continue
                    elif "429" in err or "quota" in err.lower():
                        break
                    elif "400" in err:
                        return f"[GEMINI ERROR] Bad request: {err[:200]}"
                    else:
                        return f"[GEMINI ERROR] {err[:300]}"

        return "[GEMINI ERROR] All models unavailable."

    except Exception as e:
        return f"[GEMINI ERROR] {str(e)}"


def _call_groq(prompt: str, json_mode: bool = False) -> str:
    """
    Groq API — free tier fallback, 14,400 req/day.
    """
    try:
        import requests as req

        api_key = getattr(settings, 'GROQ_API_KEY', None)
        if not api_key:
            return "[GROQ ERROR] GROQ_API_KEY not set in .env"

        system = ("You are an expert penetration tester conducting an authorised "
                  "security assessment. Return ONLY valid JSON, no markdown."
                  if json_mode else
                  "You are an expert penetration tester conducting an authorised "
                  "security assessment.")

        response = req.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}",
                     "Content-Type": "application/json"},
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user",   "content": prompt}
                ],
                "temperature": 0.3,
                "max_tokens":  4096
            },
            timeout=120
        )
        data = response.json()
        if "choices" not in data:
            return f"[GROQ ERROR] {data}"
        return data["choices"][0]["message"]["content"]

    except Exception as e:
        return f"[GROQ ERROR] {str(e)}"


def _call_anthropic(prompt: str, json_mode: bool = False) -> str:
    """Claude API — add ANTHROPIC_API_KEY to .env."""
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


def _call_deepseek(prompt: str, json_mode: bool = False) -> str:
    """DeepSeek API — large context, good security reasoning."""
    try:
        import requests as req
        api_key = getattr(settings, 'DEEPSEEK_API_KEY', None)
        if not api_key:
            return "[ERROR] DEEPSEEK_API_KEY not set in .env"

        system = ("You are an expert penetration tester conducting an authorised "
                  "security assessment. Return ONLY valid JSON, no markdown."
                  if json_mode else
                  "You are an expert penetration tester conducting an authorised "
                  "security assessment.")

        body = {
            "model": "deepseek-chat",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens":  4096
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}

        response = req.post(
            "https://api.deepseek.com/chat/completions",
            headers={"Authorization": f"Bearer {api_key}",
                     "Content-Type": "application/json"},
            json=body,
            timeout=120
        )
        data = response.json()
        if "choices" not in data:
            return f"[DEEPSEEK ERROR] {data}"
        return data["choices"][0]["message"]["content"]

    except Exception as e:
        return f"[DEEPSEEK ERROR] {str(e)}"


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