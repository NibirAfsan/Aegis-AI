"""
AEGIS core/ai_engine.py
========================
The AI brain of Phase 3.

FIXES APPLIED:
  1. _call_gemini() uses new google.genai package (old one deprecated)
  2. _build_attack_planning_prompt() now instructs AI to prefer executable
     tools (metasploit, sqlmap, hydra, zap) over "manual" wherever possible
"""

import json
import re
from django.conf import settings


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def ask_ai(prompt: str, json_mode: bool = False) -> str:
    """
    Universal AI caller. Switch provider by changing AI_PROVIDER in settings.py.
    Currently: gemini (free)
    Future:    anthropic (uncomment when you have key)
    """
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
    """
    Reads scan results and returns a complete structured attack plan.
    The plan tells the attack engine which tools, modules, and options to use.
    """
    prompt = _build_attack_planning_prompt(scan_results, target)

    raw_response = ask_ai(prompt, json_mode=True)

    try:
        plan = _parse_json_response(raw_response)
        plan['target']       = target
        plan['ai_generated'] = True
        return plan
    except Exception as e:
        return {
            "target":       target,
            "overall_risk": "UNKNOWN",
            "attack_sequence": [],
            "summary":      f"AI planning failed: {str(e)}. Raw: {raw_response[:500]}",
            "ai_generated": False,
            "error":        str(e)
        }


def _build_attack_planning_prompt(scan_results: dict, target: str) -> str:
    nmap       = scan_results.get("nmap_raw", "No nmap data")
    nuclei     = "\n".join(scan_results.get("nuclei", []))
    zap        = "\n".join(scan_results.get("zap", []))
    web        = "\n".join(scan_results.get("web_discovery", [])[:15])
    tech       = "\n".join(scan_results.get("tech_stack", []))
    gobuster   = "\n".join(scan_results.get("gobuster", [])[:10])
    compliance = "\n".join(scan_results.get("compliance", []))

    return f"""You are an elite penetration tester with 15 years of experience conducting
authorised security assessments for Fortune 500 companies and government agencies.
You think methodically, prioritise high-impact attack paths, and always consider
both the technical exploit and its business impact.

You are conducting an AUTHORISED penetration test on a controlled lab environment.
Your job is to analyse the scan results below and produce a complete, structured
attack plan that maximises coverage of real vulnerabilities.

TARGET: {target}

=== NMAP SCAN RESULTS ===
{nmap}

=== NUCLEI VULNERABILITY FINDINGS ===
{nuclei if nuclei else "No findings"}

=== OWASP ZAP WEB FINDINGS ===
{zap if zap else "No findings"}

=== EXPOSED WEB RESOURCES ===
{web if web else "No findings"}

=== TECHNOLOGY STACK ===
{tech if tech else "Unknown"}

=== DIRECTORY DISCOVERY ===
{gobuster if gobuster else "No findings"}

=== COMPLIANCE ISSUES ===
{compliance if compliance else "None"}

INSTRUCTIONS:
Analyse these findings like a senior penetration tester would. For each real,
exploitable vulnerability you find:

1. Determine the BEST tool and exact module/command to exploit it
2. Prioritise by CVSS score and exploitability (known working exploits first)
3. Consider attack chaining (use one exploit to enable the next)
4. Include post-exploitation steps for each successful shell

TOOL SELECTION GUIDE (use these exact tool names):
- "metasploit" → for known CVEs with Metasploit modules, network services
- "sqlmap"     → for SQL injection (web forms, parameters, cookies)
- "hydra"      → for brute-forcing SSH, FTP, HTTP login, SMB credentials
- "zap"        → for active web app attacks (XSS, CSRF, path traversal)
- "nikto"      → for web server vulnerability scanning + exploitation hints
- "manual"     → ONLY for logic flaws or misconfigurations with no automated tool

IMPORTANT — TOOL PRIORITY RULES:
- Prefer executable tools (metasploit, sqlmap, hydra, zap, nikto) over "manual" wherever possible
- Only use "manual" if absolutely no automated tool can handle the vulnerability
- For Apache CVEs with known Metasploit modules → always use "metasploit"
- For any SQL injection finding → always use "sqlmap"
- For any login form or brute-forceable service → always use "hydra"
- For exposed files (.env, .git, backup.sql) → use "manual" with curl commands
- For web application vulnerabilities (XSS, CSRF) → always use "zap"

METASPLOIT MODULE EXAMPLES (for reference):
- vsftpd 2.3.4:         exploit/unix/ftp/vsftpd_234_backdoor
- Apache Struts:        exploit/multi/http/struts2_content_type_ognl
- EternalBlue:          exploit/windows/smb/ms17_010_eternalblue
- Shellshock:           exploit/multi/http/apache_mod_cgi_bash_env_exec
- Apache mod_cgi:       exploit/multi/http/apache_mod_cgi_bash_env_exec
- MySQL UDF:            exploit/multi/mysql/mysql_udf_payload
- Tomcat:               exploit/multi/http/tomcat_mgr_upload
- Apache 2.4.49 path:   exploit/multi/http/apache_normalize_path_rce
- WebDAV:               exploit/windows/iis/iis_webdav_scstoragepathfromurl

Respond ONLY with valid JSON, no markdown, no explanation outside the JSON.
Use this exact structure:

{{
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "attack_sequence": [
    {{
      "priority": 1,
      "vulnerability": "short description",
      "port": 21,
      "service": "ftp",
      "tool": "metasploit",
      "module": "exploit/unix/ftp/vsftpd_234_backdoor",
      "options": {{"RHOSTS": "{target}", "RPORT": "21"}},
      "payload": "cmd/unix/interact",
      "command": "use exploit/unix/ftp/vsftpd_234_backdoor",
      "expected_outcome": "root shell / admin access / data extraction",
      "cvss": 10.0,
      "confidence": "HIGH|MEDIUM|LOW",
      "fallback": "what to try if this fails"
    }}
  ],
  "post_exploitation": [
    "cat /etc/passwd",
    "sudo -l",
    "find / -perm -4000 2>/dev/null"
  ],
  "attack_chain": "explanation of how attacks build on each other",
  "summary": "2-3 sentence overview of the target's security posture and attack approach"
}}

Only include attacks for vulnerabilities that are ACTUALLY PRESENT in the scan results above.
Do not invent vulnerabilities. If nothing is exploitable, return an empty attack_sequence.
"""


# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATORS
# ─────────────────────────────────────────────────────────────────────────────

def generate_pentest_report(scan_results: dict, attack_results: dict,
                            target: str) -> str:
    """
    Generates a professional penetration testing report.
    Written in the style of Mandiant, CrowdStrike, or NCC Group.
    """
    prompt = f"""You are a senior penetration tester writing a formal security assessment
report for a client. Write in a professional, precise style.

TARGET: {target}
ASSESSMENT TYPE: Full penetration test (black box + vulnerability assessment)

=== SCAN FINDINGS ===
{json.dumps(scan_results, indent=2)[:3000]}

=== ATTACK RESULTS ===
{json.dumps(attack_results, indent=2)[:2000]}

Write a FULL penetration testing report in Markdown with these sections:

# Penetration Testing Report — {target}

## Executive Summary
(Non-technical, 3 paragraphs. Business impact. Suitable for CEO/board.)

## Scope and Methodology

## Findings Summary Table
| # | Finding | Severity | CVSS | Location |

## Detailed Findings
For each finding:
### [SEVERITY] Finding Title
**Description:** What the vulnerability is
**Evidence:** Exact proof from scan/attack output
**Business Impact:** What an attacker could do
**Remediation:** Specific fix steps with examples
**References:** CVE numbers, OWASP links

## Attack Chain Analysis

## Compliance Impact (GDPR, ISO 27001, PCI-DSS)

## Remediation Priority

## Conclusion

Be specific. Reference actual CVE numbers from the findings.
"""
    return ask_ai(prompt)


def generate_dfir_report(scan_results: dict, attack_results: dict,
                         forensic_evidence: dict, target: str) -> str:
    """
    Generates a Digital Forensics and Incident Response report.
    Written from the defender's perspective.
    """
    prompt = f"""You are a senior DFIR analyst writing an incident response report.
Write in the style used by CISA, NCSC, or major IR firms.

TARGET SYSTEM: {target}

=== ATTACK EVIDENCE ===
{json.dumps(attack_results, indent=2)[:2000]}

=== FORENSIC EVIDENCE COLLECTED ===
{json.dumps(forensic_evidence, indent=2)[:1500]}

Write a complete DFIR report in Markdown:

# Incident Response Report — {target}

## Incident Summary (severity: IR-CRITICAL/HIGH/MEDIUM)

## Timeline of Events
(Table: timestamp | event | evidence source)

## Attack Vector Analysis (MITRE ATT&CK techniques)

## Indicators of Compromise (IOCs)
- IP addresses, file hashes, URLs, registry keys

## Evidence Collected (chain of custody, SHA256 hashes)

## Root Cause Analysis

## Containment Actions Taken

## Eradication and Recovery Steps

## Lessons Learned

## Recommendations

Reference MITRE ATT&CK techniques (e.g. T1190, T1059).
Include SHA256 hashes where available.
"""
    return ask_ai(prompt)


# ─────────────────────────────────────────────────────────────────────────────
# PROVIDER IMPLEMENTATIONS
# ─────────────────────────────────────────────────────────────────────────────

def _call_gemini(prompt: str, json_mode: bool = False) -> str:
    try:
        from google import genai
        import time

        api_key = getattr(settings, 'GEMINI_API_KEY', None)
        if not api_key:
            return "[ERROR] GEMINI_API_KEY not set in .env file"

        client = genai.Client(api_key=api_key)

        if json_mode:
            full_prompt = (prompt + "\n\nIMPORTANT: Return ONLY valid JSON. "
                          "No markdown code blocks, no explanation.")
        else:
            full_prompt = prompt

        # Try gemini-2.5-flash first, fall back to gemini-2.0-flash on 503
        models_to_try = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-2.0-flash-lite"]

        for model in models_to_try:
            for attempt in range(3):   # 3 retries per model
                try:
                    response = client.models.generate_content(
                        model=model,
                        contents=full_prompt,
                    )
                    return response.text
                except Exception as e:
                    err = str(e)
                    if "503" in err or "UNAVAILABLE" in err:
                        wait = (attempt + 1) * 10   # 10s, 20s, 30s
                        time.sleep(wait)
                        continue   # retry same model
                    elif "429" in err or "quota" in err.lower():
                        break      # quota hit — try next model
                    else:
                        return f"[GEMINI ERROR] {err}"

        return "[GEMINI ERROR] All models unavailable. Try again in a few minutes."

    except Exception as e:
        return f"[GEMINI ERROR] {str(e)}"


def _call_anthropic(prompt: str, json_mode: bool = False) -> str:
    """
    Claude API — uncomment anthropic==0.25.0 in requirements.txt when ready.
    Add ANTHROPIC_API_KEY to .env, change AI_PROVIDER=anthropic in .env.
    """
    try:
        import anthropic

        api_key = getattr(settings, 'ANTHROPIC_API_KEY', None)
        if not api_key:
            return "[ERROR] ANTHROPIC_API_KEY not set in .env file"

        client = anthropic.Anthropic(api_key=api_key)

        if json_mode:
            full_prompt = prompt + "\n\nReturn ONLY valid JSON. No markdown, no explanation."
        else:
            full_prompt = prompt

        message = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=4096,
            messages=[{"role": "user", "content": full_prompt}]
        )
        return message.content[0].text

    except ImportError:
        return "[ERROR] anthropic not installed. Run: pip install anthropic"
    except Exception as e:
        return f"[ANTHROPIC ERROR] {str(e)}"


# ─────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _parse_json_response(raw: str) -> dict:
    """Safely parses JSON from AI response, strips markdown fences if present."""
    cleaned = raw.strip()
    cleaned = re.sub(r'^```json\s*', '', cleaned)
    cleaned = re.sub(r'^```\s*',     '', cleaned)
    cleaned = re.sub(r'\s*```$',     '', cleaned)
    cleaned = cleaned.strip()
    return json.loads(cleaned)


def test_ai_connection() -> dict:
    """Quick test — visit /test-ai/ to verify Gemini is connected."""
    try:
        response = ask_ai("Say 'AEGIS AI connection successful' and nothing else.")
        return {
            "status":   "ok",
            "provider": getattr(settings, 'AI_PROVIDER', 'gemini'),
            "response": response.strip()
        }
    except Exception as e:
        return {
            "status":   "error",
            "provider": getattr(settings, 'AI_PROVIDER', 'gemini'),
            "error":    str(e)
        }