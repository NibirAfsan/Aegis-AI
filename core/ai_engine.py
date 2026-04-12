"""
AEGIS core/ai_engine.py
========================
The AI brain of Phase 3. Reads scan results and produces a complete,
structured attack plan — which tools to use, which modules, in what order,
and why. No human decision needed.

This is what makes AEGIS different from every other student pentest tool.
A real senior pentester looks at scan results and thinks:
  "Port 21 open with vsftpd 2.3.4? That's a backdoor. Metasploit module
   exploit/unix/ftp/vsftpd_234_backdoor. Direct shell."
  "MySQL on 3306 with no auth? SQLMap it first, then try UDF escalation."
  "Apache 2.2.8? Multiple critical CVEs. Start with the RCE ones."

This file teaches the machine to think exactly like that.

PROVIDER SUPPORT:
  Currently: Gemini (free tier, 1500 req/day)
  Future:    Claude/Anthropic (uncomment when you have key)
  Switch:    Change AI_PROVIDER in settings.py — nothing else changes.
"""

import json
import re
from django.conf import settings


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT — call this from anywhere in the project
# ─────────────────────────────────────────────────────────────────────────────

def ask_ai(prompt: str, json_mode: bool = False) -> str:
    """
    Universal AI caller. Routes to the correct provider based on settings.
    
    Args:
        prompt:    The prompt to send
        json_mode: If True, instructs the model to return valid JSON only
    
    Returns:
        The AI response as a string (or JSON string if json_mode=True)
    """
    provider = getattr(settings, 'AI_PROVIDER', 'gemini')

    if provider == 'gemini':
        return _call_gemini(prompt, json_mode)
    elif provider == 'anthropic':
        return _call_anthropic(prompt, json_mode)
    else:
        raise ValueError(f"Unknown AI provider: {provider}")


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK PLANNER — the core intelligence
# ─────────────────────────────────────────────────────────────────────────────

def generate_attack_plan(scan_results: dict, target: str) -> dict:
    """
    Takes structured scan results and returns a complete attack plan.
    
    The plan tells the attack engine:
    - Which vulnerabilities to attack (prioritised by severity)
    - Which tool to use for each (Metasploit, SQLMap, Hydra, ZAP, etc.)
    - The exact module/command to run
    - Expected outcome
    - Fallback if primary attack fails
    
    Returns a structured dict like:
    {
        "target": "192.168.1.100",
        "overall_risk": "CRITICAL",
        "attack_sequence": [
            {
                "priority": 1,
                "vulnerability": "vsftpd 2.3.4 backdoor",
                "port": 21,
                "tool": "metasploit",
                "module": "exploit/unix/ftp/vsftpd_234_backdoor",
                "options": {"RHOSTS": "192.168.1.100", "RPORT": "21"},
                "payload": "cmd/unix/interact",
                "expected_outcome": "root shell",
                "cvss": 10.0,
                "fallback": "Try manual FTP anonymous login"
            },
            ...
        ],
        "post_exploitation": ["dump /etc/passwd", "check sudo -l", "look for SSH keys"],
        "summary": "Target has 3 critical attack vectors..."
    }
    """

    # Build a rich context prompt for the AI
    prompt = _build_attack_planning_prompt(scan_results, target)

    # Ask the AI — we want JSON back
    raw_response = ask_ai(prompt, json_mode=True)

    # Parse and validate the response
    try:
        plan = _parse_json_response(raw_response)
        plan['target'] = target
        plan['ai_generated'] = True
        return plan
    except Exception as e:
        # If JSON parsing fails, return a safe fallback
        return {
            "target": target,
            "overall_risk": "UNKNOWN",
            "attack_sequence": [],
            "summary": f"AI planning failed: {str(e)}. Raw response: {raw_response[:500]}",
            "ai_generated": False,
            "error": str(e)
        }


def _build_attack_planning_prompt(scan_results: dict, target: str) -> str:
    """
    Builds the master prompt that makes the AI think like a senior pentester.
    This prompt is the most important part of the whole system.
    """

    nmap      = scan_results.get("nmap_raw", "No nmap data")
    nuclei    = "\n".join(scan_results.get("nuclei", []))
    zap       = "\n".join(scan_results.get("zap", []))
    web       = "\n".join(scan_results.get("web_discovery", [])[:15])
    tech      = "\n".join(scan_results.get("tech_stack", []))
    gobuster  = "\n".join(scan_results.get("gobuster", [])[:10])
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
- "manual"     → for logic flaws, misconfigurations, exposed files
- "nikto"      → for web server vulnerability scanning + exploitation hints

METASPLOIT MODULE EXAMPLES (for reference):
- vsftpd 2.3.4:    exploit/unix/ftp/vsftpd_234_backdoor
- Apache Struts:   exploit/multi/http/struts2_content_type_ognl
- EternalBlue:     exploit/windows/smb/ms17_010_eternalblue
- Shellshock:      exploit/multi/http/apache_mod_cgi_bash_env_exec
- MySQL UDF:       exploit/multi/mysql/mysql_udf_payload
- Tomcat:          exploit/multi/http/tomcat_mgr_upload

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
# REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_pentest_report(scan_results: dict, attack_results: dict,
                            target: str) -> str:
    """
    Generates a professional penetration testing report from scan + attack data.
    Written in the style of a Big 4 consulting firm security report.
    """

    prompt = f"""You are a senior penetration tester writing a formal security assessment
report for a client. Write in a professional, precise style similar to reports
from Mandiant, CrowdStrike, or NCC Group.

TARGET: {target}
ASSESSMENT TYPE: Full penetration test (black box + vulnerability assessment)

=== SCAN FINDINGS ===
{json.dumps(scan_results, indent=2)[:3000]}

=== ATTACK RESULTS ===
{json.dumps(attack_results, indent=2)[:2000]}

Write a FULL penetration testing report in Markdown with these sections:

# Penetration Testing Report — {target}

## Executive Summary
(Non-technical, 3 paragraphs. What was tested, what was found, business impact.
Suitable for a CEO/board to read.)

## Scope and Methodology
(What was tested, what tools were used, testing approach)

## Findings Summary Table
| # | Finding | Severity | CVSS | Location |
(Table of all findings)

## Detailed Findings
For each finding:
### [SEVERITY] Finding Title
**Description:** What the vulnerability is
**Evidence:** Exact proof from scan/attack output
**Business Impact:** What an attacker could do
**Remediation:** Specific steps to fix, with code/config examples where relevant
**References:** CVE numbers, OWASP links

## Attack Chain Analysis
(How vulnerabilities connect — show the kill chain)

## Compliance Impact
(GDPR, ISO 27001, PCI-DSS implications)

## Remediation Priority
(Ordered list: fix these first)

## Conclusion

Be specific. Reference actual CVE numbers and actual evidence from the findings.
Write as if this will be delivered to a real client paying £50,000 for this assessment.
"""

    return ask_ai(prompt)


def generate_dfir_report(scan_results: dict, attack_results: dict,
                         forensic_evidence: dict, target: str) -> str:
    """
    Generates a Digital Forensics and Incident Response (DFIR) report.
    Written from the defender's perspective — what happened, when, and how.
    """

    prompt = f"""You are a senior DFIR analyst writing an incident response report
after investigating a security breach. Write in the style used by CISA,
NCSC, or major incident response firms.

TARGET SYSTEM: {target}

=== ATTACK EVIDENCE ===
{json.dumps(attack_results, indent=2)[:2000]}

=== FORENSIC EVIDENCE COLLECTED ===
{json.dumps(forensic_evidence, indent=2)[:1500]}

=== NETWORK TRAFFIC CAPTURED ===
(Scapy packet analysis data included in forensic_evidence above)

Write a complete DFIR report in Markdown:

# Incident Response Report — {target}

## Incident Summary
(What happened, when, severity level — IR-CRITICAL/HIGH/MEDIUM)

## Timeline of Events
(Chronological table: timestamp | event | evidence source)

## Attack Vector Analysis
(How did the attacker get in? Initial access, persistence, lateral movement)

## Indicators of Compromise (IOCs)
- IP addresses
- File hashes
- URLs/domains
- Registry keys / file paths

## Evidence Collected
(What was gathered, chain of custody, integrity verification)

## Root Cause Analysis
(Why did this happen? What control failed?)

## Containment Actions Taken
(What was done to stop the attack)

## Eradication and Recovery Steps
(How to fully clean the system)

## Lessons Learned
(What needs to change to prevent recurrence)

## Recommendations
(Prioritised list of security improvements)

Be forensically precise. Include SHA256 hashes where available.
Reference MITRE ATT&CK techniques (e.g. T1190 Exploit Public-Facing Application).
"""

    return ask_ai(prompt)


# ─────────────────────────────────────────────────────────────────────────────
# PROVIDER IMPLEMENTATIONS
# ─────────────────────────────────────────────────────────────────────────────

def _call_gemini(prompt: str, json_mode: bool = False) -> str:
    try:
        from google import genai                          # new import
        from google.genai import types

        api_key = getattr(settings, 'GEMINI_API_KEY', None)
        if not api_key:
            return "[ERROR] GEMINI_API_KEY not set in .env file"

        client = genai.Client(api_key=api_key)           # new client style

        if json_mode:
            full_prompt = prompt + "\n\nIMPORTANT: Return ONLY valid JSON. No markdown code blocks, no explanation, just the raw JSON object."
        else:
            full_prompt = prompt

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=full_prompt,
        )
        return response.text

    except Exception as e:
        return f"[GEMINI ERROR] {str(e)}"


def _call_anthropic(prompt: str, json_mode: bool = False) -> str:
    """
    Calls Anthropic Claude API.
    Uncomment when you have an API key.
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
        return "[ERROR] anthropic package not installed. Run: pip install anthropic"
    except Exception as e:
        return f"[ANTHROPIC ERROR] {str(e)}"


# ─────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _parse_json_response(raw: str) -> dict:
    """
    Safely parses a JSON response from the AI.
    Handles cases where the model wraps JSON in markdown code blocks.
    """
    # Strip markdown code blocks if present
    cleaned = raw.strip()
    cleaned = re.sub(r'^```json\s*', '', cleaned)
    cleaned = re.sub(r'^```\s*', '', cleaned)
    cleaned = re.sub(r'\s*```$', '', cleaned)
    cleaned = cleaned.strip()

    return json.loads(cleaned)


def test_ai_connection() -> dict:
    """
    Tests the AI connection with a simple prompt.
    Call this from a view to verify setup is working.
    """
    try:
        response = ask_ai("Say 'AEGIS AI connection successful' and nothing else.")
        return {
            "status": "ok",
            "provider": getattr(settings, 'AI_PROVIDER', 'gemini'),
            "response": response.strip()
        }
    except Exception as e:
        return {
            "status": "error",
            "provider": getattr(settings, 'AI_PROVIDER', 'gemini'),
            "error": str(e)
        }