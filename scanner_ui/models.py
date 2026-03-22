from django.db import models


class ScanResult(models.Model):

    STATUS_CHOICES = [
        ('RUNNING',  'Running'),
        ('COMPLETE', 'Complete'),
        ('FAILED',   'Failed'),
    ]

    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH',     'High'),
        ('MEDIUM',   'Medium'),
        ('LOW',      'Low'),
        ('INFO',     'Info'),
    ]

    SCAN_MODE_CHOICES = [
        ('lab',    'Lab Audit'),
        ('web',    'Web Audit'),
        ('top100', 'Quick Recon'),
        ('full',   'Deep Penetration'),
    ]

    target      = models.CharField(max_length=255)
    scan_mode   = models.CharField(max_length=50, choices=SCAN_MODE_CHOICES, default='lab')
    timestamp   = models.DateTimeField(auto_now_add=True)
    status      = models.CharField(max_length=20, choices=STATUS_CHOICES, default='RUNNING')
    severity    = models.CharField(max_length=20, choices=SEVERITY_CHOICES, null=True, blank=True)

    # Structured results — one key per tool
    # {
    #   "nmap_raw":      "...raw nmap text...",
    #   "web_discovery": ["[HTTP 200] http://...", ...],
    #   "tech_stack":    ["WordPress detected", ...],
    #   "osint":         ["SSL Issuer: ...", ...],
    #   "harvester":     ["[EMAIL] admin@target.com", ...],
    #   "gobuster":      ["/admin (Status: 200)", ...],
    #   "nuclei":        ["[HIGH] CVE-...", ...],
    #   "zap":           ["[MEDIUM] XSS at ...", ...],
    #   "compliance":    ["[ALERT] Unencrypted FTP", ...]
    # }
    raw_data              = models.JSONField(default=dict)

    # Populated when GenAI is wired — field exists now, stays null until then
    ai_report             = models.TextField(null=True, blank=True)

    # Kept from your original for quick dashboard filtering
    found_vulnerabilities = models.JSONField(default=dict)
    is_critical           = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        # YOUR ORIGINAL BUG: was missing self. — now fixed
        return f"Scan of {self.target} at {self.timestamp}"

    @property
    def finding_count(self):
        if not self.raw_data:
            return 0
        return sum([
            len(self.raw_data.get("web_discovery", [])),
            len(self.raw_data.get("gobuster", [])),
            len(self.raw_data.get("nuclei", [])),
            len(self.raw_data.get("zap", [])),
            len(self.raw_data.get("compliance", [])),
        ])

    @property
    def critical_findings(self):
        findings = self.raw_data.get("nuclei", []) + self.raw_data.get("zap", [])
        return [f for f in findings if "[CRITICAL]" in f or "[HIGH]" in f]


class AttackLog(models.Model):
    """Phase 3 — one row per attack attempt. Table created now, populated later."""
    scan        = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='attacks')
    tool_used   = models.CharField(max_length=50)
    module      = models.CharField(max_length=255)
    target_port = models.IntegerField(null=True)
    status      = models.CharField(max_length=20, default='PENDING')
    output      = models.TextField(blank=True)
    session_id  = models.CharField(max_length=50, blank=True)
    created_at  = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.tool_used} → {self.scan.target}:{self.target_port} [{self.status}]"


class ForensicEvidence(models.Model):
    """Phase 4 — forensic evidence chain of custody."""
    EVIDENCE_TYPES = [
        ('PCAP',       'Packet Capture'),
        ('LOG',        'System Log'),
        ('SCREENSHOT', 'Screenshot'),
        ('FILE',       'Extracted File'),
        ('HASH',       'File Hash'),
    ]

    scan          = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='evidence')
    evidence_type = models.CharField(max_length=50, choices=EVIDENCE_TYPES)
    file_path     = models.CharField(max_length=500)
    sha256_hash   = models.CharField(max_length=64, blank=True)
    description   = models.TextField(blank=True)
    collected_at  = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.evidence_type} — {self.scan.target} — {self.collected_at:%Y-%m-%d %H:%M}"