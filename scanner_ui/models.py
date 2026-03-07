from django.db import models

class ScanResult(models.Model):
    target = models.CharField(max_length=255)
    scan_mode = models.CharField(max_length=50)
    timestamp = models.DateTimeField(auto_now_add=True)
    raw_data = models.TextField()  # The full Nmap output
    found_vulnerabilities = models.JSONField(default=dict) # Store specific bugs found
    is_critical = models.BooleanField(default=False)

    def __str__(self):
        return f"Scan of {target} at {timestamp}"