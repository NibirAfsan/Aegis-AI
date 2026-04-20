from django.urls import path
from . import views

urlpatterns = [
    # ── Dashboard ─────────────────────────────────────────────────
    path('',                                views.home,                name='home'),

    # ── Scan ──────────────────────────────────────────────────────
    path('start-scan/',                     views.start_scan,          name='start_scan'),
    path('scan-status/<str:task_id>/',      views.scan_status,         name='scan_status'),
    path('scan-results/<int:scan_id>/',     views.get_scan_results,    name='scan_results'),

    # ── Attack ────────────────────────────────────────────────────
    path('initiate-attack/',                views.initiate_attack,     name='initiate_attack'),
    path('attack-status/<str:task_id>/',    views.attack_status,       name='attack_status'),
    path('attack-plan/<int:scan_id>/',      views.view_attack_plan,    name='attack_plan'),

    # ── Report ────────────────────────────────────────────────────
    path('generate-report/<int:scan_id>/',  views.generate_report,     name='generate_report'),
    path('report-status/<str:task_id>/',    views.report_status,       name='report_status'),
    path('download-report/<int:scan_id>/',  views.download_report_pdf, name='download_report'),

    # ── Live Traffic ──────────────────────────────────────────────
    path('live-traffic/',                   views.get_live_traffic,    name='live_traffic'),

    # ── SIEM (Phase 4) ───────────────────────────────────────────
    path('siem/threats/',                   views.siem_threat_summary, name='siem_threats'),
    path('siem/alerts/',                    views.siem_alerts,         name='siem_alerts'),
    path('siem/playbook/',                  views.siem_playbook,       name='siem_playbook'),
]