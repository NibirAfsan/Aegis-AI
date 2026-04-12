from django.urls import path
from . import views

urlpatterns = [
    path('',                                views.home,             name='home'),
    path('start-scan/',                     views.start_scan,       name='start_scan'),
    path('scan-status/<str:task_id>/',      views.scan_status,      name='scan_status'),
    path('scan-results/<int:scan_id>/',     views.get_scan_results, name='scan_results'),
    path('generate-report/<int:scan_id>/',  views.generate_report,  name='generate_report'),
    path('initiate-attack/',                views.initiate_attack,  name='initiate_attack'),
    path('attack-status/<str:task_id>/',    views.attack_status,    name='attack_status'),
    path('live-traffic/',                   views.get_live_traffic, name='live_traffic'),
    path('attack-plan/<int:scan_id>/', views.view_attack_plan, name='attack_plan'),
]