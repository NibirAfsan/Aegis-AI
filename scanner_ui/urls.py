from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('live-traffic/', views.get_live_traffic, name='live_traffic'),
]