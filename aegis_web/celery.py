"""
aegis_web/celery.py
====================
Celery app configuration — adapted for YOUR project name (aegis_web).

After creating this file you must add two lines to aegis_web/__init__.py:
    from .celery import app as celery_app
    __all__ = ('celery_app',)
"""

import os
from celery import Celery

# Point at YOUR settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aegis_web.settings')

app = Celery('aegis_web')

# Load CELERY_* settings from Django settings.py
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks.py in all installed apps
app.autodiscover_tasks()