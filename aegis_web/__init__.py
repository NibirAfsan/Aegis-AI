# This file makes aegis_web a Python package AND wires Celery into Django.
# These two lines are required for Celery to work with Django.
from .celery import app as celery_app
__all__ = ('celery_app',)