from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

# Loaded from .env — never hardcoded
SECRET_KEY = os.environ.get(
    'SECRET_KEY',
    'django-insecure-fallback-only-for-dev'   # fallback if .env missing
)

DEBUG = True

ALLOWED_HOSTS = []

INSTALLED_APPS = [
    'scanner_ui',
    'core',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'aegis_web.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'aegis_web.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True
STATIC_URL = 'static/'

# ── Celery ────────────────────────────────────────────────────────────────────
CELERY_BROKER_URL      = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND  = 'redis://localhost:6379/0'
CELERY_ACCEPT_CONTENT  = ['json']
CELERY_TASK_SERIALIZER = 'json'

# ── AI providers — loaded from .env, never hardcoded ─────────────────────────
GEMINI_API_KEY    = os.environ.get('GEMINI_API_KEY')
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY')   # add when you get it
GROQ_API_KEY = os.environ.get('GROQ_API_KEY')

# Which provider to use — change this one line to switch
AI_PROVIDER = os.environ.get('AI_PROVIDER', 'gemini')