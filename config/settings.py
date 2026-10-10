"""
Django settings for the Academic Publication & Payment Tracking System (PoC).

Stack : Django 5.x + SQLite (PoC database)
Roles : ADMIN (full access / remote tracking bypass)
        BDE     (sales: create projects, authors, submit payment proofs)
        ACCOUNTS(verify payments, update acceptance / publication links)

NOTE ON PoC vs PRODUCTION
-------------------------
* DEBUG=True, ALLOWED_HOSTS=['*'] and the SQLite file are acceptable for a
  proof-of-concept only.  See the "PRODUCTION HARDENING" comments below for
  the flags that must change before going live.
"""

from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env file
env_file = BASE_DIR / '.env'
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, val = line.split('=', 1)
                os.environ.setdefault(key, val.strip("'\""))

# ---------------------------------------------------------------------------
# SECURITY WARNING: keep the secret key used in production secret!
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get('SECRET_KEY', 'django-insecure-poc-key-publication-tracker-change-me')

# Field-level encryption secret (FTSD 7.0 -- phone numbers + UTRs at rest).
# PRODUCTION: replace with a dedicated random secret (any long random string
# works; the cipher keys are derived via SHA-256).  Rotating it makes existing
# ciphertext undecryptable, so store it securely (vault / env var).
FIELD_ENC_KEY = os.environ.get('FIELD_ENC_KEY', 'poc-field-enc-key-psmp-change-me-too')

# PRODUCTION: set DEBUG = False and list the real hostnames.
DEBUG = os.environ.get('DEBUG', 'True') == 'True'
ALLOWED_HOSTS = ['*']

# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',          # intcomma / intword template filters
    'tracker',                          # <-- our publication tracking app
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',

    # --- Cookie rewrite for HTTPS preview iframes ---------------------------
    # Rewrites session / CSRF cookies to SameSite=None; Secure; Partitioned
    # when the request arrived over HTTPS, so the login keeps working inside
    # the cross-site preview iframe (third-party cookie isolation / CHIPS).
    # Plain-HTTP requests keep Django's SameSite=Lax defaults.
    # Remove for a first-party production deployment.
    'tracker.middleware.CookieIframeCompatMiddleware',

    # --- PoC sandbox helper -------------------------------------------------
    # Keeps the ?XTransformPort=... query parameter alive on every redirect
    # so this multi-page Django app works behind the sandbox preview gateway.
    # Remove this class in a normal deployment.
    'tracker.middleware.GatewayPortMiddleware',

    # --- PoC sandbox helper (clean-URL proxy, Task 34) ----------------------
    # The sandbox gateway now serves this app at clean URLs through the
    # platform's Next.js dev server, whose proxy strips trailing slashes.
    # This shim restores the slash in place (no redirect -> no redirect
    # loop).  A no-op for direct deployments; remove outside the sandbox.
    'tracker.middleware.ProxyTrailingSlashMiddleware',

    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',

    # --- Custom location / device security gate ----------------------------
    # Must run AFTER AuthenticationMiddleware so request.user is available.
    # Blocks BDE / ACCOUNTS users whose IP is not on the office whitelist.
    'tracker.middleware.LocationAndDeviceSecurityMiddleware',

    'django.contrib.messages.middleware.MessageMiddleware',
    # NOTE: XFrameOptionsMiddleware is intentionally omitted for the PoC so
    # the app can be embedded in the sandbox preview panel.
    # PRODUCTION: re-enable it and set X_FRAME_OPTIONS = 'DENY' plus a
    # Content-Security-Policy `frame-ancestors 'self'` header.
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                # Renders {{ csrf_token }} (e.g. the <meta name="csrf-token">
                # in base.html) so the fetch() apiPost helper sends the exact
                # server-resolved token instead of guessing from
                # document.cookie -- which breaks when duplicate csrftoken
                # cookies exist (CHIPS-partitioned preview iframe).
                'django.template.context_processors.csrf',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                # Injects `app_role` and the gateway `qp` helper into every
                # template (used by base.html for role-aware navigation).
                'tracker.context_processors.app_context',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

# ---------------------------------------------------------------------------
# Database -- SQLite for the PoC (single file, zero configuration).
# PRODUCTION: switch to PostgreSQL/MySQL and keep credentials in env vars.
# ---------------------------------------------------------------------------
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db' / 'db.sqlite3',
    }
}

# ---------------------------------------------------------------------------
# Password validation (used by the createsuperuser / seed command).
# ---------------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# ---------------------------------------------------------------------------
# Internationalisation -- consultancy operates in IST (Asia/Calcutta).
# ---------------------------------------------------------------------------
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Kolkata'   # IST (a.k.a. Asia/Calcutta)
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
# Added to trigger dev server reload so it discovers the new static/ directory
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ---------------------------------------------------------------------------
# Media (BDE-uploaded payment proof photos / screenshots)
# ---------------------------------------------------------------------------
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# ---------------------------------------------------------------------------
# Authentication entry points
# ---------------------------------------------------------------------------
LOGIN_URL = '/login/'
# '/dashboard/' (dashboard_router dispatches by role) rather than '/':
# behind the sandbox gateway the root path is the Next.js launcher page.
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/login/'

# ---------------------------------------------------------------------------
# CUSTOM SECURITY SETTINGS (consumed by tracker.middleware)
# ---------------------------------------------------------------------------
# Whitelist of office IP addresses from which BDE / ACCOUNTS users may work.
# ADMIN users are always allowed in (remote tracking bypass).
#
# For the PoC the local loopback addresses are whitelisted so the sandbox
# demo works.  PRODUCTION: replace with the real office egress IPs, e.g.
#     OFFICE_IP_ADDRESS = {'203.0.113.10', '203.0.113.11'}
OFFICE_IP_ADDRESS = {'127.0.0.1', '::1'}

# Only honour the X-Forwarded-For header when Django sits behind a *trusted*
# reverse proxy, otherwise the header can be spoofed to bypass the whitelist.
# Keep False for the local PoC; set True in production behind your own proxy.
TRUST_X_FORWARDED_FOR = False

# ---------------------------------------------------------------------------
# CSRF trusted origins (sandbox gateway / preview panel)
# ---------------------------------------------------------------------------
# The sandbox gateway (Caddy) terminates the connection and rewrites the
# Host header (without the port), so the browser's Origin header will not
# match the origin Django derives from the request.  These entries make the
# gateway / preview origins explicitly trusted for CSRF purposes.
# PRODUCTION: restrict this list to your real domain(s), e.g.
#     CSRF_TRUSTED_ORIGINS = ['https://tracker.jvktech.example']
CSRF_TRUSTED_ORIGINS = [
    'http://127.0.0.1:81',      # local gateway testing
    'http://localhost:81',      # local gateway testing (hostname form)
    'https://*.space-z.ai',     # sandbox preview panel (session subdomains)
    'http://*.space-z.ai',
]

# PRODUCTION HARDENING (PoC keeps defaults for local http testing):
#   SECURE_SSL_REDIRECT = True
#   SESSION_COOKIE_SECURE = True
#   CSRF_COOKIE_SECURE = True
#   SECURE_HSTS_SECONDS = 31536000
#   X_FRAME_OPTIONS = 'DENY'
