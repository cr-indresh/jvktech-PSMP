"""
Custom middleware for the Academic Publication & Payment Tracking System.

Classes
-------
LocationAndDeviceSecurityMiddleware
    Strict access control: BDE and ACCOUNTS users may only use the system
    from whitelisted OFFICE IP addresses (settings.OFFICE_IP_ADDRESS).
    ADMIN users are explicitly allowed to bypass the check so they can
    track operations remotely.

CookieIframeCompatMiddleware
    Rewrites session / CSRF cookies so the login flow keeps working when
    the app is displayed inside an HTTPS preview iframe (third-party
    cookie isolation / CHIPS).

GatewayPortMiddleware
    PoC-only helper for the sandbox preview gateway.  It propagates the
    ?XTransformPort=... query parameter onto every redirect response so the
    multi-page Django app stays addressable behind the single exposed port.
    Delete this class (and its entry in settings.MIDDLEWARE) when deploying
    the project outside the sandbox.

ProxyTrailingSlashMiddleware
    PoC-only helper for the sandbox preview gateway's clean-URL proxy:
    restores the trailing slash the proxy strips, in place (no redirect).
    A no-op in direct deployments; delete outside the sandbox.
"""

from http import cookies as _http_cookies
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render

from .models import Role, UserProfile

# ---------------------------------------------------------------------------
# 'Partitioned' (CHIPS) is only a known http.cookies attribute from
# Python 3.14 onwards.  Register it manually so cookie morsels can carry it
# on older interpreters; render it as a bare flag (no '=value').
# ---------------------------------------------------------------------------
_http_cookies.Morsel._reserved.setdefault('partitioned', 'Partitioned')
_http_cookies.Morsel._flags.add('partitioned')

# Paths that must stay reachable even when the IP check fails (login page
# assets etc.).  The middleware already skips anonymous users, so in
# practice only static assets of *authenticated* restricted users matter.
# '/logout/' stays reachable so a blocked user can always end their
# session cleanly (e.g. to hand the machine to an administrator).
EXEMPT_PREFIXES = ('/static/', '/favicon', '/logout/')


def get_client_ip(request):
    """
    Resolve the real client IP.

    The X-Forwarded-For header is only trusted when the project runs behind
    a reverse proxy we control (settings.TRUST_X_FORWARDED_FOR = True);
    otherwise a client could spoof the header and bypass the whitelist.
    """
    if getattr(settings, 'TRUST_X_FORWARDED_FOR', False):
        # Behind a trusted proxy the first entry is the original client.
        forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
        if forwarded:
            return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


class LocationAndDeviceSecurityMiddleware:
    """
    Location & device security gate (office IP whitelist).

    Rule table
    ----------
    +---------------------+---------------------------+--------------------+
    | Role                | Where may they work from? | Enforcement        |
    +---------------------+---------------------------+--------------------+
    | ADMIN               | anywhere (remote bypass)  | allowed            |
    | BDE / ACCOUNTS      | office IP whitelist only  | 403 otherwise      |
    | anonymous visitors  | login page only           | skipped (no role) |
    +---------------------+---------------------------+--------------------+

    ==========================================================================
    PRODUCTION INTEGRATION POINTS (GPS / device binding)
    ==========================================================================
    1) GPS COORDINATE LOCKING
       -----------------------------------------------
       The client app (browser or a companion desktop/mobile agent) would
       attach the employee's GPS fix to every request, e.g. as headers:

           X-Geo-Latitude : 12.971599
           X-Geo-Longitude: 77.594566
           X-Geo-Accuracy : 25          (metres)
           X-Geo-Token    : <HMAC(lat|lng|ts|device_id, server_secret)>

       Inside __call__(), *after* the IP whitelist passes, you would then:

           lat = float(request.META.get('HTTP_X_GEO_LATITUDE', 0))
           lng = float(request.META.get('HTTP_X_GEO_LONGITUDE', 0))
           if haversine_km((lat, lng), settings.OFFICE_GPS_COORDS) \
                   > settings.OFFICE_GEOFENCE_RADIUS_KM:
               return self._blocked(request, reason='outside_geofence')

       ...where haversine_km() computes the great-circle distance between
       the reported fix and the office coordinates.  The signed
       X-Geo-Token (HMAC over the coordinates + timestamp + device id,
       verified server-side) prevents clients from replaying a valid old
       fix from home.

    2) SYSTEM / DEVICE TOKEN VALIDATION
       -----------------------------------------------
       Each office machine is registered once (DeviceRegistry model: user,
       device_id, public key / hardware fingerprint, approved_by_admin).
       Every request then carries a rotating short-lived token:

           X-Device-Token : base64(device_id, nonce, expiry, HMAC(...))

       In this middleware you would verify that the token
         a) belongs to a DeviceRegistry row approved for request.user,
         b) has a valid expiry (e.g. 60 seconds) and unused nonce
            (replay protection, checked against a cache/DB set),
         c) has a valid HMAC signature made with the device secret.
       Failure => 403 with reason 'unregistered_device'.

    3) TRUSTED PROXY HANDLING
       -----------------------------------------------
       In production Django sits behind nginx/Caddy; enable
       settings.TRUST_X_FORWARDED_FOR = True ONLY then, and strip/normalise
       the header at the proxy so it cannot be spoofed (see get_client_ip).
    ==========================================================================
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, 'user', None)

        if user is not None and user.is_authenticated:
            role = UserProfile.get_role(user)

            # ADMIN (and superusers) get the documented remote bypass so the
            # leadership can track operations from anywhere in the world.
            if role == Role.ADMIN or user.is_superuser:
                return self.get_response(request)

            # Restricted roles (BDE / ACCOUNTS): enforce the office whitelist
            # for every page except the exempt static assets.
            if role in (Role.BDE, Role.ACCOUNTS):
                if not request.path.startswith(EXEMPT_PREFIXES):
                    ip = get_client_ip(request)
                    whitelist = set(getattr(settings, 'OFFICE_IP_ADDRESS', set()))
                    if ip not in whitelist:
                        return self._blocked(request, ip=ip, role=role)

        return self.get_response(request)

    # ---------------------------------------------------------------------
    def _blocked(self, request, ip, role):
        """Render a friendly (but firm) 403 page explaining the block."""
        response = render(
            request,
            'tracker/403.html',
            {
                'title': 'Office network required',
                'message': (
                    'Your role ({role}) may only access this system from a '
                    'whitelisted office network. This security policy is '
                    'enforced by LocationAndDeviceSecurityMiddleware.'
                ).format(role=Role(role).label if role else 'unknown'),
                'detected_ip': ip,
                'explanation': (
                    'Access from outside the office is restricted for Sales and '
                    'Accounts roles. Administrators retain remote access for '
                    'tracking. Please connect from the office network or contact '
                    'the IT administrator.'
                ),
            },
            status=403,
        )
        # Never cache a security block page.
        response['Cache-Control'] = 'no-store'
        return response


class CookieIframeCompatMiddleware:
    """
    Keep the login flow alive inside cross-site HTTPS preview iframes.

    WHY THIS EXISTS
    ---------------
    Django's default cookies (``SameSite=Lax``, no ``Secure``) are perfectly
    fine for first-party browsing — and that is why every local test passed.
    The sandbox preview panel, however, embeds this app inside an iframe on a
    *different* registrable domain.  In that third-party context browsers
    (Chrome third-party-cookie phaseout, Safari ITP, Firefox ETP) refuse to
    store / return ``SameSite=Lax`` cookies, so the login POST arrives with
    no ``csrftoken`` cookie and Django answers "403 CSRF cookie not set" —
    the exact "login is not working" symptom.

    THE FIX (per request, no static Secure flags)
    --------------------------------------------
    When the request reached us over HTTPS (detected via X-Forwarded-Proto /
    X-Forwarded-Scheme / the browser's own Origin / Referer headers or
    request.is_secure()), every Set-Cookie emitted on the response is
    rewritten to::

        SameSite=None; Secure; Partitioned

    * ``SameSite=None; Secure``  -> allowed in third-party contexts.
    * ``Partitioned`` (CHIPS)    -> Chrome stores the cookie in a
      per-top-level-site partition instead of blocking it outright.

    Plain-HTTP requests (local development / office LAN PoC deployments)
    keep Django's defaults — static ``SESSION_COOKIE_SECURE`` settings would
    break those, which is why the rewrite is dynamic.

    PRODUCTION: if the real deployment is first-party (no iframe), delete
    this class and its MIDDLEWARE entry; nothing else depends on it.
    Safari (no CHIPS support) still blocks third-party cookies — users on
    Safari should open the app in a dedicated tab rather than the embedded
    preview.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    # -- helpers ------------------------------------------------------------
    @staticmethod
    def _request_is_https(request):
        """Best-effort detection of the public-facing scheme."""
        # 1) Reverse-proxy scheme headers (Caddy sets X-Forwarded-Proto).
        proto = (
            request.META.get('HTTP_X_FORWARDED_PROTO', '')
            or request.META.get('HTTP_X_FORWARDED_SCHEME', '')
        )
        # A chain of proxies sends comma-separated values; first = client-most
        if proto.split(',')[0].strip().lower() == 'https':
            return True
        # 2) Django's own notion (honours SECURE_PROXY_SSL_HEADER if set).
        if request.is_secure():
            return True
        # 3) The browser's Origin / Referer reveal the public scheme of the
        #    page that issued the request (POST always carries Origin).
        for header in ('HTTP_ORIGIN', 'HTTP_REFERER'):
            if request.META.get(header, '').lower().startswith('https://'):
                return True
        # 4) Chromium / Firefox tag requests spawned from a different site
        #    (i.e. our preview iframe).  A cross-site embed that can carry
        #    cookies at all is necessarily served from an HTTPS top-level
        #    context (plain-HTTP cross-site embedding cannot work with
        #    cookies under any flag combination), so treat it as secure.
        if request.META.get('HTTP_SEC_FETCH_SITE', '').lower() == 'cross-site':
            return True
        return False

    # -- entry point ----------------------------------------------------------
    def __call__(self, request):
        response = self.get_response(request)

        if self._request_is_https(request):
            for morsel in response.cookies.values():
                morsel['samesite'] = 'None'
                morsel['secure'] = True
                morsel['partitioned'] = True

        return response


class GatewayPortMiddleware:
    """
    Sandbox preview helper -- NOT part of the product design.

    The sandbox exposes a single port through a gateway; requests carrying
    ``?XTransformPort=<port>`` are proxied to that local port (Caddy).
    Because Django answers with redirects (login_required, role routing,
    post-save redirects) whose Location would normally drop that query
    parameter, this middleware re-appends it to every redirect response so
    navigation keeps hitting the Django service.

    Remove this class and its MIDDLEWARE entry in any real deployment.
    """

    PARAM = 'XTransformPort'

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        port = request.GET.get(self.PARAM)
        if port and response.status_code in (301, 302, 303, 307, 308):
            location = response.get('Location', '')
            if location:
                parts = urlsplit(location)
                # NOTE: check actual parameter NAMES (parse_qsl), not a raw
                # substring -- the gateway param may legitimately appear
                # URL-encoded inside another parameter's value (e.g. the
                # login `next=/...?XTransformPort=8020` payload).
                params = parse_qsl(parts.query, keep_blank_values=True)
                if not any(key == self.PARAM for key, _ in params):
                    params.append((self.PARAM, port))
                    response['Location'] = urlunsplit(
                        (parts.scheme, parts.netloc, parts.path,
                         urlencode(params), parts.fragment)
                    )
        return response


class ProxyTrailingSlashMiddleware:
    """
    Sandbox preview helper -- NOT part of the product design.

    Since Task 34 the gateway serves this app at clean URLs: the platform's
    Next.js dev server transparently proxies every non-Next path to the
    Django service.  That proxy strips the trailing slash from page URLs
    (``/login/`` arrives as ``/login``), and Django's APPEND_SLASH answer
    (301 -> ``/login/``) would loop forever because the proxy strips the
    slash again on the follow-up request.

    This middleware resolves the situation IN PLACE -- no redirect at all:
    when the incoming path has no trailing slash and does not look like a
    file, the slash is restored on ``request.path_info`` (used by the URL
    resolver) and ``request.path`` (used for active-navigation checks)
    BEFORE routing, so the correct view simply serves the request.

    Direct deployments (runserver / uwsgi behind nginx) always send the
    slashed path anyway, which makes this class a no-op there.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path_info
        if (
            path
            and not path.endswith('/')
            and not path.startswith(('/static/', '/media/'))
            and '.' not in path.rsplit('/', 1)[-1]   # file-like (favicon.ico etc.)
        ):
            request.path_info = path + '/'
            request.path = request.path + '/'
        return self.get_response(request)
