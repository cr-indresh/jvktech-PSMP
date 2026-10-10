"""
Root URL configuration.

Django admin stays mounted at /admin/ as an administrative safety net
(e.g. correcting a saved author, which BDEs are forbidden to edit);
the PoC itself lives in tracker.urls.

In DEBUG the dev server also serves the BDE-uploaded payment proofs
(django-poc/media/**) at /media/ — the Accounts team views them through
the proof viewer modal.  PRODUCTION: serve media through nginx/Caddy and
 REQUIRE the office network / authentication at that layer too.
"""

from django.conf import settings
from django.contrib import admin
from django.urls import include, path, re_path

from tracker import views as tracker_views

# URLconf order matters: tracker.urls ends in a catch-all route (friendly
# branded 404 for hand-typed junk URLs, even with DEBUG=True), so the
# /media/ proof-file routes MUST be listed BEFORE the tracker include or
# the catch-all would shadow them.
urlpatterns = [
    path('admin/', admin.site.urls),
]

if settings.DEBUG:
    # DEBUG-only proof uploads (django-poc/media/**).  tracker's wrapper
    # (serve_media) turns missing files into a plain 404 instead of
    # Django's technical debug page.  PRODUCTION: nginx/Caddy + auth.
    urlpatterns += [
        re_path(r'^media/(?P<path>.*)$', tracker_views.serve_media),
    ]

urlpatterns += [
    path('', include('tracker.urls')),
]

# Styled 404 for ANY unmatched URL once DEBUG=False (production); in
# DEBUG mode the same page is produced by the catch-all route at the end
# of tracker.urls (tracker.views.styled_404_catchall).
handler404 = 'tracker.views.styled_404'
