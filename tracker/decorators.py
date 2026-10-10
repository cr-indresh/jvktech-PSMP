"""
View decorators for role-based access control.

`role_required('ACCOUNTS')` style guards sit on every dashboard / API view.
Combined with the model-level clean() checks and the IP whitelist
middleware, this gives three independent layers of enforcement.
"""

from functools import wraps

from django.contrib.auth.views import redirect_to_login
from django.http import HttpResponseForbidden
from django.shortcuts import render

from .models import Role, UserProfile


def get_role(user):
    """Thin alias so views/decorators share one role resolver."""
    return UserProfile.get_role(user)


def role_required(*allowed_roles):
    """
    Allow the view only for the given roles (requires authentication).

    Anonymous users are sent to the login page; authenticated users with a
    different role receive a friendly 403 page.
    """

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect_to_login(request.get_full_path())
            role = get_role(request.user)
            if role not in allowed_roles and not request.user.is_superuser:
                return render(
                    request,
                    'tracker/403.html',
                    {
                        'title': 'Insufficient permissions',
                        'message': (
                            f'Your role ({Role(role).label if role else "unknown"}) '
                            f'cannot access this page.'
                        ),
                        'detected_ip': None,
                        'explanation': (
                            'This dashboard is restricted to: '
                            + ', '.join(Role(r).label for r in allowed_roles) + '.'
                        ),
                    },
                    status=403,
                )
            return view_func(request, *args, **kwargs)

        return _wrapped

    return decorator
