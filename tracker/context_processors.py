"""
Context processor injecting globally useful values into every template:

* app_role : the logged-in user's role (ADMIN / BDE / ACCOUNTS) or None --
             used by base.html to render role-aware navigation.
* qp       : ready-made query string ("?XTransformPort=8020") when the app
             is reached through the sandbox preview gateway, else "".
             Templates append it to internal links, e.g.:

                 href="{% url 'tracker:bde_dashboard' %}{{ qp }}"

* xport    : the raw gateway port value (used by inline JS to build
             fetch() URLs without losing the parameter).
* nav_bdes : for ADMIN viewers only -- the active BDE executives, so the
             sidebar can offer read-only "view as" links to each sales
             dashboard (admin feature: see views.bde_dashboard).
"""


def app_context(request):
    from django.contrib.auth.models import User

    from .models import Role, UserProfile

    user = getattr(request, 'user', None)
    role = UserProfile.get_role(user) if user else None

    xport = request.GET.get('XTransformPort', '')

    context = {
        'app_role': role,
        'xport': xport,
        'qp': f'?XTransformPort={xport}' if xport else '',
    }

    # Only query the BDE roster for admins (sidebar view-as links).
    if user is not None and user.is_authenticated and (
        user.is_superuser or role == Role.ADMIN
    ):
        context['nav_bdes'] = (
            User.objects
            .filter(profile__role=Role.BDE, is_active=True)
            .order_by('first_name', 'username')
        )

    return context
