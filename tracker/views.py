"""
Views for the Publication & Sales Operations Management Portal (PSMP).

+-------------+----------------------------------------------+------------------------+
| Role        | Views                                        | Hard guarantees        |
+-------------+----------------------------------------------+------------------------+
| BDE         | bde_dashboard, project_create,               | cannot clear payments  |
|             | project_detail + author / payment /         | (incl. their own);     |
|             | project-detail edits (own projects only)    | edits limited to       |
|             |                                              | own projects; can      |
|             |                                              | NEVER delete a project |
| ACCOUNTS    | accounts_dashboard, set_verification,        | cannot alter           |
|             | update_project_status (JSON APIs)            | sale_value/discount    |
| ADMIN       | admin_dashboard (filterable analytics +      | team mutations are     |
|             | CSV export + aging), service_catalog,        | limited to BDE+ACCOUNTS|
|             | audit_log, team_management,                  | roles; view-as BDE &   |
|             | project_delete (the ONLY role allowed to     | accounts overview are  |
|             | delete a project), bde_dashboard ?as=<id>    | strictly non-mutating  |
|             | (READ-ONLY view-as), accounts_dashboard      |                        |
|             | (READ-ONLY overview)                         |                        |
+-------------+----------------------------------------------+------------------------+

Every mutating endpoint re-checks the role server-side (role_required) --
never trust the UI to hide buttons.  Every critical operation is written
to the AuditLog trail (FTSD 7.0).
"""

import csv
import json

from datetime import date as date_class
from decimal import Decimal
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Max, ProtectedError, Q, Sum
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST
from urllib.parse import quote as url_quote

from .decorators import get_role, role_required
from .forms import (
    AuthorEditFormSet,
    AuthorFormSet,
    InstallmentEditForm,
    InstallmentFormSet,
    LoginForm,
    PaymentInstallmentForm,
    ProjectEditForm,
    ProjectForm,
    ProjectStatusForm,
    ServiceTypeForm,
    TeamMemberForm,
)
from .models import (
    AuditAction,
    AuditLog,
    PaymentInstallment,
    PaymentType,
    Project,
    PublicationStatus,
    Role,
    ServiceType,
    UserProfile,
    VerificationStatus,
    log_action,
)

# Demo accounts surfaced on the login screen (PoC convenience only).
DEMO_ACCOUNTS = [
    {'username': 'admin', 'password': 'Admin@123', 'role': 'ADMIN',
     'label': 'Admin — full analytics & remote access'},
    {'username': 'bde.priya', 'password': 'Demo@123', 'role': 'BDE',
     'label': 'BDE (Sales) — create projects & payment proofs'},
    {'username': 'bde.arjun', 'password': 'Demo@123', 'role': 'BDE',
     'label': 'BDE (Sales) — second sales executive'},
    {'username': 'acc.meera', 'password': 'Demo@123', 'role': 'ACCOUNTS',
     'label': 'Accounts — verify payments & publication links'},
]


# ===========================================================================
# Audit helpers (FTSD 7.0 -- Timestamp, User, Action, Old/New values)
# ===========================================================================
def _json_safe(value):
    """Make a model_to_dict value JSON-serialisable for the audit trail."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _audit_snapshot(instance, fields=None):
    """Field -> value snapshot of an instance (Decimals / files stringified).

    ForeignKey values are resolved to their ``str()`` representation so the
    admin audit trail shows readable names ("Paid by author: Dr. A. K.
    Verma (1st Position)") instead of bare database ids.
    """
    try:
        from django.forms.models import model_to_dict
        from django.db.models import ForeignKey, OneToOneField
        data = model_to_dict(instance, fields=fields)
        # Resolve FK pks -> related-object labels for readable audit diffs.
        for f in instance._meta.concrete_fields:
            if isinstance(f, (ForeignKey, OneToOneField)) and data.get(f.name) is not None:
                try:
                    related = f.related_model.objects.filter(pk=data[f.name]).first()
                    if related is not None:
                        data[f.name] = str(related)
                except Exception:
                    pass
        return {k: _json_safe(v) for k, v in data.items()}
    except Exception:
        return {}


# ===========================================================================
# Authentication
# ===========================================================================
def login_view(request):
    """Custom login (uses the Tailwind-styled LoginForm from forms.py)."""
    if request.user.is_authenticated:
        # '/dashboard/' (not '/'): behind the sandbox gateway the root path
        # belongs to the launcher page, so signed-in users are routed to the
        # role dispatcher at /dashboard/ directly.
        return redirect('tracker:dashboard')

    form = LoginForm(request, data=request.POST or None)

    if request.method == 'POST' and form.is_valid():
        user = form.get_user()
        auth_login(request, user)
        # FTSD 7.0 oversight: every sign-in lands in the admin audit trail
        # (especially Accountants and BDEs -- the roles the admin oversees).
        log_action(request, 'LOGIN', user.profile,
                   label=f'{user.get_full_name() or user.username} signed in')
        messages.success(
            request,
            f'Welcome back, {user.get_full_name() or user.username}! '
            f'You are signed in as {Role(UserProfile.get_role(user)).label if UserProfile.get_role(user) else "user"}.',
        )

        # Open-redirect protection: only same-app relative targets allowed.
        next_url = request.POST.get('next') or request.GET.get('next')
        if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
            return redirect(next_url)
        return redirect('tracker:dashboard')

    return render(request, 'tracker/login.html', {'form': form, 'demo_accounts': DEMO_ACCOUNTS})


def logout_view(request):
    """
    End the session and return to the login screen.

    Accepts BOTH POST (the CSRF-safe <form> button rendered in the sidebar)
    and GET.  GET support is deliberate: typing, bookmarking or browser
    history navigation to /logout/ used to answer 405 ("This page isn't
    working" in Chrome), which looked like a crash to users.  Logout is
    idempotent, so serving GET costs nothing.

    The view also intentionally drops @login_required: an anonymous visitor
    hitting /logout/ is simply redirected to the login page instead of being
    bounced through a login with ?next=/logout/ that would log them straight
    back out after signing in.
    """
    # Log the sign-out BEFORE the session is destroyed (request.user must
    # still be authenticated for log_action to attribute the entry).
    if request.user.is_authenticated:
        log_action(request, 'LOGOUT', request.user.profile,
                   label=f'{request.user.get_full_name() or request.user.username} signed out')

    if request.method == 'POST':
        # Only the POST branch flashes the toast (a GET hit is usually an
        # accidental re-visit of an old URL -- no notification needed).
        auth_logout(request)
        messages.info(request, 'You have been signed out securely.')
        return redirect('tracker:login')
    # GET (or any other method): perform the logout too, then land on login.
    auth_logout(request)
    return redirect('tracker:login')


@login_required
def dashboard_router(request):
    """'/' -- send each role to its own dashboard."""
    role = get_role(request.user)
    if request.user.is_superuser or role == Role.ADMIN:
        return redirect('tracker:admin_dashboard')
    if role == Role.ACCOUNTS:
        return redirect('tracker:accounts_dashboard')
    return redirect('tracker:bde_dashboard')


# ===========================================================================
# BDE (Sales) workflow
# ===========================================================================
def _bde_context(request, bde_user, form=None, author_formset=None, installment_formset=None):
    """Shared context for the BDE dashboard (GET list + create form).

    `bde_user` is the sales executive whose projects are shown -- normally the
    logged-in BDE, but an ADMIN may pass ?as=<id> to view any BDE's dashboard
    (read-only oversight; see bde_dashboard below -- the admin's OWN
    workspace at /bde/ has the full creation form).
    """
    projects = (
        Project.objects
        .filter(bde=bde_user)
        .select_related('service_type')
        .prefetch_related('authors', 'installments')
        .order_by('-created_at')
    )

    cleared = PaymentInstallment.objects.filter(
        project__bde=bde_user, verification_status=VerificationStatus.VERIFIED,
    )
    awaiting = PaymentInstallment.objects.filter(
        project__bde=bde_user, verification_status=VerificationStatus.PENDING,
    )

    stats = {
        'project_count': projects.count(),
        'net_value': sum((p.net_value for p in projects), Decimal('0')),
        'collected': cleared.aggregate(s=Sum('amount_paid'))['s'] or Decimal('0'),
        'pending_count': awaiting.count(),
        'pending_amount': awaiting.aggregate(s=Sum('amount_paid'))['s'] or Decimal('0'),
    }

    # Service catalogue info (FTSD 4.1.2) -- consumed by the dashboard JS:
    # slot caps for the "Add author" button + base prices shown in the
    # provisioning note.  Injected as a JSON <script> by json_script.
    service_info = {
        str(s.id): {'slots': s.default_slots, 'base': str(s.base_price),
                    'name': s.name}
        for s in ServiceType.objects.filter(is_active=True)
    }

    return {
        'projects': projects,
        'stats': stats,
        'form': form or ProjectForm(),
        'author_formset': author_formset or AuthorFormSet(prefix='authors'),
        'installment_formset': installment_formset or InstallmentFormSet(prefix='installments'),
        'service_info': service_info,
        'active_services': ServiceType.objects.filter(is_active=True),
    }


@login_required
@role_required(Role.BDE, Role.ADMIN)
def bde_dashboard(request):
    """
    BDE landing page: KPI cards, project creation form, my projects.

    ADMIN ACCESS (every BDE action)
    -------------------------------
    An admin may append ``?as=<bde_user_id>`` to inspect any sales
    executive's dashboard (amber "viewing as" banner, creation form hidden),
    or open ``/bde/`` directly to get their OWN full sales workspace with
    the creation form -- whatever a BDE can do, the admin can do too.
    """
    role = get_role(request.user)

    if role == Role.BDE:
        # A genuine BDE always sees their own dashboard -- ?as= is ignored so
        # a BDE can never read a colleague's numbers.
        return render(request, 'tracker/bde_dashboard.html', _bde_context(request, request.user))

    # ADMIN / superuser: view-as mode, or their own full workspace.
    as_id = request.GET.get('as', '')
    target = (
        User.objects.select_related('profile')
        .filter(pk=as_id, profile__role=Role.BDE, is_active=True)
        .first()
        if as_id.isdigit() else None
    )
    if target is None:
        # No (or stale) ?as= : the admin's own sales workspace -- the full
        # creation form is available here (see project_create).
        return render(request, 'tracker/bde_dashboard.html', _bde_context(request, request.user))

    context = _bde_context(request, target)
    context['view_as'] = target
    context['view_as_projects'] = target.projects_sold.count()
    return render(request, 'tracker/bde_dashboard.html', context)


def _resolve_deal_owner(request):
    """
    For an ADMIN submission of the creation form: the User who will OWN the
    deal.  The form renders an admin-only "Deal owner" dropdown listing
    every active BDE (plus "Myself"); BDE submitters never pass through
    here -- a BDE always owns what they sell.
    """
    owner_id = request.POST.get('deal_owner', '')
    if owner_id.isdigit():
        owner = (
            User.objects.select_related('profile')
            .filter(pk=owner_id, is_active=True)
            .first()
        )
        if owner is not None and UserProfile.get_role(owner) == Role.BDE:
            return owner
    return request.user


@login_required
@role_required(Role.BDE, Role.ADMIN)
def project_create(request):
    """
    Handle the dynamic multi-form POST from the BDE dashboard (an admin
    may submit it from their own BDE workspace -- every BDE action):

        ProjectForm          -> commercial fields
        AuthorFormSet        -> 1+ author slot bookings (capped at the
                               provisioned total_slots)
        InstallmentFormSet   -> payment logs (transaction refs + proofs)

    SLOT PROVISIONING (FTSD 4.1): the application -- not the BDE -- derives
    the project's total author slots from the selected service's catalogue
    config (``default_slots``).  Booking more authors than provisioned
    slots is rejected here (the UI disables the button as well).

    All three forms are validated TOGETHER; anything invalid re-renders the
    dashboard with the submitted data plus inline errors (no data loss).

    SECURITY: only a genuine BDE-role user -- or an ADMIN from their own
    BDE workspace -- may create a project.  Everyone else is explicitly
    rejected here, so the superuser bypass inside role_required alone is
    never enough.
    """
    role = get_role(request.user)
    if role not in (Role.BDE, Role.ADMIN):
        return render(request, 'tracker/403.html', {
            'title': 'Creation is disabled',
            'message': 'Only BDE (sales) users and administrators can create projects.',
            'detected_ip': None,
            'explanation': (
                'Whatever a BDE can do, an admin can do too -- open the '
                'BDE Workspace in the sidebar to create a project.'
            ),
        }, status=403)

    if request.method != 'POST':
        return redirect('tracker:bde_dashboard')

    form = ProjectForm(request.POST)
    author_formset = AuthorFormSet(request.POST, prefix='authors')
    # request.FILES carries the optional transaction proof photos / PDFs
    # (the dashboard creation form posts multipart/form-data).
    installment_formset = InstallmentFormSet(
        request.POST, request.FILES, prefix='installments',
    )
    # "Schedule the remaining later": the BDE may deliberately schedule
    # only PART of the payable amount today and fill the balance in from
    # the project page over time (see project_payment_add).
    defer_remaining = request.POST.get('defer_remaining') == '1'

    # Validate everything up-front so cleaned_data exists on every bound form.
    form_valid = form.is_valid()
    authors_valid = author_formset.is_valid()
    installments_valid = installment_formset.is_valid()

    # -- cross-form validation needs the cleaned commercial fields -----
    authors = [f for f in author_formset.forms
               if getattr(f, 'cleaned_data', None) and f.cleaned_data.get('name')]
    installments = [f for f in installment_formset.forms
                    if getattr(f, 'cleaned_data', None)
                    and f.cleaned_data.get('amount_paid') is not None]

    errors = []
    total_slots = None

    if form_valid:
        service = form.cleaned_data['service_type']
        # The application provisions the author slots (FTSD 4.1.2).
        total_slots = service.default_slots
        if not authors:
            errors.append('At least one author slot booking is required.')
        elif len(authors) > total_slots:
            errors.append(
                f'"{service.name}" provisions {total_slots} author slot'
                f'{"s" if total_slots != 1 else ""} per title — you cannot book '
                f'{len(authors)} authors on it. Remove '
                f'{len(authors) - total_slots} author row(s).'
            )

        # Paid-by positions must reference an author slot actually booked
        # on THIS submit (the authors are saved 1..N just before the money
        # rows, so position N is valid while the row exists).
        for f in installments:
            pos = f.cleaned_data.get('author_position')
            if pos is not None and int(pos) > len(authors):
                f.add_error(
                    'author_position',
                    f'Only {len(authors)} author slot'
                    f'{"s" if len(authors) != 1 else ""} are being booked on this '
                    'project — pick a valid paying author.',
                )
        installments_valid = installments_valid and not any(
            f.errors for f in installment_formset.forms)

    # Installments: unique phases, positive amounts, and the TOTAL may
    # either EQUAL the payable amount (sale value − discount) or stay
    # BELOW it when the BDE ticked "Schedule the remaining later" -- the
    # balance is then filled in from the project page anytime.  Going
    # OVER the payable amount is always rejected.
    net_value = None
    if form_valid:
        sale = form.cleaned_data['sale_value']
        discount = form.cleaned_data['discount_value'] or Decimal('0')
        net_value = sale - discount
        seen_types = set()
        for f in installments:
            itype = f.cleaned_data.get('payment_type')
            if itype in seen_types:
                errors.append(f'Duplicate installment phase: {f.cleaned_data.get("payment_type")}.')
            seen_types.add(itype)
        total = sum((f.cleaned_data['amount_paid'] for f in installments), Decimal('0'))
        if discount:
            basis = (f'the payable amount (₹{net_value} = sale value ₹{sale} '
                     f'− discount ₹{discount})')
        else:
            basis = f'the sale value (₹{net_value})'
        if total > net_value:
            errors.append(
                f'Payments exceed {basis} by ₹{total - net_value}. '
                f'Lower the installment amounts first.'
            )
        elif total < net_value and not defer_remaining:
            errors.append(
                f'Payments must add up to exactly {basis}. '
                f'Your installments total ₹{total} — ₹{net_value - total} still to '
                f'schedule. Tick "Schedule the remaining later" if you want to '
                f'add the rest from the project page anytime.'
            )
        if not installments and net_value > 0 and not defer_remaining:
            errors.append('At least one payment installment is required.')

    if not (form_valid and authors_valid and installments_valid) or errors:
        for err in errors:
            form.add_error(None, err)
        if not form.is_valid() and not form.errors:
            form.add_error(None, 'Please review the highlighted fields.')
        context = _bde_context(request, request.user, form, author_formset, installment_formset)
        messages.error(request, 'The project could not be saved. Please fix the errors below.')
        return render(request, 'tracker/bde_dashboard.html', context, status=200)

    # -- all good: atomically persist ---------------------------------------
    with transaction.atomic():
        project = form.save(commit=False)
        # Deal owner: the submitting BDE, or -- for an admin -- whoever was
        # picked in the admin-only "Deal owner" dropdown (default: the admin).
        project.bde = (
            request.user if role == Role.BDE else _resolve_deal_owner(request)
        )
        project.total_slots = total_slots   # provisioned from the catalogue
        project.save()

        # Author slots are booked server-side (position 1..N) -- the BDE
        # cannot forge slot numbers, and the UNIQUE (project, position)
        # constraint is the hard slot lock (FTSD 4.1.4).
        saved_authors = []
        for idx, author_form in enumerate(authors, start=1):
            author = author_form.save(commit=False)
            author.project = project
            author.position = idx
            author.save()
            saved_authors.append(author)
        position_to_author = {a.position: a for a in saved_authors}

        next_number = 1
        for inst_form in installments:
            installment = inst_form.save(commit=False)
            installment.project = project
            installment.submitted_by = request.user
            installment.installment_number = next_number   # auto 1, 2, 3 ...
            # Authors pay individually -> link the paying author slot picked
            # on the form (position -> the freshly saved Author row).
            pos = inst_form.cleaned_data.get('author_position')
            if pos is not None:
                installment.author = position_to_author.get(int(pos))
            next_number += 1
            installment.verification_status = VerificationStatus.PENDING  # always starts Pending
            installment.save()
            # Mirror the uploaded proof photo INTO the SQLite database.
            installment.capture_proof_into_db()

        log_action(request, 'CREATE', project,
                   new={**_audit_snapshot(project),
                        'authors_booked': len(authors),
                        'installments_logged': len(installments),
                        'total_slots_provisioned': total_slots},
                   label=f'Project "{project.title}" created')

    messages.success(
        request,
        f'Project "{project.title}" created — {total_slots} author slot'
        f'{"s" if total_slots != 1 else ""} provisioned, {len(authors)} booked, '
        f'{len(installments)} payment log(s).'
        + (
            f' ₹{project.remaining_to_schedule} is still to schedule — add it '
            f'anytime from the project page.'
            if project.remaining_to_schedule > 0
            else ' Accounts will clear the payments.'
        ),
    )
    if role == Role.ADMIN:
        # The admin lands straight on the new deal (their workspace lists
        # only their own projects; an attributed deal belongs to the BDE).
        return redirect('tracker:project_detail', project.pk)
    return redirect('tracker:bde_dashboard')


# ===========================================================================
# ACCOUNTS workflow
# ===========================================================================
def _accounts_stats():
    awaiting = PaymentInstallment.objects.filter(verification_status=VerificationStatus.PENDING)
    cleared = PaymentInstallment.objects.filter(verification_status=VerificationStatus.VERIFIED)
    rejected = PaymentInstallment.objects.filter(verification_status=VerificationStatus.REJECTED)
    return {
        'pending_count': awaiting.count(),
        'pending_amount': awaiting.aggregate(s=Sum('amount_paid'))['s'] or Decimal('0'),
        'verified_count': cleared.count(),
        'verified_amount': cleared.aggregate(s=Sum('amount_paid'))['s'] or Decimal('0'),
        'rejected_count': rejected.count(),
        'rejected_amount': rejected.aggregate(s=Sum('amount_paid'))['s'] or Decimal('0'),
        'published_count': Project.objects.filter(
            publication_status=PublicationStatus.PUBLISHED).count(),
    }


@login_required
@role_required(Role.ACCOUNTS, Role.ADMIN)
def accounts_dashboard(request):
    """
    Accounts landing page: pending clearing queue (Pending + Rejected),
    verified history and the publication-status table (updated through
    the modal).

    ADMIN ACCESS (every Accounts action)
    -----------------------------------
    Whatever the Accounts role can do, the admin can do from this page
    too: the clearing buttons and the publication-status modal are shown
    for admins, and both JSON endpoints accept the ADMIN role (see
    set_verification / update_project_status).
    """
    # FTSD 4.3.1: the dashboard highlights UNVERIFIED transactions -- both
    # the ones never reviewed (Pending) and the ones bounced back (Rejected,
    # awaiting a corrected re-submission by the BDE).
    pending_installments = (
        PaymentInstallment.objects
        .filter(verification_status__in=[VerificationStatus.PENDING,
                                         VerificationStatus.REJECTED])
        .select_related('project', 'project__service_type', 'project__bde',
                        'author', 'submitted_by')
        .order_by('-submitted_at')
    )
    verified_installments = (
        PaymentInstallment.objects
        .filter(verification_status=VerificationStatus.VERIFIED)
        .select_related('project', 'project__service_type', 'project__bde',
                        'author', 'submitted_by', 'verified_by')
        .order_by('-verification_date')[:50]
    )
    projects = (
        Project.objects
        .select_related('service_type', 'bde')
        .prefetch_related('authors', 'installments')
        .order_by('-created_at')
    )

    return render(request, 'tracker/accounts_dashboard.html', {
        'pending_installments': pending_installments,
        'verified_installments': verified_installments,
        'projects': projects,
        'stats': _accounts_stats(),
        # The Accounts role AND admins get the action buttons (whatever an
        # accountant can do, the admin can do too) -- the JSON endpoints
        # enforce the same pair server-side.
        'viewer_is_accounts': get_role(request.user) in (Role.ACCOUNTS, Role.ADMIN),
    })


def _installment_payload(installment):
    """JSON shape returned by the clearing API (mirrors the UI)."""
    return {
        'id': installment.pk,
        'payment_type': installment.get_payment_type_display(),
        'installment_number': installment.installment_number,
        'amount': str(installment.amount_paid),
        'transaction_ref': installment.transaction_ref,
        # The paying author (authors pay individually).
        'author_id': installment.author_id,
        'author_name': installment.author.name if installment.author_id else '',
        'author_position': (
            installment.author.position_label if installment.author_id else ''
        ),
        'payment_mode': installment.get_payment_mode_display(),
        'payment_date': (
            installment.payment_date.strftime('%d %b %Y') if installment.payment_date else ''
        ),
        'remarks': installment.remarks,
        # Proof photo uploaded by the BDE (Accounts opens it in the proof
        # viewer modal); '' when the proof is transaction-ref only.
        # Served DB-first by views.installment_proof_file (proof_data BLOB).
        'proof_url': (
            reverse('tracker:installment_proof_file', args=[installment.pk])
            if installment.proof_image else ''
        ),
        'proof_name': installment.proof_file_name,
        'proof_is_image': installment.proof_is_image,
        'project_id': installment.project_id,
        'project_title': installment.project.title,
        'service_name': installment.project.service_type.name,
        'bde_name': (installment.project.bde.get_full_name() or installment.project.bde.username),
        'submitted_by': (installment.submitted_by.get_full_name() or installment.submitted_by.username),
        'submitted_at': timezone.localtime(installment.submitted_at).strftime('%d %b %Y, %H:%M'),
        'verification_status': installment.verification_status,
        'is_verified': installment.is_verified,
        'verified_by': (
            (installment.verified_by.get_full_name() or installment.verified_by.username)
            if installment.verified_by else ''
        ),
        'verification_date': (
            timezone.localtime(installment.verification_date).strftime('%d %b %Y, %H:%M')
            if installment.verification_date else ''
        ),
    }


def _project_payment_payload(project):
    return {
        'id': project.pk,
        'collected': str(project.total_collected),
        'pending': str(project.total_pending),
        'rejected': str(project.total_rejected),
    }


@login_required
@role_required(Role.ACCOUNTS, Role.ADMIN)
@require_POST
def set_verification(request, pk):
    """
    JSON endpoint: POST /accounts/api/installments/<pk>/verify/
    Body: {"action": "verify" | "reject" | "revert"}

    FTSD 3.3 verification_status transitions (Accounts + Admin):
      Pending  -> Verified   (action=verify,  bank feed matched)
      Pending  -> Rejected   (action=reject,  proof bounced)
      Verified -> Pending    (action=revert,  un-clear -- the approval
                               flow that unlocks a BDE edit, FTSD 7.0)
      Rejected -> Verified   (action=verify,  corrected proof accepted)

    Business rules enforced here (and again in PaymentInstallment.clean()):
      * Only the ACCOUNTS role and ADMINs may call this -- checked
        EXPLICITLY below (the superuser bypass of role_required is not
        trusted on its own): whatever an accountant can do, the admin
        can do too.
      * A user can NEVER clear a payment they submitted themselves.
      * Reverting clears the audit fields (verified_by / date).
    """
    if get_role(request.user) not in (Role.ACCOUNTS, Role.ADMIN):
        return JsonResponse(
            {'error': 'Only the Accounts role (or an administrator) may verify, '
                      'reject or revert payments.'},
            status=403,
        )

    installment = (
        PaymentInstallment.objects
        .select_related('project', 'project__service_type', 'project__bde',
                        'submitted_by')
        .filter(pk=pk)
        .first()
    )
    if installment is None:
        # Stale row (deleted by the BDE meanwhile) -> JSON error, so the
        # dashboard's fetch() handler shows a clean toast instead of an
        # HTML error page.
        return JsonResponse(
            {'error': f'Payment record #{pk} no longer exists — it may have '
                      'been deleted. Reload the page for the current list.'},
            status=404,
        )

    # Defense-in-depth: even if role rules change someday, nobody clears
    # their own submitted proof ("BDEs cannot verify their own payments").
    if installment.submitted_by_id == request.user.id:
        return JsonResponse(
            {'error': 'You cannot clear a payment proof you submitted yourself.'},
            status=403,
        )

    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = {}
    action = payload.get('action') if isinstance(payload, dict) else ''
    if action not in ('verify', 'reject', 'revert'):
        return JsonResponse(
            {'error': 'Invalid action — expected verify, reject or revert.'},
            status=400,
        )

    old_status = installment.verification_status
    old_snapshot = {
        'verification_status': old_status,
        'amount_paid': str(installment.amount_paid),
        'transaction_ref': installment.transaction_ref,
    }

    if action == 'verify':
        installment.verification_status = VerificationStatus.VERIFIED
        installment.verified_by = request.user
        installment.verification_date = timezone.now()
    elif action == 'reject':
        installment.verification_status = VerificationStatus.REJECTED
        installment.verified_by = request.user
        installment.verification_date = timezone.now()
    else:  # revert -> back to Pending, audit fields cleared
        installment.verification_status = VerificationStatus.PENDING
        installment.verified_by = None
        installment.verification_date = None

    installment.full_clean(exclude=['project'])   # model-level guards run here
    installment.save()
    installment.project.save(update_fields=['updated_at'])  # touch updated_at

    log_action(
        request, 'UPDATE', installment,
        old=old_snapshot,
        new={**old_snapshot, 'verification_status': installment.verification_status},
        label=f'Payment #{installment.installment_number} of "{installment.project.title}" '
              f'{old_status} -> {installment.verification_status}',
    )

    return JsonResponse({
        'ok': True,
        'installment': _installment_payload(installment),
        'project': _project_payment_payload(installment.project),
        'stats': {
            k: (str(v) if isinstance(v, Decimal) else v)
            for k, v in _accounts_stats().items()
        },
    })


@login_required
@role_required(Role.ACCOUNTS, Role.ADMIN)
@require_POST
def update_project_status(request, pk):
    """
    Endpoint: POST /accounts/api/projects/<pk>/status/

    Accepts BOTH multipart/form-data (when an acceptance proof FILE is
    uploaded, FTSD 3.4 / 4.3.3) and application/json (quick status-only
    updates from the modal).

    Body fields: publication_status, acceptance_link, publication_url,
    acceptance_file (multipart only).

    Validation happens through ProjectStatusForm which whitelists ONLY
    those fields -> sale_value / discount / authors / BDE can never be
    modified through this endpoint (Accounts cannot alter the sale).

    Like set_verification, the role is re-checked explicitly: the ACCOUNTS
    role and ADMINs may update -- whatever an accountant can do, the admin
    can do too.
    """
    if get_role(request.user) not in (Role.ACCOUNTS, Role.ADMIN):
        return JsonResponse(
            {'error': 'Only the Accounts role (or an administrator) may update '
                      'publication status.'},
            status=403,
        )

    project = (
        Project.objects.select_related('service_type', 'bde')
                       .filter(pk=pk).first()
    )
    if project is None:
        # Stale row (project deleted by an admin meanwhile) -> JSON error
        # so the fetch() caller shows a clean toast instead of an HTML page.
        return JsonResponse(
            {'error': f'Project #{pk} no longer exists — it may have been '
                      'deleted. Reload the page for the current list.'},
            status=404,
        )

    # -- parse the payload (multipart with file, or plain JSON) -----------
    if request.content_type and 'multipart/form-data' in request.content_type:
        payload = {k: v for k, v in request.POST.items()}
        files = request.FILES or None
    else:
        try:
            payload = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON body.'}, status=400)
        if not isinstance(payload, dict):
            return JsonResponse({'error': 'Invalid JSON body.'}, status=400)
        files = None

    old_snapshot = {
        'publication_status': project.publication_status,
        'acceptance_link': project.acceptance_link,
        'publication_url': project.publication_url,
        'acceptance_file': project.acceptance_file.name if project.acceptance_file else '',
    }

    form = ProjectStatusForm(payload, files, instance=project)
    if not form.is_valid():
        return JsonResponse({'error': ' '.join(' '.join(v) for v in form.errors.values()).strip()
                             or 'Invalid data.'}, status=400)

    project = form.save()
    # Acceptance-proof uploads are mirrored INTO the SQLite database
    # (acceptance_data) so the .sqlite3 file stays self-contained.
    project.capture_acceptance_into_db()

    log_action(
        request, 'UPDATE', project,
        old=old_snapshot,
        new={
            'publication_status': project.publication_status,
            'acceptance_link': project.acceptance_link,
            'publication_url': project.publication_url,
            'acceptance_file': project.acceptance_file.name if project.acceptance_file else '',
        },
        label=f'Publication status of "{project.title}"',
    )

    return JsonResponse({
        'ok': True,
        'project': {
            'id': project.pk,
            'title': project.title,
            'publication_status': project.publication_status,
            'publication_status_display': project.get_publication_status_display(),
            'acceptance_link': project.acceptance_link,
            'publication_url': project.publication_url,
            'acceptance_file_url': (
                reverse('tracker:project_acceptance_file', args=[project.pk])
                if project.acceptance_file else ''
            ),
            'acceptance_file_name': (
                project.acceptance_file.name.rsplit('/', 1)[-1]
                if project.acceptance_file else ''
            ),
        },
    })


# ===========================================================================
# ADMIN workflow
# ===========================================================================
def _admin_filtered_projects(request):
    """
    Shared filter engine for the admin dashboard AND the CSV export
    (FTSD 5.0): BDE, publication category, payment status (Fully Paid /
    Advance Paid / Overdue), lifecycle stage, date range, free search.
    """
    qs = (
        Project.objects
        .select_related('service_type', 'bde')
        .prefetch_related('authors', 'installments')
        .order_by('-created_at')
    )

    params = request.GET
    status = params.get('status', '')
    bde_id = params.get('bde', '')
    service_id = params.get('service', '')
    payment_state = params.get('payment_state', '')
    date_from = params.get('date_from', '')
    date_to = params.get('date_to', '')
    search = params.get('q', '').strip()

    if status in PublicationStatus.values:
        qs = qs.filter(publication_status=status)
    if bde_id.isdigit():
        qs = qs.filter(bde_id=int(bde_id))
    if service_id.isdigit():
        qs = qs.filter(service_type_id=int(service_id))
    if date_from:
        qs = qs.filter(created_at__date__gte=date_from)
    if date_to:
        qs = qs.filter(created_at__date__lte=date_to)
    if search:
        qs = qs.filter(
            Q(title__icontains=search) | Q(authors__name__icontains=search)
        ).distinct()

    projects = list(qs)

    # Payment-state filter needs per-project totals (Python post-filter).
    # FTSD 5.0 states: Fully Paid, Advance Paid, Overdue.
    if payment_state == 'fully_paid':
        projects = [p for p in projects
                    if p.net_value > 0 and p.total_collected >= p.net_value]
    elif payment_state == 'advance_paid':
        projects = [p for p in projects
                    if p.total_collected > 0 and p.total_collected < p.net_value]
    elif payment_state == 'overdue':
        projects = [p for p in projects
                    if p.balance_due > 0 and p.payment_state == 'overdue']
    elif payment_state == 'unpaid':
        projects = [p for p in projects if p.total_collected == 0 and p.net_value > 0]

    filters = {
        'status': status,
        'bde': bde_id,
        'service': service_id,
        'payment_state': payment_state,
        'date_from': date_from,
        'date_to': date_to,
        'q': search,
    }
    return projects, filters


@login_required
@role_required(Role.ADMIN)
def admin_dashboard(request):
    """
    Highly filterable analytics over every project (FTSD 5.0) with the
    KPI engine, per-BDE outstanding-balance AGING report, volume
    breakdown by publication category and a one-click CSV EXPORT of the
    currently filtered table.

    Filters (GET): status (7-stage lifecycle), bde, service (category),
    payment_state (fully_paid / advance_paid / overdue / unpaid),
    date_from + date_to, q (title/author search).

    Payment-state filtering and the metric cards are computed in Python on
    the prefetched queryset -- perfectly fine at PoC scale; for large
    datasets swap to Subquery/annotation aggregates.
    """
    projects, filters = _admin_filtered_projects(request)

    # ---- metric cards (over the CURRENTLY FILTERED set) ------------------
    total_net = sum((p.net_value for p in projects), Decimal('0'))
    total_collected = sum((p.total_collected for p in projects), Decimal('0'))
    total_pending = sum((p.total_pending for p in projects), Decimal('0'))
    stats = {
        'project_count': len(projects),
        'net_value': total_net,
        'collected': total_collected,
        'pending_amount': total_pending,
        # FTSD 5.0 KPI: Total Receivables vs Total Collected.
        'receivables': total_net - total_collected,
        'published_count': sum(
            1 for p in projects if p.publication_status == PublicationStatus.PUBLISHED),
        'accepted_count': sum(
            1 for p in projects if p.publication_status == PublicationStatus.ACCEPTED),
        'draft_count': sum(
            1 for p in projects if p.publication_status == PublicationStatus.DRAFT),
    }

    # ---- per-service volume breakdown (FTSD 5.0) -------------------------
    services = list(ServiceType.objects.all())
    breakdown = []
    for service in services:
        count = sum(1 for p in projects if p.service_type_id == service.id)
        breakdown.append({'name': service.name, 'count': count})

    # ---- outstanding balance AGING report per BDE (FTSD 5.0) -------------
    bdes = list(User.objects.filter(profile__role=Role.BDE).order_by('first_name'))
    aging = []
    for bde in bdes:
        rows = [p for p in projects if p.bde_id == bde.id and p.balance_due > 0]
        if not rows:
            continue
        buckets = {'d0_30': Decimal('0'), 'd31_60': Decimal('0'), 'd60_plus': Decimal('0')}
        for p in rows:
            age = p.age_days
            key = 'd0_30' if age <= 30 else ('d31_60' if age <= 60 else 'd60_plus')
            buckets[key] += p.balance_due
        aging.append({
            'bde': bde,
            'bde_name': bde.get_full_name() or bde.username,
            'outstanding': sum(buckets.values(), Decimal('0')),
            'open_projects': len(rows),
            **buckets,
        })
    aging.sort(key=lambda a: a['outstanding'], reverse=True)

    # ---- payment ledger / UTR register (every entry in the database) ---
    # The ADMIN needs the money rows themselves -- with the paying author
    # (authors pay individually) and the Transaction ref (UTR) -- to
    # reconcile collections against bank feeds; each row also carries its
    # database ENTRY ID so a payment can be referenced unambiguously.
    payment_ledger = list(
        PaymentInstallment.objects
        .select_related('project', 'project__service_type', 'project__bde',
                        'author', 'submitted_by', 'verified_by')
        .prefetch_related('project__authors')
        .order_by('-submitted_at', '-id')
    )

    # Paid-by options per ledger row (for the admin payment-override modal):
    # installment pk -> [{id, label}] of the project's booked authors.
    ledger_author_map = {
        str(inst.pk): [
            {'id': a.pk, 'label': f'{a.name} ({a.position_label})'}
            for a in inst.project.authors.all()
        ]
        for inst in payment_ledger
    }

    return render(request, 'tracker/admin_dashboard.html', {
        'projects': projects,
        'stats': stats,
        'service_breakdown': breakdown,
        'aging': aging,
        'payment_ledger': payment_ledger,
        'ledger_author_map_json': json.dumps(ledger_author_map),
        'bdes': bdes,
        'service_types': services,
        'filters': filters,
        'payment_states': [
            ('', 'Payment status: all'),
            ('fully_paid', 'Fully Paid'),
            ('advance_paid', 'Advance Paid'),
            ('overdue', 'Overdue'),
            ('unpaid', 'Unpaid'),
        ],
    })


@login_required
@role_required(Role.ADMIN)
def admin_export_csv(request):
    """
    One-click export of the FILTERED projects table to CSV (FTSD 5.0
    Export Engine; opens cleanly in Excel thanks to the UTF-8 BOM).

    Reuses the exact filter engine of the dashboard, so what you see is
    what you export.
    """
    projects, _filters = _admin_filtered_projects(request)

    response = HttpResponse(content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename="psmp-projects-export.csv"'
    # UTF-8 BOM so Excel detects the encoding (₹ symbol etc.).
    response.write('\ufeff')

    writer = csv.writer(response)
    writer.writerow([
        'Project ID', 'Title', 'Category', 'BDE',
        'Sale Value (INR)', 'Discount (INR)', 'Net Payable (INR)',
        'Collected-Verified (INR)', 'Pending Verification (INR)', 'Balance Due (INR)',
        'Payment State', 'Publication Status',
        'Authors (booked/provisioned)', 'Created', 'Publication URL',
    ])
    for p in projects:
        writer.writerow([
            p.pk,
            p.title,
            p.service_type.name,
            p.bde.get_full_name() or p.bde.username,
            f'{p.sale_value:.2f}',
            f'{p.discount_value:.2f}',
            f'{p.net_value:.2f}',
            f'{p.total_collected:.2f}',
            f'{p.total_pending:.2f}',
            f'{p.balance_due:.2f}',
            p.payment_state.replace('_', ' ').title(),
            p.get_publication_status_display(),
            f'{p.authors_count}/{p.total_slots}',
            timezone.localtime(p.created_at).strftime('%Y-%m-%d'),
            p.publication_url or '',
        ])
    return response


# ===========================================================================
# ADMIN: service catalogue management (FTSD 2.0 / 3.1 -- configurable)
# ===========================================================================
@login_required
@role_required(Role.ADMIN)
def service_catalog(request):
    """
    Admin page: view / add / edit the service catalogue (publication
    categories) with their BASE PRICE and provisioned AUTHOR SLOTS.
    """
    services = ServiceType.objects.all().order_by('name')
    # Pair each service with its bound edit form (templates cannot do
    # dict lookups natively, so we hand over an explicit pairing).
    rows = [
        {'service': service,
         'form': ServiceTypeForm(instance=service, prefix=f'svc{service.id}')}
        for service in services
    ]
    return render(request, 'tracker/service_catalog.html', {
        'services': services,
        'service_rows': rows,
        'form': ServiceTypeForm(),
    })


@login_required
@role_required(Role.ADMIN)
@require_POST
def service_add(request):
    """Add a new service to the catalogue (admin-only)."""
    form = ServiceTypeForm(request.POST)
    if form.is_valid():
        service = form.save()
        log_action(request, 'CREATE', service,
                   new=_audit_snapshot(service), label=f'Service "{service.name}"')
        messages.success(request, f'Service "{service.name}" added to the catalogue.')
    else:
        messages.error(
            request,
            'The service could not be added: '
            + ' '.join(' '.join(v) for v in form.errors.values()),
        )
    return redirect('tracker:service_catalog')


@login_required
@role_required(Role.ADMIN)
@require_POST
def service_update(request, pk):
    """Edit an existing service (base price, slots, active flag ...)."""
    service = ServiceType.objects.filter(pk=pk).first()
    if service is None:
        return redirect('tracker:service_catalog')
    old = _audit_snapshot(service)
    form = ServiceTypeForm(request.POST, instance=service, prefix=f'svc{pk}')
    if form.is_valid():
        service = form.save()
        log_action(request, 'UPDATE', service, old=old,
                   new=_audit_snapshot(service), label=f'Service "{service.name}"')
        messages.success(request, f'Service "{service.name}" updated.')
    else:
        messages.error(
            request,
            f'The service "{service.name}" could not be updated: '
            + ' '.join(' '.join(v) for v in form.errors.values()),
        )
    return redirect('tracker:service_catalog')


# ===========================================================================
# ADMIN: audit trail (FTSD 7.0)
# ===========================================================================
@login_required
@role_required(Role.ADMIN)
def audit_log(request):
    """
    ADMIN page: EVERY recorded operation with readable old -> new diffs.

    Filters (role / user / action) let the admin review exactly what the
    Accountants and BDEs have been doing; the full history is paginated
    (50 per page) -- nothing is silently truncated by the old 200-entry
    cap.  ``?user=<username>`` deep-links (e.g. from Team Management)
    pre-filter to one person's every action.
    """
    entries = (
        AuditLog.objects
        .select_related('user', 'user__profile')
        .order_by('-timestamp')
    )

    role_filter = (request.GET.get('role') or '').strip().upper()
    user_filter = (request.GET.get('user') or '').strip()
    action_filter = (request.GET.get('action') or '').strip().upper()

    if role_filter in Role.values:
        entries = entries.filter(user__profile__role=role_filter)
    if user_filter:
        entries = entries.filter(user__username=user_filter)
    if action_filter in AuditAction.values:
        entries = entries.filter(action=action_filter)

    # Base querystring (without page) so the pagination links keep filters.
    filter_qs = ''
    if role_filter in Role.values:
        filter_qs += f'&role={role_filter}'
    if user_filter:
        filter_qs += f'&user={url_quote(user_filter)}'
    if action_filter in AuditAction.values:
        filter_qs += f'&action={action_filter}'

    paginator = Paginator(entries, 50)          # full history, 50 per page
    page_obj = paginator.get_page(request.GET.get('page'))

    # Dropdown data: every active user with his role label.
    audit_users = (
        User.objects
        .filter(is_active=True)
        .select_related('profile')
        .order_by('username')
    )

    return render(request, 'tracker/audit_log.html', {
        'page_obj': page_obj,
        'entries': page_obj.object_list,
        'total': paginator.count,
        'role_filter': role_filter if role_filter in Role.values else '',
        'user_filter': user_filter,
        'action_filter': action_filter if action_filter in AuditAction.values else '',
        'filter_qs': filter_qs,
        'audit_users': audit_users,
        'role_choices': Role.choices,
        'action_choices': AuditAction.choices,
    })


# ===========================================================================
# ADMIN: payment overrides (edit ANY payment / revert verifications)
# ===========================================================================
#: The snapshot fields of the admin payment-edit override (focused diff).
_ADMIN_PAYMENT_FIELDS = [
    'payment_type', 'amount_paid', 'transaction_ref',
    'payment_mode', 'payment_date', 'remarks', 'author',
]


@login_required
@role_required(Role.ADMIN)
@require_POST
def admin_payment_edit(request, pk):
    """
    ADMIN OVERRIDE: correct ANY payment installment -- including VERIFIED
    rows (which stay locked for the BDE) and payments owned by any BDE.

    The admin is the escalation path when an Accountant verified a wrong
    figure or a BDE logged a wrong UTR/amount and is unavailable.  Every
    override lands in the audit trail with the old -> new values, so the
    change is fully reviewable on the Audit Trail page.
    """
    installment = (
        PaymentInstallment.objects
        .select_related('project', 'project__bde')
        .prefetch_related('project__authors')
        .filter(pk=pk)
        .first()
    )
    if installment is None:
        return _styled_404(request, f'Payment record #{pk} no longer exists.')

    old_snapshot = _audit_snapshot(installment, _ADMIN_PAYMENT_FIELDS)

    form = InstallmentEditForm(
        request.POST, request.FILES, instance=installment,
        project=installment.project,
    )
    if not form.is_valid():
        messages.error(
            request,
            'Payment override failed: '
            + ' '.join(' '.join(v) for v in form.errors.values()).strip(),
        )
        return redirect('tracker:admin_dashboard')

    with transaction.atomic():
        installment = form.save()
        if form.cleaned_data.get('new_proof'):
            # Mirror the (admin-replaced) proof photo INTO the SQLite DB.
            installment.capture_proof_into_db()
        installment.project.save(update_fields=['updated_at'])

    log_action(
        request, 'UPDATE', installment,
        old=old_snapshot, new=_audit_snapshot(installment, _ADMIN_PAYMENT_FIELDS),
        label=f'ADMIN OVERRIDE — Payment #{installment.installment_number} of '
              f'"{installment.project.title}" (logged by '
              f'{installment.project.bde.get_full_name() or installment.project.bde.username})',
    )
    messages.success(
        request,
        f'Admin override saved — payment #{installment.installment_number} of '
        f'"{installment.project.title}" updated and recorded in the audit trail.',
    )
    return redirect('tracker:admin_dashboard')


@login_required
@role_required(Role.ADMIN)
@require_POST
def admin_payment_revert(request, pk):
    """
    ADMIN OVERRIDE: undo an Accountant's verification (VERIFIED -> Pending)
    exactly like the Accounts "revert" action -- the approval flow that
    unlocks the owning BDE's edit.  Audit-logged as an admin override.
    """
    installment = (
        PaymentInstallment.objects
        .select_related('project', 'project__bde', 'author', 'verified_by')
        .filter(pk=pk)
        .first()
    )
    if installment is None:
        return _styled_404(request, f'Payment record #{pk} no longer exists.')
    if installment.verification_status != VerificationStatus.VERIFIED:
        messages.error(request, 'Only VERIFIED payments can be reverted.')
        return redirect('tracker:admin_dashboard')

    verifier = installment.verified_by
    old_snapshot = _audit_snapshot(
        installment, ['verification_status', 'verified_by', 'verification_date'],
    )

    with transaction.atomic():
        installment.verification_status = VerificationStatus.PENDING
        installment.verified_by = None
        installment.verification_date = None
        installment.save()
        installment.project.save(update_fields=['updated_at'])

    log_action(
        request, 'UPDATE', installment,
        old=old_snapshot,
        new=_audit_snapshot(
            installment, ['verification_status', 'verified_by', 'verification_date'],
        ),
        label=f'ADMIN OVERRIDE — reverted verification of payment '
              f'#{installment.installment_number} of "{installment.project.title}"'
              + (f' (was verified by {verifier.get_full_name() or verifier.username})'
                 if verifier else ''),
    )
    messages.success(
        request,
        f'Verification reverted — payment #{installment.installment_number} of '
        f'"{installment.project.title}" is Pending again and the owning BDE can edit it.',
    )
    return redirect('tracker:admin_dashboard')


# ===========================================================================
# ADMIN: team management (add / remove BDE & Accounts members)
# ===========================================================================
def _team_lists():
    """User lists + activity counts for the Team Management page."""
    bdes = (
        User.objects
        .filter(profile__role=Role.BDE)
        .select_related('profile')
        .annotate(
            project_count=Count('projects_sold', distinct=True),
            submitted_count=Count('installments_submitted', distinct=True),
        )
        .order_by('-is_active', 'first_name', 'username')
    )
    accounts_users = (
        User.objects
        .filter(profile__role=Role.ACCOUNTS)
        .select_related('profile')
        .annotate(verified_count=Count('installments_verified', distinct=True))
        .order_by('-is_active', 'first_name', 'username')
    )
    admins = (
        User.objects
        .filter(Q(is_superuser=True) | Q(profile__role=Role.ADMIN))
        .order_by('username')
    )
    return bdes, accounts_users, admins


@login_required
@role_required(Role.ADMIN)
def team_management(request):
    """ADMIN page: onboard BDE / Accounts executives and manage their access."""
    bdes, accounts_users, admins = _team_lists()
    return render(request, 'tracker/team_management.html', {
        'bdes': bdes,
        'accounts_users': accounts_users,
        'admins': admins,
        'form': TeamMemberForm(),
    })


@login_required
@role_required(Role.ADMIN)
@require_POST
def team_member_add(request):
    """Create a BDE or Accounts user (role whitelisted by TeamMemberForm)."""
    form = TeamMemberForm(request.POST)

    if form.is_valid():
        data = form.cleaned_data
        with transaction.atomic():
            user = User.objects.create_user(
                username=data['username'],
                password=data['password1'],
                first_name=data['first_name'],
                last_name=data['last_name'] or '',
                email=data['email'] or '',
            )
            # The post_save signal already created a profile (role=BDE by
            # default) -- set the role the admin actually picked.
            profile = user.profile
            profile.role = data['role']
            profile.phone = data['phone'] or ''
            profile.employee_id = data['employee_id'] or ''
            profile.save()

        role_label = Role(data['role']).label
        full_name = f"{data['first_name']} {data['last_name']}".strip()
        log_action(request, 'CREATE', user.profile,
                   new={'username': user.username, 'role': data['role'],
                        'name': full_name},
                   label=f'Team member {full_name} (@{user.username})')
        messages.success(
            request,
            f'{role_label} member {full_name} (@{user.username}) was added — they can sign in now.',
        )
        return redirect('tracker:team_management')

    # Invalid: re-render with errors (no data loss).
    bdes, accounts_users, admins = _team_lists()
    messages.error(request, 'The team member could not be added. Please fix the errors below.')
    return render(request, 'tracker/team_management.html', {
        'bdes': bdes,
        'accounts_users': accounts_users,
        'admins': admins,
        'form': form,
    }, status=200)


def _get_managed_member(pk):
    """
    Fetch a user this page is allowed to manage (BDE / ACCOUNTS roles only).

    Returns (user, error_response); error_response is None when allowed.
    Admins and superusers can never be modified through Team Management --
    they are provisioned out-of-band, which also protects the last admin.
    """
    member = (
        User.objects.select_related('profile')
        .filter(pk=pk, profile__role__in=[Role.BDE, Role.ACCOUNTS])
        .first()
    )
    if member is None:
        return None, redirect('tracker:team_management')
    return member, None


@login_required
@role_required(Role.ADMIN)
@require_POST
def team_member_remove(request, pk):
    """
    Permanently delete a BDE / Accounts member -- admin-only, on demand.

    Safety rails:
      * Admins/superusers are not manageable here (see _get_managed_member).
      * A member may not delete their own account.
      * If the member owns projects, those projects (and their authors /
        payment proofs, via CASCADE) are deleted WITH the member inside one
        transaction -- the confirm dialog states this in plain words.
        Deactivating instead is the history-preserving alternative.
      * Any unexpected ProtectedError still aborts cleanly.
    """
    member, err = _get_managed_member(pk)
    if err:
        return err
    if member.id == request.user.id:
        messages.error(request, 'You cannot remove your own account.')
        return redirect('tracker:team_management')

    name = member.get_full_name() or member.username
    role_label = Role(member.profile.role).label
    projects = list(member.projects_sold.all())
    payment_count = PaymentInstallment.objects.filter(
        project__bde=member).count()
    log_action(request, 'DELETE', member.profile,
               old={'username': member.username, 'role': member.profile.role,
                    'projects_deleted': len(projects),
                    'payment_records_deleted': payment_count},
               label=f'Team member {name} (@{member.username}) removed')
    try:
        with transaction.atomic():
            # The member's projects go first -- each cascades its authors
            # and installments (proofs included); Project.bde is PROTECT,
            # so leaving any behind would block the member delete below.
            for project in projects:
                project.delete()
            member.delete()
    except ProtectedError:
        messages.error(
            request,
            f'{name} is referenced by records that could not be removed '
            f'safely. Deactivate them instead — their sign-in is blocked '
            f'but every record stays intact.',
        )
        return redirect('tracker:team_management')

    if projects:
        messages.success(
            request,
            f'{role_label} member {name} (@{member.username}) was removed — '
            f'{len(projects)} project{len(projects) == 1 and "" or "s"} '
            f'and {payment_count} payment record'
            f'{"s" if payment_count != 1 else ""} were deleted with them.',
        )
    else:
        messages.success(
            request, f'{role_label} member {name} (@{member.username}) was removed.')
    return redirect('tracker:team_management')


@login_required
@role_required(Role.ADMIN)
@require_POST
def team_member_toggle_active(request, pk):
    """
    Deactivate / reactivate a BDE or Accounts member.

    Deactivation is the recommended way to part with an executive who has
    history: Django's authentication rejects inactive users, yet all their
    projects / verifications remain attributable.
    """
    member, err = _get_managed_member(pk)
    if err:
        return err
    if member.id == request.user.id:
        messages.error(request, 'You cannot deactivate your own account.')
        return redirect('tracker:team_management')

    member.is_active = not member.is_active
    member.save(update_fields=['is_active'])
    name = member.get_full_name() or member.username
    log_action(request, 'UPDATE', member.profile,
               old={'is_active': not member.is_active},
               new={'is_active': member.is_active},
               label=f'Team member {name} (@{member.username}) '
                     f'{"reactivated" if member.is_active else "deactivated"}')
    if member.is_active:
        messages.success(request, f'{name} was reactivated — they can sign in again.')
    else:
        messages.info(request, f'{name} was deactivated. Sign-in is blocked; history is preserved.')
    return redirect('tracker:team_management')


@login_required
@role_required(Role.ADMIN)
@require_POST
def team_member_reset_password(request, pk):
    """Set a new password for a BDE / Accounts member (admin-typed, validated)."""
    member, err = _get_managed_member(pk)
    if err:
        return err

    new_password = (request.POST.get('new_password') or '').strip()
    if not new_password:
        messages.error(request, 'Please provide a new password.')
        return redirect('tracker:team_management')
    try:
        validate_password(new_password, user=member)
    except ValidationError as exc:
        messages.error(request, ' '.join(exc.messages))
        return redirect('tracker:team_management')

    member.set_password(new_password)
    member.save(update_fields=['password'])
    name = member.get_full_name() or member.username
    log_action(request, 'UPDATE', member.profile,
               new={'password': '***reset***'},
               label=f'Password reset for {name} (@{member.username})')
    messages.success(request, f'Password updated for {name} (@{member.username}).')
    return redirect('tracker:team_management')


# ===========================================================================
# Shared views
# ===========================================================================
def _styled_404(request, message=None):
    """
    Friendly styled 404 page -- used IN-VIEW whenever a record a user
    clicked on (project / installment link) no longer exists, so the raw
    Django technical/debug 404 page never leaks to end users even with
    DEBUG=True.  `message` explains what happened in plain words.
    """
    return render(request, 'tracker/404.html', {
        'notfound_message': message,
    }, status=404)


def styled_404(request, exception=None):
    """
    handler404 (wired in config/urls.py) -- renders the same styled page
    for ANY unmatched URL once DEBUG=False.  With DEBUG=True the dev
    server keeps its technical 404 for hand-typed junk URLs, while all
    app-generated dead links are handled by _styled_404 in-view.
    """
    return _styled_404(request)


def styled_404_catchall(request, *args, **kwargs):
    """
    Catch-all URL route (LAST pattern in tracker/urls.py).  Any path that
    matched no other route -- e.g. a hand-typed junk URL like
    /admin-panel/hjkl/ -- renders the same friendly branded 404 card as
    _styled_404, so Django's technical debug page (which lists every URL
    pattern when DEBUG=True) NEVER leaks to an end user, in any mode.

    Asset probes (favicon.ico, robots.txt, a missing .css/.png) answer
    with a bare text 404 instead of the HTML card -- browsers and
    devtools stay quiet and we skip rendering the full shell.
    """
    path = request.path or '/'
    last_segment = path.rstrip('/').rsplit('/', 1)[-1]
    if '.' in last_segment:
        return HttpResponse(f'Not found: {path}',
                            content_type='text/plain; charset=utf-8',
                            status=404)
    return _styled_404(
        request,
        f'There is no page at \u201c{path}\u201d \u2014 it may have been '
        f'typed incorrectly, or the link is out of date.',
    )


def serve_media(request, path):
    """
    DEBUG-only serving of the BDE-uploaded payment proofs (media/**).

    Wraps django.views.static.serve so a missing / expired / deleted
    proof file answers with a plain text 404 instead of letting its
    internal Http404 bubble up into Django's technical debug page
    (DEBUG=True) -- the same no-debug-leak guarantee the catch-all
    route gives page URLs.  PRODUCTION: serve /media/ from nginx/Caddy
    with auth at that layer and drop this route entirely.
    """
    try:
        from django.views.static import serve as _static_serve
        return _static_serve(request, path, document_root=settings.MEDIA_ROOT)
    except Http404:
        return HttpResponse(
            f'Not found: /media/{path}',
            content_type='text/plain; charset=utf-8', status=404)


# ---------------------------------------------------------------------------
# Proof photos served FROM the SQLite database (proof_data BLOB) -- the
# .sqlite3 file is fully self-contained: every transaction photo and
# acceptance proof lives inside the DB, media/ is only a fallback.
# ---------------------------------------------------------------------------
@login_required
def installment_proof_file(request, pk):
    """
    The payment's proof photo, answered from proof_data (SQLite BLOB).
    Fallback chain: DB bytes -> disk file (legacy row not yet mirrored)
    -> styled 404.  Replaces the old unauthenticated /media/ URLs, so
    proof photos now require a signed-in session (the UTR/account
    details visible in them are sensitive).
    """
    installment = PaymentInstallment.objects.filter(pk=pk).first()
    if installment is None:
        return _styled_404(request, f'Payment record #{pk} no longer exists.')
    if not installment.proof_image:
        return _styled_404(request, 'This payment has no proof photo on file.')

    data = installment.proof_data
    if not data:
        # Legacy row not mirrored yet (e.g. migration skipped a missing
        # file): try the disk copy and mirror it opportunistically.
        try:
            installment.proof_image.open('rb')
            data = installment.proof_image.read()
        except (FileNotFoundError, ValueError, OSError):
            data = None
        if data:
            installment.proof_data = data
            installment.proof_content_type = installment.proof_mime_type()
            installment.save(update_fields=['proof_data',
                                            'proof_content_type'])

    if not data:
        return _styled_404(
            request,
            'The stored proof photo for this payment is missing — '
            'please ask the BDE to re-upload it.',
        )

    response = HttpResponse(data, content_type=(
        installment.proof_content_type or 'application/octet-stream'))
    response['Content-Disposition'] = (
        f'inline; filename="{installment.proof_file_name}"')
    return response


@login_required
def project_acceptance_file(request, pk):
    """
    The project's acceptance proof, answered from acceptance_data
    (SQLite BLOB); same DB-first / disk-fallback chain as above.
    """
    project = Project.objects.filter(pk=pk).first()
    if project is None:
        return _styled_404(request, f'Project #{pk} no longer exists.')
    if not project.acceptance_file:
        return _styled_404(
            request, 'This project has no acceptance proof on file yet.')

    data = project.acceptance_data
    if not data:
        try:
            project.acceptance_file.open('rb')
            data = project.acceptance_file.read()
        except (FileNotFoundError, ValueError, OSError):
            data = None
        if data:
            project.acceptance_data = data
            project.acceptance_content_type = project.ACCEPTANCE_CONTENT_TYPES.get(
                Path(project.acceptance_file.name).suffix.lower(),
                'application/octet-stream')
            project.save(update_fields=['acceptance_data',
                                        'acceptance_content_type'])

    if not data:
        return _styled_404(
            request,
            'The stored acceptance proof for this project is missing — '
            'please re-upload it from the publication-status modal.',
        )

    response = HttpResponse(data, content_type=(
        project.acceptance_content_type or 'application/octet-stream'))
    response['Content-Disposition'] = (
        f'inline; filename="{project.acceptance_file.name.rsplit("/", 1)[-1]}"')
    return response


def _project_detail_context(request, project, add_payment_form=None, edit_forms=None,
                            project_edit_form=None):
    """
    Shared context for project_detail and the payment-management POSTs
    (project_payment_add / installment_edit / project_edit) so their
    error re-renders stay pixel-identical to the real page.

    The owning BDE (and, since admins hold every BDE action, any
    admin) additionally gets the "fill the remaining later" tooling
    (an add-payment form while something is left to schedule and
    one inline edit form per UNCLEARED installment -- Pending or
    Rejected; editing a Rejected row re-queues it as Pending) plus the
    "Edit project" card (title / service / sale value / discount /
    remarks -- see project_edit).
    """
    role = get_role(request.user)
    installments = list(project.installments.order_by('installment_number', 'id'))
    # The owning BDE edits their deal; an ADMIN holds every BDE action and
    # may therefore edit authors / payments / commercial details on ANY
    # project (peer BDEs and Accounts stay read-only).
    is_admin = role == Role.ADMIN or request.user.is_superuser
    can_edit_authors = (
        (role == Role.BDE and project.bde_id == request.user.id) or is_admin
    )

    context = {
        'project': project,
        'authors': project.authors.all(),
        'installments': installments,
        # Per-row pairs {inst, form} for the payments table (form is None
        # for VERIFIED rows and for read-only viewers).
        'installment_rows': [],
        'total_scheduled': project.total_scheduled,
        'remaining': project.remaining_to_schedule,
        # The owning BDE -- or an admin (every BDE action) -- edits author
        # details / manages payments / edits the commercial project fields;
        # everyone else stays read-only.
        'can_edit_authors': can_edit_authors,
        'can_manage_payments': can_edit_authors,
        'can_edit_project': can_edit_authors,
        # ADMINs are the only role that may DELETE a project (the red
        # button in the page header) -- on top of every edit action.
        'is_admin_viewer': is_admin,
    }

    # Per-row edit forms for the UNCLEARED installments (Pending/Rejected).
    # Fresh forms for every row; a bound (erroring) form passed by
    # installment_edit's re-render overrides just its own row so the
    # others keep theirs.
    forms_map = {
        inst.pk: InstallmentEditForm(instance=inst, prefix=f'inst{inst.pk}',
                                     project=project)
        for inst in installments
        if inst.verification_status != VerificationStatus.VERIFIED
    } if can_edit_authors else {}
    forms_map.update(edit_forms or {})
    context['installment_rows'] = [
        {'inst': inst, 'form': forms_map.get(inst.pk)}
        for inst in installments
    ]

    if not can_edit_authors:
        return context

    context['author_formset'] = AuthorEditFormSet(
        prefix='authors', queryset=project.authors.all(),
    )

    # "Edit project" card (owning BDE): fresh unbound form, or the bound
    # erroring one passed by project_edit's re-render (card stays open).
    context['project_edit_form'] = (
        project_edit_form or ProjectEditForm(instance=project)
    )

    # -- "add payment" form: only useful while something is left to
    #    schedule (over-scheduled legacy rows also hide it) ---------------
    if project.remaining_to_schedule > 0:
        used = {inst.payment_type for inst in installments}
        suggested = next(
            (t for t in (PaymentType.REMAINING,
                         PaymentType.ADVANCE_2,
                         PaymentType.ADVANCE_1)
             if t not in used),
            PaymentType.REMAINING,
        )
        context['add_payment_form'] = add_payment_form or PaymentInstallmentForm(
            project=project,
            initial={'payment_type': suggested, 'payment_date': date_class.today()},
        )
    return context


@login_required
def project_detail(request, pk):
    """
    Project page -- read-only EXCEPT for the owning BDE -- or any ADMIN
    (every BDE action) -- who gets:
      * the "Edit project" card (title / service type / sale value /
        discount / remarks via project_edit -- everything they filled
        at creation; authors and payments keep their own forms below)
      * the inline author-edit formset (profile details via
        project_authors_update; booked slots and the author count stay
        fixed)
      * the "fill the remaining amount later" payment tools (add a new
        installment, edit or remove UNCLEARED ones — Verified rows are
        locked by Accounts, FTSD 7.0 data immutability).

    Access: ADMIN/ACCOUNTS see everything; a BDE sees ONLY their own
    projects (attempts on someone else's project => 403).  ADMIN
    additionally carries the project-delete button (project_delete is
    the single admin-exclusive mutation).
    """
    project = (
        Project.objects
        .select_related('service_type', 'bde')
        .prefetch_related('authors', 'installments')
        .filter(pk=pk)
        .first()
    )
    if project is None:
        # Stale link (e.g. the project was deleted from another tab) --
        # show the friendly styled 404, never the raw technical page.
        return _styled_404(
            request,
            f'Project #{pk} no longer exists — it may have been deleted '
            'already. Your dashboard always lists the current projects.',
        )

    role = get_role(request.user)
    if role == Role.BDE and project.bde_id != request.user.id and not request.user.is_superuser:
        return render(request, 'tracker/403.html', {
            'title': 'Not your project',
            'message': 'BDE users can only view projects they created.',
            'detected_ip': None,
            'explanation': 'Sales executives are scoped to their own deals.',
        }, status=403)

    return render(request, 'tracker/project_detail.html',
                  _project_detail_context(request, project))


def _bde_payment_guard(request, project):
    """
    403 response when the requester may not manage this project's payments.

    Allowed: the project's OWNING BDE and -- since the admin holds every
    BDE action -- any ADMIN, on ANY project.  Peer BDEs and the Accounts
    role are still bounced (sales executives are scoped to their deals).
    """
    if project.bde_id == request.user.id or get_role(request.user) == Role.ADMIN:
        return None
    return render(request, 'tracker/403.html', {
        'title': 'Not your project',
        'message': 'Payments can only be managed on projects you created.',
        'detected_ip': None,
        'explanation': 'Sales executives are scoped to their own deals; '
                       'administrators may manage any project.',
    }, status=403)


def _next_installment_number(project):
    """Auto-incrementing log number within the project (FTSD 3.3: 1, 2, 3...)."""
    current = (
        PaymentInstallment.objects.filter(project=project)
        .aggregate(m=Max('installment_number'))['m']
    )
    return (current or 0) + 1


@login_required
@role_required(Role.BDE, Role.ADMIN)
@require_POST
def project_payment_add(request, pk):
    """
    Add one more payment installment from the project page (the "fill
    the remaining amount later" workflow opened by the "Schedule the
    remaining later" option at creation time).

    Guards (beyond form validation):
      * owning BDE only (_bde_payment_guard);
      * something must still be left to schedule;
      * no over-scheduling — the new total may reach but never exceed
        the payable amount;
      * no duplicate installment phases on one project.
    """
    project = (
        Project.objects
        .select_related('service_type', 'bde')
        .prefetch_related('authors', 'installments')
        .filter(pk=pk)
        .first()
    )
    if project is None:
        return _styled_404(
            request,
            f'Project #{pk} no longer exists — it may have been deleted '
            'already, so no payment can be added to it.',
        )
    guard = _bde_payment_guard(request, project)
    if guard:
        return guard

    remaining = project.remaining_to_schedule
    if remaining <= 0:
        messages.error(
            request,
            'Every rupee of this project is already scheduled — there is nothing left to add.',
        )
        return redirect('tracker:project_detail', project.pk)

    form = PaymentInstallmentForm(request.POST, request.FILES, project=project)
    if form.is_valid():
        amount = form.cleaned_data['amount_paid']
        itype = form.cleaned_data['payment_type']
        used = {inst.payment_type for inst in project.installments.all()}
        problems = []
        if itype in used:
            problems.append(
                f'"{dict(PaymentType.choices).get(itype, itype)}" is already used '
                f'on this project — pick another installment phase.'
            )
        if amount > remaining:
            problems.append(
                f'Only ₹{remaining} is left to schedule — this payment is ₹{amount}. '
                f'Lower the amount or wait for more of the balance to free up.'
            )
        if not problems:
            with transaction.atomic():
                installment = form.save(commit=False)
                installment.project = project
                installment.submitted_by = request.user
                installment.installment_number = _next_installment_number(project)
                installment.verification_status = VerificationStatus.PENDING
                installment.save()
                # Mirror the uploaded proof photo INTO the SQLite database.
                installment.capture_proof_into_db()
                project.save(update_fields=['updated_at'])
                log_action(request, 'CREATE', installment,
                           new=_audit_snapshot(installment),
                           label=f'Payment #{installment.installment_number} on '
                                 f'"{project.title}"'
                                 + (f' by {installment.author.name}'
                                    if installment.author_id else ''))
            left = remaining - amount
            if left > 0:
                messages.success(
                    request,
                    f'Payment of ₹{amount} added — ₹{left} still to schedule.',
                )
            else:
                messages.success(
                    request,
                    f'Payment of ₹{amount} added — the project is now fully '
                    f'scheduled (₹{project.net_value}). Accounts will verify it.',
                )
            return redirect('tracker:project_detail', project.pk)
        for problem in problems:
            form.add_error(None, problem)

    messages.error(
        request, 'The payment could not be added. Please fix the errors below.',
    )
    context = _project_detail_context(request, project, add_payment_form=form)
    return render(request, 'tracker/project_detail.html', context, status=200)


@login_required
@role_required(Role.BDE, Role.ADMIN)
@require_POST
def installment_edit(request, pk):
    """
    Save the inline per-row edit of ONE UNCLEARED payment installment
    (Pending or Rejected -- editing a Rejected row re-queues it as
    Pending for a fresh Accounts review).

    SECURITY (FTSD 7.0 data immutability): owning BDE only
    (_bde_payment_guard) and VERIFIED rows are LOCKED — once Accounts
    cleared a payment, the BDE must ask Accounts to revert it first (the
    admin-approval flow; the template hides the button, this is the
    server-side re-check).  The proof photo is only replaced when a new
    file is picked; otherwise the stored photo is kept.
    """
    installment = (
        PaymentInstallment.objects
            .select_related('project', 'project__service_type', 'project__bde')
            .prefetch_related('project__authors', 'project__installments')
            .filter(pk=pk)
            .first()
    )
    if installment is None:
        return _styled_404(
            request,
            f'Payment record #{pk} no longer exists — it may have been '
            'removed already. Reload the project page for the current '
            'payment schedule.',
        )
    project = installment.project
    guard = _bde_payment_guard(request, project)
    if guard:
        return guard
    if installment.verification_status == VerificationStatus.VERIFIED:
        messages.error(
            request,
            'Accounts has already verified this payment — it is locked '
            '(data immutability). Ask Accounts to revert the verification '
            'first; that is the approval flow.',
        )
        return redirect('tracker:project_detail', project.pk)

    old_snapshot = _audit_snapshot(
        installment, fields=['payment_type', 'amount_paid', 'transaction_ref',
                             'author', 'payment_mode', 'payment_date', 'remarks'])

    form = InstallmentEditForm(
        request.POST, request.FILES, instance=installment,
        prefix=f'inst{installment.pk}', project=project,
    )
    if form.is_valid():
        amount = form.cleaned_data['amount_paid']
        itype = form.cleaned_data['payment_type']
        others = [i for i in project.installments.all() if i.pk != installment.pk]
        others_total = sum((i.amount_paid for i in others), Decimal('0'))
        used = {i.payment_type for i in others}
        problems = []
        if itype in used:
            problems.append(
                f'"{dict(PaymentType.choices).get(itype, itype)}" is already used '
                f'by another installment on this project.'
            )
        if others_total + amount > project.net_value:
            problems.append(
                f'Only ₹{project.net_value - others_total} can sit on this '
                f'installment — the rest of the payable amount is already scheduled.'
            )
        if not problems:
            with transaction.atomic():
                saved = form.save(commit=False)
                new_proof = form.cleaned_data.get('new_proof')
                if new_proof:
                    saved.proof_image = new_proof   # replaces the stored photo
                # A corrected Rejected row goes back into the Pending queue.
                if installment.verification_status == VerificationStatus.REJECTED:
                    saved.verification_status = VerificationStatus.PENDING
                    saved.verified_by = None
                    saved.verification_date = None
                saved.save()
                if new_proof:
                    # Mirror the replaced proof photo INTO the SQLite DB.
                    saved.capture_proof_into_db()
                project.save(update_fields=['updated_at'])
                log_action(request, 'UPDATE', installment, old=old_snapshot,
                           new=_audit_snapshot(
                               installment,
                               fields=['payment_type', 'amount_paid', 'transaction_ref',
                                       'author', 'payment_mode', 'payment_date', 'remarks',
                                       'verification_status']),
                           label=f'Payment #{installment.installment_number} on '
                                 f'"{project.title}"'
                                 + (f' by {installment.author.name}'
                                    if installment.author_id else ''))
            left = project.net_value - (others_total + amount)
            if left > 0:
                messages.success(
                    request,
                    f'Payment updated — ₹{left} still to schedule on this project.',
                )
            else:
                messages.success(
                    request,
                    f'Payment updated — the project is now fully scheduled (₹{project.net_value}).',
                )
            return redirect('tracker:project_detail', project.pk)
        for problem in problems:
            form.add_error(None, problem)

    messages.error(
        request, 'The payment could not be updated. Please fix the errors below.',
    )
    context = _project_detail_context(
        request, project, edit_forms={installment.pk: form},
    )
    return render(request, 'tracker/project_detail.html', context, status=200)


@login_required
@role_required(Role.BDE, Role.ADMIN)
@require_POST
def installment_delete(request, pk):
    """
    Remove one UNCLEARED installment (owning BDE).  The amount simply
    returns to "still to schedule" and can be re-added with a fresh
    proof anytime.  VERIFIED rows are locked (FTSD 7.0 immutability,
    server-side re-check).
    """
    installment = (
        PaymentInstallment.objects
            .select_related('project', 'project__service_type', 'project__bde')
            .prefetch_related('project__authors', 'project__installments')
            .filter(pk=pk)
            .first()
    )
    if installment is None:
        return _styled_404(
            request,
            f'Payment record #{pk} no longer exists — it may have been '
            'removed already. Reload the project page for the current '
            'payment schedule.',
        )
    project = installment.project
    guard = _bde_payment_guard(request, project)
    if guard:
        return guard
    if installment.verification_status == VerificationStatus.VERIFIED:
        messages.error(
            request,
            'Accounts has already verified this payment — it is locked '
            '(data immutability). Ask Accounts to revert the verification '
            'first; that is the approval flow.',
        )
        return redirect('tracker:project_detail', project.pk)

    amount = installment.amount_paid
    log_action(request, 'DELETE', installment,
               old=_audit_snapshot(installment),
               label=f'Payment #{installment.installment_number} on "{project.title}"')
    with transaction.atomic():
        installment.delete()
        project.save(update_fields=['updated_at'])
    # remaining BEFORE the delete + the removed amount = what is left now
    # (avoids relying on the prefetched installments cache).
    left = project.remaining_to_schedule + amount
    if left > 0:
        messages.success(
            request,
            f'Payment of ₹{amount} removed — ₹{left} is back to schedule. '
            f'Add a fresh one anytime below.',
        )
    else:
        messages.success(
            request,
            f'Payment of ₹{amount} removed — the project is now fully scheduled (₹{project.net_value}).',
        )
    return redirect('tracker:project_detail', project.pk)


@login_required
@role_required(Role.BDE, Role.ADMIN)
@require_POST
def project_authors_update(request, pk):
    """
    Save the inline author-edit formset posted from the project page.

    SECURITY: the BDE who OWNS the project -- or any ADMIN (every BDE
    action) -- may edit authors, and only the whitelisted profile fields:
    AuthorEditForm never exposes `position` or `project`, so the booked
    slots and the author count can never change here.  Peer BDEs and the
    Accounts role stay read-only (the check below bounces them even
    through the superuser bypass of role_required).
    """
    project = (
        Project.objects.select_related('service_type', 'bde')
                       .prefetch_related('authors', 'installments')
                       .filter(pk=pk)
                       .first()
    )
    if project is None:
        return _styled_404(
            request,
            f'Project #{pk} no longer exists — it may have been deleted '
            'already, so its authors cannot be edited.',
        )
    if project.bde_id != request.user.id and get_role(request.user) != Role.ADMIN:
        return render(request, 'tracker/403.html', {
            'title': 'Not your project',
            'message': 'Authors can only be edited on projects you created.',
            'detected_ip': None,
            'explanation': 'Sales executives are scoped to their own deals; '
                           'administrators may edit any project.',
        }, status=403)

    formset = AuthorEditFormSet(
        request.POST, prefix='authors', queryset=project.authors.all(),
    )
    if formset.is_valid():
        with transaction.atomic():
            saved = formset.save()
            for author in saved:
                log_action(request, 'UPDATE', author,
                           new=_audit_snapshot(author),
                           label=f'Author slot {author.position} of "{project.title}"')
        messages.success(
            request,
            f'{len(saved)} author record(s) updated for "{project.title}".',
        )
        return redirect('tracker:project_detail', project.pk)

    # Invalid: re-render the project page with the bound (erroring) formset.
    messages.error(
        request, 'Some author details need attention — please fix the errors below.',
    )
    context = _project_detail_context(request, project)
    context['author_formset'] = formset
    return render(request, 'tracker/project_detail.html', context, status=200)


@login_required
@role_required(Role.BDE, Role.ADMIN)
@require_POST
def project_edit(request, pk):
    """
    Save the commercial-detail edits (title / service / sale value /
    discount / remarks) posted from the collapsible "Edit project" card
    on the project page -- "the BDE can edit everything about their own
    deal", while DELETING it stays reserved for admins (project_delete).

    SECURITY: the BDE who OWNS the project -- or any ADMIN (every BDE
    action) -- may edit it (the superuser bypass of role_required is
    re-checked by the ownership guard below, exactly like
    project_authors_update).

    Extra business rule beyond ProjectEditForm: the net billable amount
    (sale − discount) may never drop below what is already scheduled on
    the payment plan, so an edit can never over-schedule the project.
    """
    project = (
        Project.objects
        .select_related('service_type', 'bde')
        .prefetch_related('authors', 'installments')
        .filter(pk=pk)
        .first()
    )
    if project is None:
        return _styled_404(
            request,
            f'Project #{pk} no longer exists — it may have been deleted '
            'already, so its details cannot be edited.',
        )
    if project.bde_id != request.user.id and get_role(request.user) != Role.ADMIN:
        return render(request, 'tracker/403.html', {
            'title': 'Not your project',
            'message': 'Project details can only be edited on projects you created.',
            'detected_ip': None,
            'explanation': 'Sales executives are scoped to their own deals; '
                           'administrators may edit any project.',
        }, status=403)

    old_snapshot = _audit_snapshot(
        project, fields=['title', 'service_type', 'sale_value',
                         'discount_value', 'remarks'])
    form = ProjectEditForm(request.POST, instance=project)
    if form.is_valid():
        scheduled = project.total_scheduled
        sale = form.cleaned_data['sale_value']
        discount = form.cleaned_data.get('discount_value') or Decimal('0')
        if sale - discount < scheduled:
            form.add_error(
                None,
                f'₹{scheduled:,.2f} is already scheduled on this project — the net '
                f'billable amount (sale − discount) cannot drop below that. '
                f'Lower or remove scheduled payments first, or keep the net '
                f'billable at ₹{scheduled:,.2f} or above.',
            )
        else:
            with transaction.atomic():
                form.save()
                project.refresh_from_db()
                log_action(request, 'UPDATE', project, old=old_snapshot,
                           new=_audit_snapshot(
                               project, fields=['title', 'service_type', 'sale_value',
                                                'discount_value', 'remarks']),
                           label=f'Project "{project.title}" commercial details')
            messages.success(
                request,
                'Project details updated — authors, payments and the '
                'verification history stay untouched.',
            )
            return redirect('tracker:project_detail', project.pk)

    messages.error(
        request, 'The project could not be updated. Please fix the errors below.',
    )
    # ModelForm validation MUTATES the bound instance in memory
    # (construct_instance copies the submitted values onto it during
    # is_valid()), even though nothing was saved.  Reload the project
    # from the DB so the re-rendered page keeps showing the REAL saved
    # values, while the bound form below still holds the user's rejected
    # input for correction.  (Prefetch caches for authors / installments
    # survive refresh_from_db, so no extra queries are needed.)
    project.refresh_from_db()
    # Re-render the full project page; the edit card stays OPEN because
    # the bound (erroring) form is passed through (template checks
    # project_edit_form.errors), mirroring the inline payment edits.
    context = _project_detail_context(request, project, project_edit_form=form)
    return render(request, 'tracker/project_detail.html', context, status=200)


@login_required
@role_required(Role.ADMIN)
@require_POST
def project_delete(request, pk):
    """
    Permanently remove a project -- ADMIN ONLY.  BDEs can edit every
    detail of their own deals (project_edit / authors / payments) but can
    never delete them; this is the single admin-exclusive mutation on a
    project.

    Deleting cascades the project's authors, payment installments and
    their uploaded proof files (FK CASCADE in the schema), so nothing
    orphaned stays behind.
    """
    project = (
        Project.objects
        .select_related('service_type', 'bde')
        .prefetch_related('authors', 'installments')
        .filter(pk=pk)
        .first()
    )
    if project is None:
        return _styled_404(
            request,
            f'Project #{pk} no longer exists — it may already have been deleted.',
        )

    title = project.title
    log_action(request, 'DELETE', project,
               old=_audit_snapshot(project),
               label=f'Project "{title}" deleted (with authors + payments)')
    with transaction.atomic():
        project.delete()
    messages.success(
        request,
        f'Project "{title}" was permanently deleted, together with its '
        'authors, payment history and uploaded proofs.',
    )
    return redirect('tracker:admin_dashboard')


@login_required
def api_service_types(request):
    """JSON catalogue of the active services (id, name, slots, base price)."""
    services = [
        {'id': s.id, 'name': s.name, 'default_slots': s.default_slots,
         'base_price': str(s.base_price)}
        for s in ServiceType.objects.filter(is_active=True)
    ]
    return JsonResponse({'ok': True, 'service_types': services})
