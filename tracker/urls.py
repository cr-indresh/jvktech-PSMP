"""
URL routes for the tracker app.

All page URLs are plain server-rendered Django views; the two Accounts
endpoints marked with <JSON> accept/answer JSON (the status one also
accepts multipart/form-data for the acceptance-proof upload) for the
fetch() calls in accounts_dashboard.html.
"""

from django.urls import path, re_path

from . import views

app_name = 'tracker'

urlpatterns = [
    # ---- auth -------------------------------------------------------------
    path('', views.dashboard_router, name='home'),
    # Clean-URL entry point: behind the sandbox gateway '/' belongs to the
    # Next.js launcher, so post-login routing and the header links target
    # /dashboard/ instead (in a plain local deployment both paths work).
    path('dashboard/', views.dashboard_router, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # ---- BDE (sales) ------------------------------------------------------
    path('bde/', views.bde_dashboard, name='bde_dashboard'),
    path('bde/projects/create/', views.project_create, name='project_create'),

    # ---- ACCOUNTS ---------------------------------------------------------
    path('accounts/', views.accounts_dashboard, name='accounts_dashboard'),
    # <JSON> set verification_status on a payment installment
    # (action = verify / reject / revert, FTSD 3.3)
    path('accounts/api/installments/<int:pk>/verify/',
         views.set_verification, name='set_verification'),
    # <JSON / multipart> update publication status + links + acceptance
    # proof on a project
    path('accounts/api/projects/<int:pk>/status/',
         views.update_project_status, name='update_project_status'),

    # ---- ADMIN ------------------------------------------------------------
    path('admin-panel/', views.admin_dashboard, name='admin_dashboard'),
    # One-click CSV export of the FILTERED projects table (FTSD 5.0).
    path('admin-panel/export/csv/', views.admin_export_csv, name='admin_export_csv'),
    # Service catalogue management (base price + author slot limits).
    path('services/', views.service_catalog, name='service_catalog'),
    path('services/add/', views.service_add, name='service_add'),
    path('services/<int:pk>/update/', views.service_update, name='service_update'),
    # Audit trail (FTSD 7.0) -- filterable by role/user/action, full history.
    path('audit/', views.audit_log, name='audit_log'),
    # ADMIN payment overrides: correct ANY payment (even VERIFIED ones) and
    # revert an Accountant's verification -- every override is audit-logged.
    path('admin-panel/payments/<int:pk>/edit/', views.admin_payment_edit,
         name='admin_payment_edit'),
    path('admin-panel/payments/<int:pk>/revert/', views.admin_payment_revert,
         name='admin_payment_revert'),
    # Team management (add / remove / deactivate / reset-password for the
    # BDE and Accounts roles; admin-only).
    path('team/', views.team_management, name='team_management'),
    path('team/add/', views.team_member_add, name='team_member_add'),
    path('team/<int:pk>/remove/', views.team_member_remove, name='team_member_remove'),
    path('team/<int:pk>/toggle-active/', views.team_member_toggle_active,
         name='team_member_toggle_active'),
    path('team/<int:pk>/reset-password/', views.team_member_reset_password,
         name='team_member_reset_password'),

    # ---- shared -----------------------------------------------------------
    path('projects/<int:pk>/', views.project_detail, name='project_detail'),
    # BDE: commercial-detail edits (title / service / sale value / discount
    # / remarks) from the collapsible "Edit project" card -- owning BDE
    # only; admins stay read-only.
    path('projects/<int:pk>/edit/', views.project_edit, name='project_edit'),
    # ADMIN: the ONLY role allowed to delete a project (cascades authors,
    # payments and proof uploads).
    path('projects/<int:pk>/delete/', views.project_delete, name='project_delete'),
    # BDE: inline author-profile edits from the project page -- owning BDE
    # only, booked slots stay fixed.
    path('projects/<int:pk>/authors/update/', views.project_authors_update,
         name='project_authors_update'),
    # BDE: "fill the remaining amount later" workflow -- add a missing
    # payment installment from the project page (owning BDE only).
    path('projects/<int:pk>/payments/add/', views.project_payment_add,
         name='project_payment_add'),
    # BDE: inline edit / removal of a single UNCLEARED installment
    # (Verified rows are locked; Accounts re-verifies any change).
    path('installments/<int:pk>/edit/', views.installment_edit,
         name='installment_edit'),
    path('installments/<int:pk>/delete/', views.installment_delete,
         name='installment_delete'),
    # <JSON> service catalogue (id, name, slots, base price)
    path('api/service-types/', views.api_service_types, name='api_service_types'),

    # Proof photos served FROM the SQLite database (proof_data BLOB) --
    # the transaction photo bytes live inside db.sqlite3 itself, so the
    # DB file is fully self-contained (media/ is only a fallback).
    path('installments/<int:pk>/proof/', views.installment_proof_file,
         name='installment_proof_file'),
    path('projects/<int:pk>/acceptance/', views.project_acceptance_file,
         name='project_acceptance_file'),

    # ---- catch-all (MUST stay LAST) ----------------------------------------
    # Any path that matched no route above -- e.g. a hand-typed junk URL
    # like /admin-panel/hjkl/ -- gets the friendly branded 404 card via
    # views.styled_404_catchall.  Django's handler404 only fires when
    # DEBUG=False, so without this route the technical debug 404 page
    # (which lists every URL pattern) would leak to end users in DEBUG
    # mode.  config/urls.py serves /media/ BEFORE this include for the
    # same reason.
    re_path(r'^.*$', views.styled_404_catchall, name='catchall_404'),
]
