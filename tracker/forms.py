"""
Forms for the Publication & Sales Operations Management Portal (PSMP).

 SECURITY BOUNDARIES ENCODED HERE (FTSD §2.0)
 ---------------------------------------------
 * ProjectForm          (BDE)     -> only commercial creation fields
                                     (slots are provisioned by the app).
 * AuthorForm(s)        (BDE)     -> author slot booking as a dynamic formset.
 * InstallmentForm(s)   (BDE)     -> payment proofs (transaction refs).
 * ProjectStatusForm    (ACCOUNTS)-> publication lifecycle + links +
                                     acceptance proof upload ONLY.
 * ServiceTypeForm      (ADMIN)   -> service catalogue configuration
                                     (base price, slot limits).

 `sale_value`, `discount_value` and author details are deliberately NOT
 editable through the Accounts workflow -- "Accounts cannot alter the
 initial sale value" is enforced by simply never exposing those fields to
 that role (plus the JSON endpoint validates through this same form).
"""

from datetime import date
from decimal import Decimal
from pathlib import Path

from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from .models import (
    Author, PaymentInstallment, PaymentMode, PaymentType, Project,
    PublicationStatus, Role, ServiceType,
)

# ---------------------------------------------------------------------------
# Shared Tailwind CSS widget styling (keeps templates tidy)
# ---------------------------------------------------------------------------
TW_INPUT = (
    'w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm '
    'text-slate-800 shadow-sm placeholder:text-slate-400 transition '
    'focus:border-emerald-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/30 '
    'disabled:bg-slate-100'
)
TW_TEXTAREA = TW_INPUT + ' min-h-[76px] resize-y'


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
class LoginForm(AuthenticationForm):
    """Login form with Tailwind styling (renders on login.html)."""

    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': TW_INPUT,
            'placeholder': 'e.g. bde.priya',
            'autocomplete': 'username',
            'autofocus': 'autofocus',
        }),
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': TW_INPUT,
            'placeholder': '••••••••',
            'autocomplete': 'current-password',
        }),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.error_messages['invalid_login'] = (
            'Please enter a correct username and password. Note that both fields are case-sensitive.'
        )


# ---------------------------------------------------------------------------
# BDE: project creation / edit (FTSD §4.1)
# ---------------------------------------------------------------------------
class ProjectForm(forms.ModelForm):
    """
    Initial sale details captured by the BDE.  The author SLOTS are
    provisioned by the application from the selected service's catalogue
    config (Project.total_slots) -- the BDE never types a slot count.
    """

    class Meta:
        model = Project
        fields = ['service_type', 'title', 'sale_value', 'discount_value', 'remarks']
        widgets = {
            'service_type': forms.Select(attrs={
                'class': TW_INPUT,
                'data-autosubmit-less': '1',
            }),
            'title': forms.TextInput(attrs={
                'class': TW_INPUT,
                'placeholder': 'e.g. Federated Learning for IoT Security — Scopus Paper',
            }),
            'sale_value': forms.NumberInput(attrs={
                'class': TW_INPUT,
                'min': '0', 'step': '0.01',
                'placeholder': 'e.g. 120000',
            }),
            'discount_value': forms.NumberInput(attrs={
                'class': TW_INPUT,
                'min': '0', 'step': '0.01',
                'placeholder': '0',
            }),
            'remarks': forms.Textarea(attrs={
                'class': TW_TEXTAREA,
                'placeholder': 'Client expectations, timelines, special commitments...',
            }),
        }

    def clean(self):
        cleaned = super().clean()
        sale = cleaned.get('sale_value')
        discount = cleaned.get('discount_value') or Decimal('0')
        if sale is not None and discount > sale:
            raise ValidationError('Discount applied cannot exceed the sale value.')
        return cleaned


class ProjectEditForm(forms.ModelForm):
    """
    Commercial-detail edits made by the OWNING BDE from the project page
    ("Edit project" collapsible card): title, service, sale value,
    discount and remarks -- everything the BDE filled at creation except
    the authors and payments, which keep their dedicated forms on the
    same page.  Publication status / links / proofs stay with the
    Accounts workflow and are deliberately absent here.

    Beyond this form's own validation, views.project_edit additionally
    rejects any edit that would push the net billable amount (sale −
    discount) BELOW what is already scheduled on the payment plan, so a
    sale-value edit can never break the installment schedule.
    """

    # Both optional in the edit UI: an empty discount clears back to ₹0
    # (coerced in clean_discount_value) and empty remarks simply wipe.
    discount_value = forms.DecimalField(
        required=False,
        min_value=Decimal('0'), max_digits=12, decimal_places=2,
        widget=forms.NumberInput(attrs={
            'class': TW_INPUT,
            'min': '0', 'step': '0.01',
            'placeholder': '0',
        }),
    )
    remarks = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': TW_TEXTAREA,
            'placeholder': 'Client expectations, timelines, special commitments...',
        }),
    )

    class Meta:
        model = Project
        fields = ['service_type', 'title', 'sale_value', 'discount_value', 'remarks']
        widgets = {
            'service_type': forms.Select(attrs={'class': TW_INPUT}),
            'title': forms.TextInput(attrs={
                'class': TW_INPUT,
                'placeholder': 'e.g. Federated Learning for IoT Security — Scopus Paper',
            }),
            'sale_value': forms.NumberInput(attrs={
                'class': TW_INPUT,
                'min': '0', 'step': '0.01',
                'placeholder': 'e.g. 120000',
            }),
        }

    def clean_discount_value(self):
        # Empty input == no discount (store ₹0 instead of None, which
        # would violate the model's NOT NULL column).
        return self.cleaned_data.get('discount_value') or Decimal('0')

    def clean(self):
        cleaned = super().clean()
        sale = cleaned.get('sale_value')
        discount = cleaned.get('discount_value') or Decimal('0')
        if sale is not None and discount > sale:
            raise ValidationError('Discount applied cannot exceed the sale value.')
        return cleaned


# ---------------------------------------------------------------------------
# BDE: dynamic author formset (FTSD §3.2 author profile data)
# ---------------------------------------------------------------------------
AUTHOR_FIELD_WIDGETS = {
    'name': forms.TextInput(attrs={
        'class': TW_INPUT,
        'placeholder': 'e.g. Dr. Meera Iyer',
    }),
    'email': forms.EmailInput(attrs={
        'class': TW_INPUT,
        'placeholder': 'author@university.edu',
    }),
    'phone': forms.TextInput(attrs={
        'class': TW_INPUT,
        'placeholder': '+91 98xxxxxx00',
    }),
    'designation': forms.TextInput(attrs={
        'class': TW_INPUT,
        'placeholder': 'e.g. Assistant Professor',
    }),
    'department': forms.TextInput(attrs={
        'class': TW_INPUT,
        'placeholder': 'e.g. Computer Science',
    }),
    'company_name': forms.TextInput(attrs={
        'class': TW_INPUT,
        'placeholder': 'e.g. Anna University',
    }),
    'city': forms.TextInput(attrs={
        'class': TW_INPUT,
        'placeholder': 'e.g. Chennai',
    }),
    'state': forms.TextInput(attrs={
        'class': TW_INPUT,
        'placeholder': 'e.g. Tamil Nadu',
    }),
    'country': forms.TextInput(attrs={
        'class': TW_INPUT,
        'placeholder': 'e.g. India',
    }),
    'pin_code': forms.TextInput(attrs={
        'class': TW_INPUT,
        'placeholder': 'e.g. 600025',
    }),
    'nationality': forms.TextInput(attrs={
        'class': TW_INPUT,
        'placeholder': 'e.g. Indian',
    }),
}
AUTHOR_TEXTAREA_WIDGET = forms.Textarea(attrs={
    'class': TW_INPUT + ' min-h-[40px] resize-none',
    'rows': 1,
    'placeholder': 'Complete postal address',
})
AUTHOR_DETAILS_WIDGET = forms.Textarea(attrs={
    'class': TW_INPUT + ' min-h-[40px] resize-none',
    'rows': 1,
    'placeholder': 'Extra notes / ORCID',
})


class AuthorForm(forms.ModelForm):
    """
    One author SLOT booking inside the dynamic "Authors" repeater.

    `position` is hidden and auto-numbered (server side assigns the final
    slot ordering, the JS only keeps the display in sync), so BDEs cannot
    forge slot numbers.  Name / email / phone are REQUIRED (star-marked in
    the UI); the remaining FTSD §3.2 profile fields are optional but all
    present.  The slot COUNT is provisioned by the application from the
    service catalogue -- the formset is capped to the project's
    total_slots in the view.
    """

    position = forms.IntegerField(required=False, widget=forms.HiddenInput())
    details = forms.CharField(required=False, widget=AUTHOR_DETAILS_WIDGET)
    email = forms.EmailField(required=True, widget=AUTHOR_FIELD_WIDGETS['email'])
    phone = forms.CharField(max_length=20, required=True, widget=AUTHOR_FIELD_WIDGETS['phone'])
    full_address = forms.CharField(required=False, widget=AUTHOR_TEXTAREA_WIDGET)

    class Meta:
        model = Author
        fields = [
            'name', 'email', 'phone', 'position', 'details',
            'designation', 'department', 'company_name', 'full_address',
            'city', 'district', 'state', 'country', 'pin_code', 'nationality',
        ]
        widgets = AUTHOR_FIELD_WIDGETS


AuthorFormSet = forms.formset_factory(
    AuthorForm,
    extra=1,
    can_delete=False,
    # No static max_num: the cap is the project's provisioned total_slots,
    # enforced dynamically in views.project_create.
)


class AuthorEditForm(forms.ModelForm):
    """
    Per-author edit form used on the project page: the OWNING BDE may
    update the profile details.  `position` (booked slot) and the project
    binding are deliberately absent -- they never change after creation.
    """

    details = forms.CharField(required=False, widget=AUTHOR_DETAILS_WIDGET)
    email = forms.EmailField(required=True, widget=AUTHOR_FIELD_WIDGETS['email'])
    phone = forms.CharField(max_length=20, required=True, widget=AUTHOR_FIELD_WIDGETS['phone'])
    full_address = forms.CharField(required=False, widget=AUTHOR_TEXTAREA_WIDGET)

    class Meta:
        model = Author
        fields = [
            'name', 'email', 'phone', 'details',
            'designation', 'department', 'company_name', 'full_address',
            'city', 'district', 'state', 'country', 'pin_code', 'nationality',
        ]
        widgets = AUTHOR_FIELD_WIDGETS


AuthorEditFormSet = forms.modelformset_factory(
    Author,
    form=AuthorEditForm,
    extra=0,
    can_delete=False,
)


# ---------------------------------------------------------------------------
# BDE: dynamic installment formset (FTSD §3.3 payment logging)
# ---------------------------------------------------------------------------
# Proof-upload rules shared by every proof field in the app (creation
# formset, per-project "add payment" form and the inline edit rows).
PROOF_ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.webp', '.pdf'}
PROOF_MAX_SIZE_MB = 10      # FTSD 3.4: proofs up to 10 MB


def validate_proof_file(uploaded):
    """Extension whitelist + size cap for a transaction proof upload."""
    ext = Path(uploaded.name).suffix.lower()
    if ext not in PROOF_ALLOWED_EXTENSIONS:
        raise ValidationError(
            'Proof must be a JPG, PNG or WebP image, or a PDF file.'
        )
    if uploaded.size and uploaded.size > PROOF_MAX_SIZE_MB * 1024 * 1024:
        raise ValidationError(
            f'Proof file is too large — please keep it under {PROOF_MAX_SIZE_MB} MB.'
        )
    return uploaded


def installment_widgets():
    """Shared widget set for the payment logging forms."""
    return {
        'payment_type': forms.Select(attrs={'class': TW_INPUT}),
        'amount_paid': forms.NumberInput(attrs={
            'class': TW_INPUT + ' inst-amount-input',
            'min': '0', 'step': '0.01',
            'placeholder': 'e.g. 30000',
        }),
        'transaction_ref': forms.TextInput(attrs={
            'class': TW_INPUT,
            'placeholder': 'e.g. UTR 883729105',
        }),
        'author': forms.Select(attrs={
            'class': TW_INPUT + ' paid-by-select',
            'title': 'Authors pay individually — pick who made this payment',
        }),
        'payment_mode': forms.Select(attrs={'class': TW_INPUT}),
        'payment_date': forms.DateInput(
            attrs={'class': TW_INPUT, 'type': 'date'},
            format='%Y-%m-%d',
        ),
        'remarks': forms.TextInput(attrs={
            'class': TW_INPUT,
            'placeholder': 'e.g. part payment via GPay (optional)',
        }),
    }


def _position_choice_label(n):
    """'1st Position' / '2nd Position' / ... (matches Author.position_label)."""
    if 10 <= n % 100 <= 20:
        suffix = 'th'
    else:
        suffix = {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')
    return f'{n}{suffix} Position'


# The create-formset "paid by" picker offers slot POSITIONS (the authors
# are booked on the very same submit, saved just before the installments).
MAX_PAID_BY_POSITIONS = 20   # mirrors ServiceType.default_slots upper bound


def paid_by_position_choices():
    return [('', '— select the paying author —')] + [
        (str(n), _position_choice_label(n)) for n in range(1, MAX_PAID_BY_POSITIONS + 1)
    ]


def _paid_by_field(queryset):
    """Author picker for payments on an EXISTING project (real FK choices)."""
    field = forms.ModelChoiceField(
        queryset=queryset,
        required=True,
        label='Paid by author',
        help_text='Authors pay individually — pick who made this payment.',
        empty_label='— select the paying author —',
        error_messages={'required': 'Pick the author who paid this installment.'},
    )
    field.label_from_instance = (
        lambda author: f'{author.name} · {author.position_label}'
    )
    return field


class PaymentInstallmentForm(forms.ModelForm):
    """
    One payment log row inside the dynamic "Installments" repeater.

    Captures the full FTSD §3.3 metadata: phase, amount paid, transaction
    reference (UTR), payment MODE (UPI / Bank Transfer), payment DATE and
    remarks -- PLUS THE PAYING AUTHOR (authors pay individually, so every
    installment records who actually paid it).  Besides the transaction
    ref, the BDE MUST attach a PHOTO / SCREENSHOT of the transaction which
    the Accounts team opens while verifying.  The file input itself is
    hidden in the UI -- the template renders a styled "Upload photo"
    button that triggers it -- but validation still runs here: extension
    whitelist + 10 MB cap, defense-in-depth below the browser accept=.

    PAYER SELECTION has two flavours (``project`` kwarg):
      * project=PROJECT ("add payment" on the project page) -> a real
        ``author`` FK select scoped to that project's booked authors;
      * project=None (creation formset) -> an ``author_position`` select
        (1st Position, 2nd Position, ...) because the authors are booked
        on the SAME submit -- views.project_create resolves the picked
        position to the freshly saved Author row.
    """

    proof_image = forms.FileField(
        required=True,
        widget=forms.ClearableFileInput(attrs={
            # Hidden: the visible "Upload photo" button opens the picker.
            'class': 'hidden proof-file-input',
            'accept': 'image/jpeg,image/png,image/webp,.pdf',
        }),
    )

    class Meta:
        model = PaymentInstallment
        fields = [
            'payment_type', 'amount_paid', 'transaction_ref',
            'payment_mode', 'payment_date', 'remarks', 'proof_image',
            # 'author' is listed so ModelForm.save() carries the payer onto
            # the instance; the field itself is swapped in __init__ (real
            # author FK with a project, position picker without).
            'author',
        ]
        widgets = installment_widgets()

    def __init__(self, *args, project=None, **kwargs):
        super().__init__(*args, **kwargs)
        # Payment date defaults to today (FTSD 3.3 "Date selector").
        if not self.initial.get('payment_date'):
            self.initial['payment_date'] = date.today()
        # -- payer picker (authors pay individually) --------------------
        if project is not None:
            self.fields['author'] = _paid_by_field(project.authors.all())
        else:
            # Creation formset: authors are being booked on this very
            # submit, so the payer is picked by SLOT POSITION (the plain
            # FK select is replaced -- construct_instance only copies
            # fields that are still present in self.fields).
            del self.fields['author']
            self.fields['author_position'] = forms.ChoiceField(
                required=True,
                choices=paid_by_position_choices(),
                label='Paid by author',
                help_text='Authors pay individually — pick the slot of the author who paid.',
                error_messages={'required': 'Pick the author who paid this installment.'},
                widget=forms.Select(attrs={
                    'class': TW_INPUT + ' paid-by-select',
                    'title': 'Authors pay individually — pick who made this payment',
                }),
            )

    def clean_author_position(self):
        # ChoiceField cleaning keeps raw strings; normalise '' -> None
        # ('' never survives the required check above).
        return self.cleaned_data.get('author_position') or None

    def clean_proof_image(self):
        uploaded = self.cleaned_data.get('proof_image')
        if not uploaded:
            return uploaded
        return validate_proof_file(uploaded)


InstallmentFormSet = forms.formset_factory(
    PaymentInstallmentForm,
    extra=1,
    can_delete=False,
    max_num=6,
)


class InstallmentEditForm(forms.ModelForm):
    """
    Edit ONE uncleared (Pending / Rejected) payment installment from the
    project page (the "fill the remaining amount later" workflow --
    owning BDE only, which views.installment_edit re-checks together
    with the verified lock).

    The proof photo is OPTIONAL here: leaving the picker empty KEEPS the
    existing photo, picking a file replaces it (same whitelist + cap via
    validate_proof_file).  A dedicated plain `new_proof` FileField keeps
    the ModelForm from ever clearing the stored file when nothing is
    re-uploaded.
    """

    new_proof = forms.FileField(
        required=False,
        widget=forms.ClearableFileInput(attrs={
            'class': 'hidden proof-file-input',
            'accept': 'image/jpeg,image/png,image/webp,.pdf',
        }),
    )

    class Meta:
        model = PaymentInstallment
        fields = [
            'payment_type', 'amount_paid', 'transaction_ref',
            'payment_mode', 'payment_date', 'remarks',
            # 'author' in Meta.fields so ModelForm.save() copies the payer
            # onto the instance (the field is injected in __init__).
            'author',
        ]
        widgets = installment_widgets()

    def __init__(self, *args, project=None, **kwargs):
        super().__init__(*args, **kwargs)
        # Payer picker scoped to this project's booked authors (authors
        # pay individually) -- required so an edit can also (re)link the
        # payer of a legacy row.
        if project is not None:
            self.fields['author'] = _paid_by_field(project.authors.all())

    def clean_new_proof(self):
        uploaded = self.cleaned_data.get('new_proof')
        if uploaded:
            validate_proof_file(uploaded)
        return uploaded


# ---------------------------------------------------------------------------
# ACCOUNTS: publication lifecycle + links + acceptance proof (FTSD §3.4)
# ---------------------------------------------------------------------------
ACCEPTANCE_ALLOWED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.pdf'}
ACCEPTANCE_MAX_SIZE_MB = 10


class ProjectStatusForm(forms.ModelForm):
    """
    Fields the ACCOUNTS role may update on a project.

    !!! SECURITY !!!
    `sale_value`, `discount_value`, `remarks`, authors and the owning BDE
    are intentionally ABSENT.  Accounts users therefore *cannot* alter the
    initial sale value through any UI or API bound to this form -- the
    update_project_status JSON endpoint validates its payload against this
    exact form, so unknown/extra fields are simply ignored by Django forms.
    """

    acceptance_file = forms.FileField(
        required=False,
        widget=forms.ClearableFileInput(attrs={
            'class': 'hidden',
            'accept': 'image/jpeg,image/png,.pdf',
            'id': 'modal-acceptance-file',
        }),
        help_text='Acceptance proof (PNG, JPG or PDF, max 10 MB).',
    )

    class Meta:
        model = Project
        fields = ['publication_status', 'acceptance_link', 'publication_url']
        widgets = {
            'publication_status': forms.Select(attrs={
                'class': TW_INPUT,
                'id': 'modal-status-select',
            }),
            'acceptance_link': forms.URLInput(attrs={
                'class': TW_INPUT,
                'placeholder': 'https://… acceptance letter / proof link',
            }),
            'publication_url': forms.URLInput(attrs={
                'class': TW_INPUT,
                'placeholder': 'https://doi.org/... the live publication / DOI link',
            }),
        }

    def clean_publication_status(self):
        status = self.cleaned_data.get('publication_status')
        if status and status not in PublicationStatus.values:
            raise ValidationError('Invalid publication status.')
        return status

    def clean_acceptance_file(self):
        uploaded = self.cleaned_data.get('acceptance_file')
        if not uploaded:
            return None
        ext = Path(uploaded.name).suffix.lower()
        if ext not in ACCEPTANCE_ALLOWED_EXTENSIONS:
            raise ValidationError('Acceptance proof must be a PNG, JPG or PDF file.')
        if uploaded.size and uploaded.size > ACCEPTANCE_MAX_SIZE_MB * 1024 * 1024:
            raise ValidationError(
                f'Acceptance proof is too large — please keep it under {ACCEPTANCE_MAX_SIZE_MB} MB.'
            )
        return uploaded

    def save(self, commit=True):
        """Persist the status fields and (when picked) the proof upload."""
        project = super().save(commit=False)
        uploaded = self.cleaned_data.get('acceptance_file')
        if uploaded:
            project.acceptance_file = uploaded
        if commit:
            project.save()
        return project


# ---------------------------------------------------------------------------
# ADMIN: service catalogue management (FTSD §3.1 / transcript §2)
# ---------------------------------------------------------------------------
class ServiceTypeForm(forms.ModelForm):
    """
    Add / edit a service in the catalogue.  Admin-only (the view re-checks
    the role); ``default_slots`` provisions the author slots for new
    projects of this type.
    """

    class Meta:
        model = ServiceType
        fields = ['name', 'description', 'base_price', 'default_slots', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': TW_INPUT,
                'placeholder': 'e.g. Scopus Guaranteed',
            }),
            'description': forms.Textarea(attrs={
                'class': TW_INPUT + ' min-h-[60px] resize-y',
                'placeholder': 'What the service covers…',
            }),
            'base_price': forms.NumberInput(attrs={
                'class': TW_INPUT, 'min': '0', 'step': '0.01',
                'placeholder': 'e.g. 55000',
            }),
            'default_slots': forms.NumberInput(attrs={
                'class': TW_INPUT, 'min': '1', 'max': '20',
                'placeholder': '1 for books, 4-8 for papers / patents',
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'h-4 w-4 rounded border-slate-300 text-emerald-600 '
                         'focus:ring-emerald-500 accent-emerald-600',
            }),
        }

    def clean_default_slots(self):
        slots = self.cleaned_data.get('default_slots')
        if slots is not None and (slots < 1 or slots > 20):
            raise ValidationError('Author slots must be between 1 and 20.')
        return slots


# ---------------------------------------------------------------------------
# ADMIN: team management (add BDE / Accounts members)
# ---------------------------------------------------------------------------
class TeamMemberForm(forms.Form):
    """
    Onboarding form used by ADMINs on the Team Management page to create
    BDE (sales) or ACCOUNTS executives.

    SECURITY BOUNDARIES
    -------------------
    * `role` is whitelisted to BDE / ACCOUNTS -- admins are provisioned
      out-of-band (Django admin), never through this form.
    * Passwords run through Django's built-in password validators.
    """

    ROLE_CHOICES = (('', 'Choose a role…'), (Role.BDE, 'BDE — Sales executive'),
                    (Role.ACCOUNTS, 'Accounts — verifications'))

    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': TW_INPUT,
            'placeholder': 'e.g. bde.ravi (used to sign in)',
            'autocomplete': 'off',
        }),
    )
    first_name = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': TW_INPUT, 'placeholder': 'e.g. Ravi',
        }),
    )
    last_name = forms.CharField(
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={
            'class': TW_INPUT, 'placeholder': 'e.g. Krishnan (optional)',
        }),
    )
    email = forms.EmailField(
        required=False,
        widget=forms.EmailInput(attrs={
            'class': TW_INPUT, 'placeholder': 'name@company.com (optional)',
        }),
    )
    phone = forms.CharField(
        max_length=20, required=False,
        widget=forms.TextInput(attrs={
            'class': TW_INPUT, 'placeholder': 'e.g. +91 98xxxxxx00 (optional)',
        }),
    )
    employee_id = forms.CharField(
        max_length=30, required=False,
        widget=forms.TextInput(attrs={
            'class': TW_INPUT, 'placeholder': 'e.g. EMP-014 (optional)',
        }),
    )
    role = forms.ChoiceField(
        choices=ROLE_CHOICES,
        widget=forms.Select(attrs={'class': TW_INPUT}),
    )
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={
            'class': TW_INPUT,
            'placeholder': 'Min. 8 characters',
            'autocomplete': 'new-password',
        }),
    )
    password2 = forms.CharField(
        label='Confirm password',
        widget=forms.PasswordInput(attrs={
            'class': TW_INPUT,
            'placeholder': 'Repeat the password',
            'autocomplete': 'new-password',
        }),
    )

    def clean_username(self):
        username = self.cleaned_data['username'].strip().lower()
        if User.objects.filter(username__iexact=username).exists():
            raise ValidationError('That username is already taken.')
        return username

    def clean_role(self):
        role = self.cleaned_data['role']
        if role not in (Role.BDE, Role.ACCOUNTS):
            raise ValidationError('Select either BDE (Sales) or Accounts.')
        return role

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get('password1')
        p2 = cleaned.get('password2')
        if p1 and p2 and p1 != p2:
            raise ValidationError({'password2': 'The two password fields do not match.'})
        if p1:
            # Run Django's password validators (length, common words, similarity...).
            # The ValidationError message list is surfaced under password1.
            try:
                validate_password(p1)
            except ValidationError as exc:
                raise ValidationError({'password1': list(exc.messages)})
        return cleaned
