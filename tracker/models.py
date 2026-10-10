"""
Data models for the Publication & Sales Operations Management Portal (PSMP).

Workflow (FTSD §1.0)
--------------------
1. BDE (sales)  -> creates a Project for a ServiceType.  The application
   provisions the project's TOTAL AUTHOR SLOTS from the service catalogue
   (FTSD §4.1.2), the BDE books slots by entering the author profile data
   (each booked position is LOCKED for everybody else -- the UNIQUE
   (project, position) constraint is the hard slot lock of §4.1.4) and
   logs payment installments (UTR + proof + mode + date).
2. ACCOUNTS     -> verifies / rejects PaymentInstallments against the bank
   feeds and drives the publication lifecycle (Draft -> Submitted -> Under
   Review -> Accepted -> Published -> Completed / Withdrawn), uploading the
   acceptance proof and pasting the live publication URL (FTSD §3.4, §4.3).
3. ADMIN        -> analyses everything through a filterable dashboard with
   KPIs, aging report and CSV export, manages the service catalogue and the
   team; every critical operation lands in the audit trail (FTSD §7.0).

Business rules enforced at the MODEL layer (defense-in-depth; the views and
forms layer enforces the same rules for a friendly UX):
* Only ACCOUNTS users may verify / reject a payment (clean()).
* A user can never verify a payment they submitted themselves.
* Once an installment is VERIFIED it is immutable for the BDE role
  (FTSD §7.0 data immutability) -- Accounts must revert it first.
* Sensitive contact numbers and financial UTRs are encrypted at rest
  (FTSD §7.0 field-level encryption -- see EncryptedCharField below:
  an authenticated SHA-256-CTR keystream cipher + HMAC-SHA256 built
  ONLY on the Python standard library, so it can never break because
  of a missing third-party package).
"""

import base64
import hashlib
import hmac
import os
from decimal import Decimal
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.db import models

# ---------------------------------------------------------------------------
# Field-level encryption (FTSD §7.0) -- sensitive phone numbers + UTRs
# ---------------------------------------------------------------------------
# IMPORTANT: this cipher is implemented with the Python STANDARD LIBRARY
# only (hashlib + hmac + os).  The previous Fernet implementation depended
# on the third-party ``cryptography`` package, which kept disappearing from
# the sandbox virtualenv -- when that happened every screen showed raw
# ``enc::gAAAAAB...`` ciphertext instead of the decrypted value.  A cipher
# that silently degrades into showing ciphertext is worse than a slightly
# less flashy one that always works, hence this dependency-free rewrite.
# Design: 16-byte random nonce, SHA-256-CTR keystream XOR, and an
# encrypt-then-MAC HMAC-SHA256 authentication tag (truncated to 16 bytes).

ENC_PREFIX = 'enc::'
V2_MARK = 'v2.'          # new stdlib-cipher payloads: enc::v2.<b64(nonce|ct|tag)>
_LEGACY_FERNET_B64 = 'gA'  # legacy tokens (Fernet v0x80) start with 'gA' in base64


def _enc_material():
    """Domain-separated keys derived from the field-encryption secret.

    The keys are derived (SHA-256) so ANY random string works as
    settings.FIELD_ENC_KEY -- in production set a dedicated secret and
    NEVER recycle SECRET_KEY for it.
    """
    material = (getattr(settings, 'FIELD_ENC_KEY', '') or settings.SECRET_KEY).encode('utf-8')
    enc_key = hashlib.sha256(material + b'|psmp|field-enc|v2').digest()
    mac_key = hashlib.sha256(material + b'|psmp|field-mac|v2').digest()
    return enc_key, mac_key


def _v2_keystream_xor(enc_key, nonce, data):
    """XOR ``data`` with a SHA-256-CTR keystream seeded by (enc_key, nonce)."""
    out = bytearray(len(data))
    for block in range((len(data) + 31) // 32):
        stream = hashlib.sha256(enc_key + nonce + block.to_bytes(4, 'big')).digest()
        chunk = data[block * 32:(block + 1) * 32]
        for i, byte in enumerate(chunk):
            out[block * 32 + i] = byte ^ stream[i]
    return bytes(out)


def _v2_encrypt(plaintext: str) -> str:
    """Encrypt to ``enc::v2.<urlsafe-b64(nonce|ciphertext|tag)>``."""
    enc_key, mac_key = _enc_material()
    nonce = os.urandom(16)
    ciphertext = _v2_keystream_xor(enc_key, nonce, plaintext.encode('utf-8'))
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()[:16]
    return ENC_PREFIX + V2_MARK + base64.urlsafe_b64encode(nonce + ciphertext + tag).decode('ascii')


def _v2_decrypt(payload: str):
    """Verify + decrypt a ``v2.`` payload; ``None`` if the tag check fails."""
    try:
        raw = base64.urlsafe_b64decode(payload[len(V2_MARK):].encode('ascii'))
        nonce, ciphertext, tag = raw[:16], raw[16:-16], raw[-16:]
        if not ciphertext or len(raw) < 33:
            return None
        enc_key, mac_key = _enc_material()
        expected = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected):
            return None
        return _v2_keystream_xor(enc_key, nonce, ciphertext).decode('utf-8')
    except Exception:
        return None


def _legacy_fernet_decrypt(payload: str):
    """Best-effort decryption of legacy ``enc::gAAAA...`` Fernet tokens.

    Only needed for databases written by the old implementation.  If the
    optional ``cryptography`` package happens to be installed we decrypt;
    otherwise the value is returned untouched (v2 values never rely on
    this path).
    """
    try:
        from cryptography.fernet import Fernet, InvalidToken  # optional
    except ImportError:
        return None
    material = getattr(settings, 'FIELD_ENC_KEY', '') or settings.SECRET_KEY
    digest = hashlib.sha256(material.encode('utf-8')).digest()
    try:
        return Fernet(base64.urlsafe_b64encode(digest)).decrypt(
            payload.encode('ascii')).decode('utf-8')
    except (InvalidToken, Exception):
        return None


class EncryptedCharField(models.CharField):
    """
    Transparent encryption-at-rest for short sensitive text columns.

    * ``from_db_value`` decrypts ``enc::<payload>`` values on the way OUT
      (forms + templates always see the plaintext);
    * ``get_prep_value`` encrypts on the way IN;
    * values that are already encrypted (or empty) pass through untouched.
    Payloads are ``v2.`` (stdlib cipher -- see above); legacy Fernet
    tokens are still readable when ``cryptography`` is available.
    Equality/contains LOOKUPS on the ciphertext are not meaningful -- the
    app never filters on phone / UTR, so this is a safe trade-off.
    """

    def get_prep_value(self, value):
        if not value:
            return value
        if isinstance(value, str) and value.startswith(ENC_PREFIX):
            return value
        return _v2_encrypt(value)

    def from_db_value(self, value, expression, connection):
        if not value or not isinstance(value, str) or not value.startswith(ENC_PREFIX):
            return value
        payload = value[len(ENC_PREFIX):]
        if payload.startswith(V2_MARK):
            plaintext = _v2_decrypt(payload)
            return value if plaintext is None else plaintext
        if payload.startswith(_LEGACY_FERNET_B64):
            plaintext = _legacy_fernet_decrypt(payload)
            return value if plaintext is None else plaintext
        return value


# ---------------------------------------------------------------------------
# Enumerations (FTSD §3 data dictionary)
# ---------------------------------------------------------------------------
class Role(models.TextChoices):
    """User roles used across the system (stored on UserProfile)."""
    ADMIN = 'ADMIN', 'Administrator'
    BDE = 'BDE', 'BDE (Sales)'
    ACCOUNTS = 'ACCOUNTS', 'Accounts'


class PublicationStatus(models.TextChoices):
    """Editorial lifecycle (FTSD §3.4)."""
    DRAFT = 'DRAFT', 'Draft'
    SUBMITTED = 'SUBMITTED', 'Submitted'
    UNDER_REVIEW = 'UNDER_REVIEW', 'Under Review'
    ACCEPTED = 'ACCEPTED', 'Accepted'
    PUBLISHED = 'PUBLISHED', 'Published'
    COMPLETED = 'COMPLETED', 'Completed'
    WITHDRAWN = 'WITHDRAWN', 'Withdrawn'


class PaymentType(models.TextChoices):
    """Installment phases (FTSD §3.3)."""
    ADVANCE_1 = 'ADVANCE_1', 'Advance Amount'
    ADVANCE_2 = 'ADVANCE_2', 'Installment 2'
    REMAINING = 'REMAINING', 'Remaining / Full Settlement'


class VerificationStatus(models.TextChoices):
    """Accounts clearing status of an installment (FTSD §3.3)."""
    PENDING = 'PENDING', 'Pending'
    VERIFIED = 'VERIFIED', 'Verified'
    REJECTED = 'REJECTED', 'Rejected'


class PaymentMode(models.TextChoices):
    """How the customer actually moved the money (FTSD transcript §4)."""
    UPI = 'UPI', 'UPI'
    BANK_TRANSFER = 'BANK_TRANSFER', 'Bank Transfer'
    OTHER = 'OTHER', 'Other'


class AuditAction(models.TextChoices):
    """Critical operations recorded in the audit trail (FTSD §7.0)."""
    CREATE = 'CREATE', 'Create'
    UPDATE = 'UPDATE', 'Update'
    DELETE = 'DELETE', 'Delete'
    LOGIN = 'LOGIN', 'Sign-in'
    LOGOUT = 'LOGOUT', 'Sign-out'


# ---------------------------------------------------------------------------
# User profile (extends the built-in User with a role)
# ---------------------------------------------------------------------------
class UserProfile(models.Model):
    """
    One-to-one extension of django.contrib.auth.models.User.

    A post_save signal (tracker/signals.py) guarantees every User owns a
    profile, so `request.user.profile.role` is always safe after login.
    Superusers automatically receive the ADMIN role.
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='profile',
    )
    role = models.CharField(
        max_length=10,
        choices=Role.choices,
        default=Role.BDE,
        help_text='Access role controlling dashboards and API permissions.',
    )
    phone = models.CharField(max_length=20, blank=True)
    employee_id = models.CharField(max_length=30, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'User profile'
        verbose_name_plural = 'User profiles'

    def __str__(self):
        return f'{self.user.get_full_name() or self.user.username} ({self.get_role_display()})'

    # -- convenience properties ------------------------------------------
    @property
    def is_admin(self):
        return self.role == Role.ADMIN

    @property
    def is_bde(self):
        return self.role == Role.BDE

    @property
    def is_accounts(self):
        return self.role == Role.ACCOUNTS

    # -- single source of truth for role lookup ---------------------------
    @classmethod
    def get_role(cls, user):
        """
        Safely resolve the role of *any* user object.

        Returns None for anonymous users or (theoretically) profile-less
        users, which callers treat as "no privileged role".
        """
        if not getattr(user, 'is_authenticated', False):
            return None
        profile = getattr(user, 'profile', None)
        return profile.role if profile else None


# ---------------------------------------------------------------------------
# Catalogue (FTSD §3.1 -- admin-configurable service master)
# ---------------------------------------------------------------------------
class ServiceType(models.Model):
    """
    Catalogue of services sold by the consultancy (ABDC, Scopus
    Guaranteed, patents, copyrights, IEEE, Textbook ...).

    ``base_price``     -- base service price in INR (FTSD §3.1).
    ``default_slots``  -- author slots provisioned for a new project of
                          this type (1 for Books/Full Titles, 4-8 for
                          patents / journal papers).  Admin-configurable
                          (FTSD transcript §2 "Slot & Position
                          Configuration").
    """
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    base_price = models.DecimalField(
        max_digits=12, decimal_places=2, default=Decimal('0.00'),
        validators=[MinValueValidator(Decimal('0'))],
        help_text='Base service price (INR).',
    )
    default_slots = models.PositiveIntegerField(
        default=1,
        help_text='Author slots provisioned for a new project of this type '
                  '(1 for books / full titles, 4-8 for patents & papers).',
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


# ---------------------------------------------------------------------------
# Core entity: Project (a publication / patent engagement)
# ---------------------------------------------------------------------------
class Project(models.Model):
    """
    A sale / publication engagement tracked from signing to publication.

    * ``bde``             : the sales executive who owns the sale.
    * ``total_slots``     : author slots provisioned at creation from the
                            service catalogue (FTSD §4.1.2) -- the project
                            can never hold more authors than this.
    * publication fields  : maintained exclusively by the ACCOUNTS team
                            (BDEs can never set their own publication
                            status).
    """
    service_type = models.ForeignKey(
        ServiceType,
        on_delete=models.PROTECT,               # never orphan a sale
        related_name='projects',
    )
    bde = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='projects_sold',
        limit_choices_to={'profile__role': Role.BDE},
    )
    title = models.CharField(max_length=500)    # FTSD §3.1: max 500 chars
    sale_value = models.DecimalField(
        max_digits=12, decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))],
    )
    discount_value = models.DecimalField(
        max_digits=12, decimal_places=2, default=Decimal('0.00'),
        validators=[MinValueValidator(Decimal('0'))],
    )
    remarks = models.TextField(blank=True)

    # -- author slot provisioning (FTSD §4.1) ------------------------------
    total_slots = models.PositiveIntegerField(
        default=1,
        help_text='Total author slots provisioned for this title.',
    )

    # -- publication lifecycle (owned by Accounts, FTSD §3.4) --------------
    publication_status = models.CharField(
        max_length=12,
        choices=PublicationStatus.choices,
        default=PublicationStatus.DRAFT,
    )
    acceptance_file = models.FileField(
        upload_to='acceptance/%Y/%m/',
        blank=True, default='',
        help_text='Acceptance proof (PNG, JPG or PDF, max 10 MB) -- FTSD §3.4.',
    )
    # Acceptance-proof bytes stored INSIDE the SQLite database (same pattern
    # as PaymentInstallment.proof_data): captured on every upload, served
    # DB-first by views.project_acceptance_file, disk file kept as fallback.
    acceptance_data = models.BinaryField(
        blank=True, null=True,
        help_text='Raw bytes of the acceptance proof, stored in the database itself.',
    )
    acceptance_content_type = models.CharField(
        max_length=80, blank=True, default='',
        help_text='MIME type of the stored acceptance bytes (image/png, application/pdf, ...).',
    )
    acceptance_link = models.URLField(blank=True)
    publication_url = models.URLField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['publication_status']),
            models.Index(fields=['bde', 'publication_status']),
        ]

    def __str__(self):
        return f'{self.title} [{self.service_type.name}]'

    # ---- computed financials (use .prefetch_related('installments') ----
    @property
    def net_value(self):
        """Amount actually billable after discount."""
        return (self.sale_value or Decimal('0')) - (self.discount_value or Decimal('0'))

    @property
    def total_collected(self):
        """Sum of VERIFIED installment amounts (money actually in the bank)."""
        return sum(
            (i.amount_paid for i in self.installments.all()
             if i.verification_status == VerificationStatus.VERIFIED),
            Decimal('0'),
        )

    @property
    def total_pending(self):
        """Sum of PENDING installment amounts (awaiting Accounts clearing)."""
        return sum(
            (i.amount_paid for i in self.installments.all()
             if i.verification_status == VerificationStatus.PENDING),
            Decimal('0'),
        )

    @property
    def total_rejected(self):
        """Sum of REJECTED installment amounts (bounced by Accounts)."""
        return sum(
            (i.amount_paid for i in self.installments.all()
             if i.verification_status == VerificationStatus.REJECTED),
            Decimal('0'),
        )

    @property
    def total_scheduled(self):
        """Sum of ALL installment amounts (verified + pending + rejected).

        This is what the BDE has scheduled so far.  A project may be
        created with only PART of the payable amount scheduled (the BDE
        ticks "Schedule the remaining later") -- the balance is then
        filled in over time from the project page, so
        `total_scheduled < net_value` is a perfectly normal state while a
        deal is still being paid off.
        """
        return sum((i.amount_paid for i in self.installments.all()), Decimal('0'))

    @property
    def remaining_to_schedule(self):
        """Payable amount not yet covered by any installment.

        0 = fully scheduled; negative = over-scheduled (legacy rows);
        positive = the BDE still owes the schedule this many rupees.
        """
        return self.net_value - self.total_scheduled

    @property
    def balance_due(self):
        """Net billable minus VERIFIED collections (the true receivable)."""
        return self.net_value - self.total_collected

    @property
    def authors_count(self):
        return self.authors.count()

    @property
    def slots_remaining(self):
        return max(0, self.total_slots - self.authors.count())

    # ---- DB storage of the acceptance proof (acceptance_data) -----------
    ACCEPTANCE_CONTENT_TYPES = {
        '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
        '.pdf': 'application/pdf',
    }

    def capture_acceptance_into_db(self):
        """
        Mirror the stored acceptance proof's bytes into acceptance_data so
        the file lives INSIDE the SQLite database (called right after
        every upload save -- see views.update_project_status).  Returns
        True when bytes were captured.
        """
        if not self.acceptance_file:
            return False
        try:
            self.acceptance_file.open('rb')
            data = self.acceptance_file.read()
        except (FileNotFoundError, ValueError, OSError):
            return False
        if not data:
            return False
        self.acceptance_data = data
        self.acceptance_content_type = self.ACCEPTANCE_CONTENT_TYPES.get(
            Path(self.acceptance_file.name).suffix.lower(),
            'application/octet-stream')
        self.save(update_fields=['acceptance_data', 'acceptance_content_type'])
        return True

    # ---- payment-state classification for the admin filter (FTSD §5.0) --
    #  * FULLY_PAID   : verified collections cover the whole net value.
    #  * ADVANCE_PAID : some (but not all) of the net value is collected.
    #  * OVERDUE      : balance still due AND the deal is late -- the
    #                   lifecycle has moved past payment expectations
    #                   (Accepted / Published / Completed) or the project
    #                   is older than 30 days with money outstanding.
    @property
    def payment_state(self):
        if self.total_collected >= self.net_value and self.net_value > 0:
            return 'fully_paid'
        late = (
            self.publication_status in (
                PublicationStatus.ACCEPTED,
                PublicationStatus.PUBLISHED,
                PublicationStatus.COMPLETED,
            )
            or self.age_days > 30
        )
        if self.total_collected > 0:
            return 'overdue' if late and self.balance_due > 0 else 'advance_paid'
        if self.balance_due > 0 and late:
            return 'overdue'
        return 'unpaid'

    @property
    def age_days(self):
        from django.utils import timezone
        return max(0, (timezone.now() - self.created_at).days)

    def clean(self):
        # Discount can never exceed the sale value.
        if self.discount_value and self.sale_value and self.discount_value > self.sale_value:
            raise ValidationError({'discount_value': 'Discount cannot exceed the sale value.'})


# ---------------------------------------------------------------------------
# Authors (slot booking, FTSD §3.2)
# ---------------------------------------------------------------------------
class Author(models.Model):
    """
    An author booked into one SLOT of a Project.

    ``position`` is the booked slot number (1 = 1st Position, 2 = 2nd
    Position ...).  The UNIQUE (project, position) constraint is the hard
    slot LOCK of FTSD §4.1.4 -- once a position is booked it can never be
    double-sold, and a project can never hold more authors than its
    provisioned ``total_slots`` (validated in the views / forms).

    EDIT RIGHTS: the OWNING BDE may update an author's details after
    creation through the project page (views.project_authors_update) --
    the project binding and the slot itself stay fixed.  The ACCOUNTS
    role has read-only access to author personal records (FTSD §2.0).
    """
    POSITION_SUFFIXES = {1: 'st', 2: 'nd', 3: 'rd'}

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='authors')
    name = models.CharField(max_length=150)
    position = models.PositiveIntegerField(help_text='Booked slot: 1 = 1st Position, 2 = 2nd Position ...')
    details = models.TextField(blank=True, help_text='Extra notes (ORCID, requirements ...).')

    # -- author profile data (FTSD §3.2) ------------------------------------
    designation = models.CharField(max_length=150, blank=True, default='')
    department = models.CharField(max_length=150, blank=True, default='')
    company_name = models.CharField(max_length=200, blank=True, default='')
    full_address = models.TextField(blank=True, default='')
    city = models.CharField(max_length=100, blank=True, default='')
    district = models.CharField(max_length=100, blank=True, default='')
    state = models.CharField(max_length=100, blank=True, default='')
    country = models.CharField(max_length=100, blank=True, default='')
    pin_code = models.CharField(max_length=12, blank=True, default='')
    nationality = models.CharField(max_length=60, blank=True, default='')
    email = models.EmailField(
        blank=True,
        help_text='Author contact email (maintained by the owning BDE).',
    )
    phone = EncryptedCharField(
        max_length=255, blank=True,
        help_text='Author contact phone (encrypted at rest).',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['position']
        constraints = [
            models.UniqueConstraint(fields=['project', 'position'], name='unique_author_position'),
        ]

    def __str__(self):
        return f'{self.position_label}: {self.name}'

    @property
    def position_label(self):
        """Human slot label per FTSD §3.2 ('1st Position', '2nd Position'...)."""
        if 10 <= self.position % 100 <= 20:
            suffix = 'th'
        else:
            suffix = self.POSITION_SUFFIXES.get(self.position % 10, 'th')
        return f'{self.position}{suffix} Position'


# ---------------------------------------------------------------------------
# Payments (installment log, FTSD §3.3)
# ---------------------------------------------------------------------------
class PaymentInstallment(models.Model):
    """
    A payment installment logged by a BDE (transaction reference + proof)
    which the ACCOUNTS team then clears: Pending -> Verified / Rejected.

    PAYER (per-client workflow): every author pays INDIVIDUALLY, so each
    installment records WHICH booked author of the project made this
    payment (``author``).  The BDE picks the payer when logging the
    payment; the name then travels with the row everywhere -- the
    Accounts clearing queue, the admin payment ledger (UTR register),
    the project page and the audit trail.

    Verification fields (``verification_status``, ``verified_by``,
    ``verification_date``) are only ever written by the Accounts JSON API;
    the model-level clean() below is the last line of defence enforcing:
      * verifiers must hold the ACCOUNTS role,
      * nobody can clear a payment they submitted themselves.
    """
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='installments')
    # The author who PAID this installment (authors pay individually).
    # Nullable on purpose: rows logged before the payer was captured, and
    # SET_NULL so deleting an author row never orphans the money history.
    author = models.ForeignKey(
        Author,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='payments',
        help_text='The booked author who paid this installment (each author pays individually).',
    )
    payment_type = models.CharField(max_length=12, choices=PaymentType.choices)
    installment_number = models.PositiveIntegerField(
        default=1,
        help_text='Auto-incrementing log number within the project (1, 2, 3 ...).',
    )
    amount_paid = models.DecimalField(
        max_digits=12, decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))],
    )
    transaction_ref = EncryptedCharField(
        max_length=255,
        help_text='UPI Ref No / UTR / IMPS reference (encrypted at rest).',
    )
    payment_mode = models.CharField(
        max_length=15, choices=PaymentMode.choices, default=PaymentMode.UPI,
    )
    payment_date = models.DateField(
        null=True, blank=True,
        help_text='When the customer actually made this payment.',
    )
    remarks = models.CharField(max_length=250, blank=True, default='')
    # Photo / screenshot of the bank or UPI transaction, uploaded by the BDE
    # alongside the transaction reference.  The ACCOUNTS team opens it while
    # verifying the proof (see accounts_dashboard.html "View proof" modal).
    # FileField (not ImageField) on purpose: no Pillow dependency needed --
    # allowed extensions / size are validated in forms.PaymentInstallmentForm.
    proof_image = models.FileField(
        upload_to='proofs/%Y/%m/',
        blank=True,
        help_text='Photo / screenshot of the payment transaction (JPG, PNG, WebP or PDF, max 10 MB).',
    )
    # THE PHOTO BYTES THEMSELVES, stored INSIDE the SQLite database: the
    # upload flow mirrors the disk file into proof_data right after every
    # save (capture_proof_into_db), so the .sqlite3 file is fully
    # self-contained -- copying/backupping the DB carries every transaction
    # photo with it.  Serving is DB-first (views.installment_proof_file);
    # the media/ file stays as a compatibility fallback only.
    proof_data = models.BinaryField(
        blank=True, null=True,
        help_text='Raw bytes of the proof photo, stored in the database itself.',
    )
    proof_content_type = models.CharField(
        max_length=80, blank=True, default='',
        help_text='MIME type of the stored proof bytes (image/png, application/pdf, ...).',
    )

    # -- submission metadata ----------------------------------------------
    submitted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='installments_submitted',
    )
    submitted_at = models.DateTimeField(auto_now_add=True)

    # -- verification (Accounts only) --------------------------------------
    verification_status = models.CharField(
        max_length=10,
        choices=VerificationStatus.choices,
        default=VerificationStatus.PENDING,
    )
    verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='installments_verified',
    )
    verification_date = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['installment_number', 'id']
        indexes = [models.Index(fields=['verification_status'])]

    def __str__(self):
        payer = f' by {self.author.name}' if self.author_id else ''
        return (f'{self.get_payment_type_display()} - INR {self.amount_paid} '
                f'({self.transaction_ref}){payer}')

    @property
    def paid_by_label(self):
        """'Prof. Meera Iyer (1st Position)' or '' when the payer is not linked."""
        if not self.author_id:
            return ''
        return f'{self.author.name} ({self.author.position_label})'

    def clean(self):
        # Last line of defence -- mirrors the permission checks in views.py.
        if self.verified_by:
            verifier_role = UserProfile.get_role(self.verified_by)
            # The ACCOUNTS role clears payments -- and, since the admin holds
            # every Accounts action, so may an ADMIN.
            if verifier_role not in (Role.ACCOUNTS, Role.ADMIN):
                raise ValidationError('Only ACCOUNTS or ADMIN users can clear payments.')
            # "BDEs cannot verify their own payments" (also true for an
            # Account executive who somehow submitted a proof).
            if self.verified_by_id == self.submitted_by_id:
                raise ValidationError('A payment can never be cleared by the person who submitted it.')
        if self.verification_status in (VerificationStatus.VERIFIED,
                                        VerificationStatus.REJECTED) and not self.verified_by:
            raise ValidationError('A cleared payment must record who cleared it.')

    @property
    def is_verified(self):
        """Backwards-compatible boolean view of verification_status."""
        return self.verification_status == VerificationStatus.VERIFIED

    @property
    def submitted_by_name(self):
        user = self.submitted_by
        return user.get_full_name() or user.username if user else '—'

    # -- proof upload helpers (used by templates / JSON payloads) ----------
    IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.webp', '.gif'}

    @property
    def has_proof(self):
        return bool(self.proof_image)

    @property
    def proof_is_image(self):
        """True when the proof can be previewed in an <img> tag (vs an iframe)."""
        if not self.proof_image:
            return False
        return Path(self.proof_image.name).suffix.lower() in self.IMAGE_EXTENSIONS

    @property
    def proof_file_name(self):
        """Last path segment of the stored proof, e.g. 'utr-883729105.png'."""
        if not self.proof_image:
            return ''
        return self.proof_image.name.rsplit('/', 1)[-1]

    # -- DB storage of the photo (proof_data) ------------------------------
    PROOF_CONTENT_TYPES = {
        '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
        '.webp': 'image/webp', '.gif': 'image/gif', '.pdf': 'application/pdf',
    }

    def proof_mime_type(self):
        """MIME type for the stored photo, by file extension."""
        return self.PROOF_CONTENT_TYPES.get(
            Path(self.proof_image.name).suffix.lower()
            if self.proof_image else '', 'application/octet-stream')

    def capture_proof_into_db(self):
        """
        Mirror the stored proof file's bytes into proof_data so the photo
        lives INSIDE the SQLite database (called right after every upload
        save -- see views.project_create / project_payment_add /
        installment_edit / admin_payment_edit).  Returns True when bytes
        were captured.
        """
        if not self.proof_image:
            return False
        try:
            self.proof_image.open('rb')
            data = self.proof_image.read()
        except (FileNotFoundError, ValueError, OSError):
            return False
        if not data:
            return False
        self.proof_data = data
        self.proof_content_type = self.proof_mime_type()
        self.save(update_fields=['proof_data', 'proof_content_type'])
        return True


# ---------------------------------------------------------------------------
# Audit trail (FTSD §7.0)
# ---------------------------------------------------------------------------
class AuditLog(models.Model):
    """
    Automated log for every critical operation: who did what, when, and
    the OLD vs NEW values (JSON) of the touched fields.
    """
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='audit_entries',
    )
    # Denormalised name so entries stay readable after a user is deleted.
    user_name = models.CharField(max_length=150, blank=True)
    action = models.CharField(max_length=10, choices=AuditAction.choices)
    entity_type = models.CharField(max_length=60)
    entity_id = models.CharField(max_length=40, blank=True)
    entity_label = models.CharField(max_length=250, blank=True)
    old_values = models.JSONField(null=True, blank=True)
    new_values = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Audit log entry'
        verbose_name_plural = 'Audit log entries'

    def __str__(self):
        return f'{self.timestamp:%d %b %Y %H:%M} — {self.user_name} {self.action} {self.entity_type}'

    # -- readable change rendering (admin audit trail) -------------------
    #: Friendly labels for the fields that appear in old/new snapshots.
    #: Anything not listed falls back to the prettified field key.
    AUDIT_FIELD_LABELS = {
        'title': 'Title',
        'service_type': 'Service type',
        'total_amount': 'Total amount (₹)',
        'bde': 'BDE (owner)',
        'authors': 'Authors',
        'name': 'Author name',
        'email': 'Email',
        'phone': 'Phone (encrypted at rest)',
        'designation': 'Designation',
        'department': 'Department',
        'institution': 'Institution / Company',
        'city': 'City',
        'state': 'State',
        'country': 'Country',
        'author': 'Paid by author',
        'payment_type': 'Payment phase',
        'installment_number': 'Installment log #',
        'amount_paid': 'Amount paid (₹)',
        'transaction_ref': 'Transaction ref (UTR)',
        'payment_mode': 'Payment mode',
        'payment_date': 'Payment date',
        'remarks': 'Remarks',
        'verification_status': 'Verification status',
        'verified_by': 'Verified by',
        'verification_date': 'Verified on',
        'publication_status': 'Publication status',
        'acceptance_link': 'Acceptance link',
        'publication_url': 'Publication URL',
        'acceptance_file': 'Acceptance proof',
        'proof_image': 'Payment proof',
        'status': 'Status',
        'role': 'Role',
        'is_active': 'Active',
        'username': 'Username',
        'first_name': 'First name',
        'last_name': 'Last name',
        'base_price': 'Base price (₹)',
        'max_authors': 'Max author slots',
    }

    @staticmethod
    def _display_value(value, limit=110):
        """Human-readable rendering of ONE snapshot value."""
        if value is None:
            return '—'
        if value is True:
            return 'Yes'
        if value is False:
            return 'No'
        if value == '':
            return '(empty)'
        if isinstance(value, (list, tuple)):
            return ', '.join(str(v) for v in value) if value else '(none)'
        if isinstance(value, dict):
            return ', '.join(f'{k}: {v}' for k, v in value.items()) if value else '(none)'
        text = str(value)
        return text if len(text) <= limit else text[:limit - 1] + '…'

    @classmethod
    def _field_label(cls, key):
        return cls.AUDIT_FIELD_LABELS.get(key, key.replace('_', ' ').capitalize())

    @property
    def change_rows(self):
        """
        The old -> new changes as a list of readable rows:
        ``[{key, label, old, new, changed}, ...]`` -- changed fields first,
        then alphabetical.  Consumed by the admin audit trail template so
        the Change column renders a proper field-by-field diff instead of
        raw JSON.
        """
        old = self.old_values if isinstance(self.old_values, dict) else {}
        new = self.new_values if isinstance(self.new_values, dict) else {}
        rows = []
        for key in sorted(set(old) | set(new)):
            old_v, new_v = old.get(key), new.get(key)
            rows.append({
                'key': key,
                'label': self._field_label(key),
                'old': self._display_value(old_v),
                'new': self._display_value(new_v),
                'changed': old_v != new_v,
            })
        rows.sort(key=lambda r: (not r['changed'], r['label'].lower()))
        return rows

    @property
    def changes_summary(self):
        """
        One-line digest of the change (shown without expanding the row):
        ``"Verification status: Verified → Rejected · +2 more"``.
        """
        changed = [r for r in self.change_rows if r['changed']]
        if not changed:
            parts = [r['label'] for r in self.change_rows[:3]]
            suffix = f' · +{len(self.change_rows) - 3} more' if len(self.change_rows) > 3 else ''
            return ('Snapshot: ' + ', '.join(parts) + suffix) if parts else ''
        shown = changed[:2]
        text = ' · '.join(f'{r["label"]}: {r["old"]} → {r["new"]}' for r in shown)
        if len(changed) > 2:
            text += f' · +{len(changed) - 2} more'
        return text


def log_action(request, action, instance, *, old=None, new=None, label=None):
    """
    Write one audit-trail entry.

    ``old`` / ``new`` are plain dicts of field -> value (already JSON-safe;
    call sites pass e.g. model_to_dict snapshots).  Never raises: an audit
    failure must not break the business operation itself.
    """
    try:
        user = getattr(request, 'user', None)
        user = user if getattr(user, 'is_authenticated', False) else None
        meta = instance._meta
        AuditLog.objects.create(
            user=user,
            user_name=(user.get_full_name() or user.username) if user else 'system',
            action=action,
            entity_type=meta.label,
            entity_id=str(getattr(instance, 'pk', '') or ''),
            entity_label=(label or str(instance))[:250],
            old_values=old,
            new_values=new,
        )
    except Exception:   # pragma: no cover -- audit must never break flow
        pass
