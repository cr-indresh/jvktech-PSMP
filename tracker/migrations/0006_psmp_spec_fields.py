"""
PSMP spec-exact schema migration (FTSD 3 data dictionary).

Field renames map the old PoC names onto the spec names:
  Project.acceptance_status -> publication_status (7-stage lifecycle)
  Project.publication_link   -> publication_url
  Project.discount_offered   -> discount_value
  PaymentInstallment.installment_type -> payment_type
  PaymentInstallment.amount           -> amount_paid
  PaymentInstallment.transaction_id   -> transaction_ref (encrypted at rest)

New capabilities: service base price + provisioned author slots, project
total_slots + acceptance proof upload, full author profile data (FTSD 3.2),
payment date / mode / remarks + auto installment number, 3-state
verification (Pending / Verified / Rejected), the AuditLog trail (FTSD 7.0)
and field-level encryption for phone numbers + UTRs.

Data migrations keep LEGACY databases upgradeable (value remapping,
ciphertext backfill, slot provisioning backfill); on a fresh database they
are all no-ops.
"""

from django.core.validators import MinValueValidator
from django.db import migrations, models

import tracker.models


def _cipher():
    """Reuse the model layer's Fernet helper (imported lazily)."""
    import base64
    import hashlib
    from django.conf import settings
    from cryptography.fernet import Fernet
    material = getattr(settings, 'FIELD_ENC_KEY', '') or settings.SECRET_KEY
    digest = hashlib.sha256(material.encode('utf-8')).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


ENC_PREFIX = 'enc::'


def map_verification_status(apps, schema_editor):
    """is_verified (bool) -> verification_status ('VERIFIED' / 'PENDING')."""
    PaymentInstallment = apps.get_model('tracker', 'PaymentInstallment')
    PaymentInstallment.objects.filter(is_verified=True).update(
        verification_status='VERIFIED')
    PaymentInstallment.objects.filter(is_verified=False).update(
        verification_status='PENDING')


def map_publication_status(apps, schema_editor):
    """Old 3-state values -> FTSD 7-stage lifecycle values."""
    Project = apps.get_model('tracker', 'Project')
    Project.objects.filter(publication_status='PENDING').update(
        publication_status='SUBMITTED')


def encrypt_sensitive_fields(apps, schema_editor):
    """
    Field-level encryption backfill (FTSD 7.0): encrypt any plaintext
    author phone number and payment transaction reference still stored in
    the clear (values already carrying the enc:: prefix are skipped).
    """
    Author = apps.get_model('tracker', 'Author')
    PaymentInstallment = apps.get_model('tracker', 'PaymentInstallment')
    try:
        cipher = _cipher()
    except Exception:
        return  # cryptography unavailable -- leave values untouched
    for author in Author.objects.exclude(phone='').iterator():
        if not author.phone.startswith(ENC_PREFIX):
            author.phone = ENC_PREFIX + cipher.encrypt(
                author.phone.encode('utf-8')).decode('ascii')
            author.save(update_fields=['phone'])
    for inst in (PaymentInstallment.objects.exclude(transaction_ref='')
                 .order_by('id').iterator()):
        if not inst.transaction_ref.startswith(ENC_PREFIX):
            inst.transaction_ref = ENC_PREFIX + cipher.encrypt(
                inst.transaction_ref.encode('utf-8')).decode('ascii')
            inst.save(update_fields=['transaction_ref'])


def backfill_slots_and_numbers(apps, schema_editor):
    """
    Provision total_slots for legacy projects (from the service catalogue,
    never below the authors already booked) and assign the auto-incrementing
    installment_number 1..N within every project.
    """
    Project = apps.get_model('tracker', 'Project')
    PaymentInstallment = apps.get_model('tracker', 'PaymentInstallment')
    for project in Project.objects.select_related('service_type').iterator():
        booked = project.authors.count()
        project.total_slots = max(project.service_type.default_slots, booked, 1)
        project.save(update_fields=['total_slots'])
    for project in Project.objects.all().iterator():
        number = 0
        for inst in (PaymentInstallment.objects.filter(project=project)
                     .order_by('id')):
            number += 1
            if inst.installment_number != number:
                inst.installment_number = number
                inst.save(update_fields=['installment_number'])


class Migration(migrations.Migration):

    dependencies = [
        ('tracker', '0005_remove_servicetype_max_authors_alter_author_details'),
    ]

    operations = [
        # -- Project: renames + lifecycle + slots + acceptance proof -----
        # (old indexes are dropped while the column still carries the old
        #  name, then recreated on the renamed column further below)
        migrations.RemoveIndex(
            model_name='project',
            name='tracker_pro_accepta_993d1e_idx',
        ),
        migrations.RemoveIndex(
            model_name='project',
            name='tracker_pro_bde_id_1086fc_idx',
        ),
        migrations.RenameField(
            model_name='project',
            old_name='acceptance_status',
            new_name='publication_status',
        ),
        migrations.AlterField(
            model_name='project',
            name='publication_status',
            field=models.CharField(
                choices=[
                    ('DRAFT', 'Draft'),
                    ('SUBMITTED', 'Submitted'),
                    ('UNDER_REVIEW', 'Under Review'),
                    ('ACCEPTED', 'Accepted'),
                    ('PUBLISHED', 'Published'),
                    ('COMPLETED', 'Completed'),
                    ('WITHDRAWN', 'Withdrawn'),
                ],
                default='DRAFT',
                max_length=12,
            ),
        ),
        migrations.RunPython(map_publication_status, migrations.RunPython.noop),
        migrations.AddIndex(
            model_name='project',
            index=models.Index(fields=['publication_status'], name='tracker_pro_publica_15d348_idx'),
        ),
        migrations.AddIndex(
            model_name='project',
            index=models.Index(fields=['bde', 'publication_status'], name='tracker_pro_bde_id_e39f66_idx'),
        ),
        migrations.RenameField(
            model_name='project',
            old_name='publication_link',
            new_name='publication_url',
        ),
        migrations.RenameField(
            model_name='project',
            old_name='discount_offered',
            new_name='discount_value',
        ),
        migrations.AlterField(
            model_name='project',
            name='title',
            field=models.CharField(max_length=500),
        ),
        migrations.AddField(
            model_name='project',
            name='total_slots',
            field=models.PositiveIntegerField(
                default=1,
                help_text='Total author slots provisioned for this title.',
            ),
        ),
        migrations.AddField(
            model_name='project',
            name='acceptance_file',
            field=models.FileField(
                blank=True,
                default='',
                help_text='Acceptance proof (PNG, JPG or PDF, max 10 MB) -- FTSD §3.4.',
                upload_to='acceptance/%Y/%m/',
            ),
            preserve_default=True,
        ),

        # -- ServiceType: base price + provisioned author slots -----------
        migrations.AddField(
            model_name='servicetype',
            name='base_price',
            field=models.DecimalField(
                decimal_places=2, default=0, max_digits=12,
                validators=[MinValueValidator(0)],
                help_text='Base service price (INR).',
            ),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='servicetype',
            name='default_slots',
            field=models.PositiveIntegerField(
                default=1,
                help_text='Author slots provisioned for a new project of this '
                          'type (1 for books / full titles, 4-8 for patents & papers).',
            ),
            preserve_default=True,
        ),

        # -- Author: full FTSD 3.2 profile data + encrypted phone ---------
        migrations.AddField(
            model_name='author', name='designation',
            field=models.CharField(blank=True, default='', max_length=150),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='author', name='department',
            field=models.CharField(blank=True, default='', max_length=150),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='author', name='company_name',
            field=models.CharField(blank=True, default='', max_length=200),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='author', name='full_address',
            field=models.TextField(blank=True, default=''),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='author', name='city',
            field=models.CharField(blank=True, default='', max_length=100),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='author', name='district',
            field=models.CharField(blank=True, default='', max_length=100),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='author', name='state',
            field=models.CharField(blank=True, default='', max_length=100),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='author', name='country',
            field=models.CharField(blank=True, default='', max_length=100),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='author', name='pin_code',
            field=models.CharField(blank=True, default='', max_length=12),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='author', name='nationality',
            field=models.CharField(blank=True, default='', max_length=60),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='author',
            name='phone',
            field=tracker.models.EncryptedCharField(blank=True, help_text='Author contact phone (encrypted at rest).', max_length=255),
        ),

        # -- PaymentInstallment: renames + FTSD 3.3 metadata --------------
        migrations.RenameField(
            model_name='paymentinstallment',
            old_name='installment_type',
            new_name='payment_type',
        ),
        migrations.AlterField(
            model_name='paymentinstallment',
            name='payment_type',
            field=models.CharField(
                choices=[
                    ('ADVANCE_1', 'Advance Amount'),
                    ('ADVANCE_2', 'Installment 2'),
                    ('REMAINING', 'Remaining / Full Settlement'),
                ],
                max_length=12,
            ),
        ),
        migrations.RenameField(
            model_name='paymentinstallment',
            old_name='amount',
            new_name='amount_paid',
        ),
        migrations.RenameField(
            model_name='paymentinstallment',
            old_name='transaction_id',
            new_name='transaction_ref',
        ),
        migrations.AlterField(
            model_name='paymentinstallment',
            name='transaction_ref',
            field=tracker.models.EncryptedCharField(
                help_text='UPI Ref No / UTR / IMPS reference (encrypted at rest).',
                max_length=255,
            ),
        ),
        migrations.AddField(
            model_name='paymentinstallment',
            name='installment_number',
            field=models.PositiveIntegerField(
                default=1,
                help_text='Auto-incrementing log number within the project (1, 2, 3 ...).',
            ),
        ),
        # Historical Meta.ordering still referenced the renamed field --
        # point it at the new auto-incrementing log number.
        migrations.AlterModelOptions(
            name='paymentinstallment',
            options={'ordering': ['installment_number', 'id']},
        ),
        migrations.AddField(
            model_name='paymentinstallment',
            name='payment_mode',
            field=models.CharField(
                choices=[('UPI', 'UPI'), ('BANK_TRANSFER', 'Bank Transfer'), ('OTHER', 'Other')],
                default='UPI', max_length=15,
            ),
        ),
        migrations.AddField(
            model_name='paymentinstallment',
            name='payment_date',
            field=models.DateField(
                blank=True, help_text='When the customer actually made this payment.',
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='paymentinstallment',
            name='remarks',
            field=models.CharField(blank=True, default='', max_length=250),
            preserve_default=True,
        ),

        # -- 3-state verification (Pending / Verified / Rejected) ---------
        migrations.RemoveIndex(
            model_name='paymentinstallment',
            name='tracker_pay_is_veri_d2aafd_idx',
        ),
        migrations.AddField(
            model_name='paymentinstallment',
            name='verification_status',
            field=models.CharField(
                choices=[('PENDING', 'Pending'), ('VERIFIED', 'Verified'), ('REJECTED', 'Rejected')],
                default='PENDING', max_length=10,
            ),
        ),
        migrations.RunPython(map_verification_status, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name='paymentinstallment',
            name='is_verified',
        ),
        migrations.AddIndex(
            model_name='paymentinstallment',
            index=models.Index(fields=['verification_status'], name='tracker_pay_verific_bde268_idx'),
        ),
        migrations.AlterField(
            model_name='paymentinstallment',
            name='verified_by',
            field=models.ForeignKey(
                blank=True, help_text='', null=True,
                on_delete=models.SET_NULL,
                related_name='installments_verified',
                to='auth.user',
            ),
        ),

        # -- Audit trail (FTSD 7.0) ----------------------------------------
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('user_name', models.CharField(blank=True, max_length=150)),
                ('action', models.CharField(choices=[('CREATE', 'Create'), ('UPDATE', 'Update'), ('DELETE', 'Delete')], max_length=10)),
                ('entity_type', models.CharField(max_length=60)),
                ('entity_id', models.CharField(blank=True, max_length=40)),
                ('entity_label', models.CharField(blank=True, max_length=250)),
                ('old_values', models.JSONField(blank=True, null=True)),
                ('new_values', models.JSONField(blank=True, null=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=models.SET_NULL, related_name='audit_entries', to='auth.user')),
            ],
            options={
                'ordering': ['-timestamp'],
                'verbose_name': 'Audit log entry',
                'verbose_name_plural': 'Audit log entries',
            },
        ),

        # -- data backfills for legacy rows (no-ops on a fresh DB) ---------
        migrations.RunPython(encrypt_sensitive_fields, migrations.RunPython.noop),
        migrations.RunPython(backfill_slots_and_numbers, migrations.RunPython.noop),
    ]
