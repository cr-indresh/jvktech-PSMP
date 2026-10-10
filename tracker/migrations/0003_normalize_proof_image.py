"""Normalize proof_image storage to '' (Django FileField convention).

0002 added the FileField as nullable, so pre-existing installment rows carry
NULL instead of ''.  FileField lookups (filter(proof_image='')) do not match
NULL rows in SQL, which silently skipped those rows in seed/sample tooling.
Convert NULLs to '' and tighten the column to NOT NULL going forward.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tracker', '0002_paymentinstallment_proof_image'),
    ]

    operations = [
        migrations.RunSQL(
            sql="UPDATE tracker_paymentinstallment SET proof_image = '' WHERE proof_image IS NULL;",
            reverse_sql=migrations.RunSQL.noop,
        ),
        migrations.AlterField(
            model_name='paymentinstallment',
            name='proof_image',
            field=models.FileField(
                blank=True,
                help_text='Photo / screenshot of the payment transaction '
                          '(JPG, PNG, WebP or PDF, max 5 MB).',
                upload_to='proofs/%Y/%m/',
            ),
        ),
    ]
