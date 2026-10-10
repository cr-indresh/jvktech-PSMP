"""Add contact fields (email, phone) to Author.

The owning BDE maintains these through the project page
(views.project_authors_update); they are optional at the model level so
existing rows and the seed stay valid.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tracker', '0003_normalize_proof_image'),
    ]

    operations = [
        migrations.AddField(
            model_name='author',
            name='email',
            field=models.EmailField(
                blank=True,
                help_text='Author contact email (maintained by the owning BDE).',
                max_length=254,
            ),
        ),
        migrations.AddField(
            model_name='author',
            name='phone',
            field=models.CharField(
                blank=True,
                help_text='Author contact phone (maintained by the owning BDE).',
                max_length=20,
            ),
        ),
    ]
