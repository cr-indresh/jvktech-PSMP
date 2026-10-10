"""
Signals ensuring every User automatically owns a UserProfile.

Superusers receive the ADMIN role; everyone else defaults to BDE until an
administrator changes it (seed_demo / Django admin).
"""

from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import Role, UserProfile


@receiver(post_save, sender=User)
def ensure_user_profile(sender, instance, created, **kwargs):
    """Create the 1:1 profile on the fly whenever a user is saved."""
    if not hasattr(instance, 'profile'):
        UserProfile.objects.create(
            user=instance,
            role=Role.ADMIN if instance.is_superuser else Role.BDE,
        )
