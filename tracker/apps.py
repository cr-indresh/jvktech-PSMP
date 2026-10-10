from django.apps import AppConfig


class TrackerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'tracker'
    verbose_name = 'Publication & Payment Tracker'

    def ready(self):
        # Import signal handlers so profiles are auto-created.
        from . import signals  # noqa: F401
