"""Django admin registration (mainly for ADMIN data fixes).

The PoC UI is entirely custom (role dashboards); Django admin is kept as a
safety net for administrative corrections (e.g. editing a saved author,
which BDEs are forbidden from doing).
"""

from django.contrib import admin

from .models import Author, PaymentInstallment, Project, ServiceType, UserProfile


@admin.register(ServiceType)
class ServiceTypeAdmin(admin.ModelAdmin):
    list_display = ('name', 'base_price', 'default_slots', 'is_active')
    search_fields = ('name',)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'employee_id')
    list_filter = ('role',)
    search_fields = ('user__username', 'user__first_name')


class AuthorInline(admin.TabularInline):
    model = Author
    extra = 0
    ordering = ('position',)


class InstallmentInline(admin.TabularInline):
    model = PaymentInstallment
    extra = 0
    fields = ('installment_number', 'author', 'payment_type', 'amount_paid',
              'transaction_ref', 'payment_mode', 'payment_date',
              'verification_status')
    readonly_fields = ('submitted_by', 'submitted_at', 'verified_by', 'verification_date')


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('title', 'service_type', 'bde', 'sale_value',
                    'discount_value', 'publication_status', 'created_at')
    list_filter = ('publication_status', 'service_type', 'bde')
    search_fields = ('title',)
    inlines = (AuthorInline, InstallmentInline)


@admin.register(PaymentInstallment)
class PaymentInstallmentAdmin(admin.ModelAdmin):
    list_display = ('id', 'project', 'installment_number', 'author', 'payment_type',
                    'amount_paid', 'submitted_by', 'verification_status', 'verified_by',
                    'verification_date')
    list_filter = ('verification_status', 'payment_type')
    search_fields = ('transaction_ref', 'author__name', 'project__title')
