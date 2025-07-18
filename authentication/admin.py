from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from .models import User, UserProfile, UserSession


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """
    Configuration admin pour le modèle User personnalisé
    """
    list_display = ('email', 'username', 'first_name', 'last_name', 'tenant_id', 'is_active', 'is_verified', 'date_joined')
    list_filter = ('is_active', 'is_verified', 'is_staff', 'is_superuser', 'date_joined')
    search_fields = ('email', 'username', 'first_name', 'last_name', 'tenant_id')
    ordering = ('-date_joined',)
    readonly_fields = ('id', 'date_joined', 'last_login', 'updated_at')
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Informations personnelles'), {
            'fields': ('username', 'first_name', 'last_name', 'phone', 'avatar')
        }),
        (_('Tenant'), {
            'fields': ('tenant_id',)
        }),
        (_('Permissions'), {
            'fields': ('is_active', 'is_verified', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        (_('Préférences'), {
            'fields': ('language', 'timezone'),
        }),
        (_('Dates importantes'), {
            'fields': ('date_joined', 'last_login', 'updated_at'),
        }),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2', 'tenant_id'),
        }),
        (_('Informations personnelles'), {
            'fields': ('first_name', 'last_name', 'phone'),
        }),
    )
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        # Les admins non-superuser ne voient que les utilisateurs de leur tenant
        return qs.filter(tenant_id=request.user.tenant_id)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """
    Configuration admin pour UserProfile
    """
    list_display = ('user', 'company_role', 'department', 'email_notifications', 'sms_notifications')
    list_filter = ('email_notifications', 'sms_notifications', 'created_at')
    search_fields = ('user__email', 'user__first_name', 'user__last_name', 'company_role', 'department')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        (_('Utilisateur'), {
            'fields': ('user',)
        }),
        (_('Informations professionnelles'), {
            'fields': ('bio', 'website', 'company_role', 'department')
        }),
        (_('Préférences de notification'), {
            'fields': ('email_notifications', 'sms_notifications')
        }),
        (_('Métadonnées'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        # Filtrer par tenant
        return qs.filter(user__tenant_id=request.user.tenant_id)


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    """
    Configuration admin pour UserSession
    """
    list_display = ('user', 'ip_address', 'is_active', 'created_at', 'last_activity')
    list_filter = ('is_active', 'created_at', 'last_activity')
    search_fields = ('user__email', 'ip_address', 'user_agent')
    readonly_fields = ('session_key', 'created_at', 'last_activity')
    
    fieldsets = (
        (_('Session'), {
            'fields': ('user', 'session_key', 'is_active')
        }),
        (_('Informations de connexion'), {
            'fields': ('ip_address', 'user_agent')
        }),
        (_('Métadonnées'), {
            'fields': ('created_at', 'last_activity'),
        }),
    )
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        # Filtrer par tenant
        return qs.filter(user__tenant_id=request.user.tenant_id)
    
    def has_add_permission(self, request):
        # Empêcher la création manuelle de sessions
        return False
