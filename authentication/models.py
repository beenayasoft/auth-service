from django.db import models
import uuid
import requests
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone
from django.conf import settings
from django.core.exceptions import ValidationError

# Create your models here.

class UserManager(BaseUserManager):
    """
    Manager personnalisé pour le modèle User
    """
    def create_user(self, email, password=None, tenant_id=None, **extra_fields):
        """Créer un utilisateur normal"""
        if not email:
            raise ValueError('L\'email est obligatoire')
        
        if not tenant_id:
            raise ValueError('Le tenant_id est obligatoire')
        
        # Vérifier que le tenant existe
        if not self._validate_tenant(tenant_id):
            raise ValidationError(f'Le tenant {tenant_id} n\'existe pas')
        
        email = self.normalize_email(email)
        user = self.model(
            email=email,
            tenant_id=tenant_id,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        """Créer un superutilisateur"""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Le superutilisateur doit avoir is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Le superutilisateur doit avoir is_superuser=True.')
        
        # Pour les superusers, on peut créer sans tenant ou avec un tenant par défaut
        tenant_id = extra_fields.pop('tenant_id', None)
        if not tenant_id:
            # Créer un tenant admin par défaut ou utiliser un tenant existant
            tenant_id = self._get_or_create_admin_tenant()
        
        return self.create_user(email, password, tenant_id, **extra_fields)
    
    def _validate_tenant(self, tenant_id):
        """Valider l'existence d'un tenant via le service tenant"""
        try:
            response = requests.get(
                f"{settings.TENANT_SERVICE_URL}/api/tenants/{tenant_id}/validate/",
                timeout=5
            )
            return response.status_code == 200
        except requests.RequestException:
            # En cas d'erreur de connexion, on log mais on n'empêche pas la création
            # (pour le développement ou si le service tenant est indisponible)
            return True
    
    def _get_or_create_admin_tenant(self):
        """Obtenir ou créer un tenant admin par défaut"""
        try:
            # Essayer de créer un tenant admin
            response = requests.post(
                f"{settings.TENANT_SERVICE_URL}/api/tenants/",
                json={
                    "name": "Admin",
                    "domain": "admin.local",
                    "is_active": True
                },
                timeout=5
            )
            if response.status_code in [200, 201]:
                return response.json()['id']
        except requests.RequestException:
            pass
        
        # Retourner un UUID par défaut si le service tenant n'est pas disponible
        return str(uuid.uuid4())


class User(AbstractBaseUser, PermissionsMixin):
    """
    Modèle utilisateur personnalisé avec support multi-tenant
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField('Adresse email', unique=True)
    username = models.CharField('Nom d\'utilisateur', max_length=150, blank=True)
    first_name = models.CharField('Prénom', max_length=30, blank=True)
    last_name = models.CharField('Nom', max_length=150, blank=True)
    
    # Champ crucial pour le multi-tenant
    tenant_id = models.UUIDField('ID du tenant', db_index=True)
    
    # Champs de statut
    is_active = models.BooleanField('Actif', default=True)
    is_staff = models.BooleanField('Staff', default=False)
    is_verified = models.BooleanField('Email vérifié', default=False)
    
    # Métadonnées
    date_joined = models.DateTimeField('Date d\'inscription', default=timezone.now)
    last_login = models.DateTimeField('Dernière connexion', blank=True, null=True)
    updated_at = models.DateTimeField('Modifié le', auto_now=True)
    
    # Champs optionnels pour le profil
    phone = models.CharField('Téléphone', max_length=20, blank=True)
    avatar = models.URLField('Avatar', blank=True)
    language = models.CharField('Langue', max_length=10, default='fr')
    timezone = models.CharField('Fuseau horaire', max_length=50, default='Europe/Paris')
    
    # Manager personnalisé
    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    class Meta:
        db_table = 'auth_users'
        verbose_name = 'Utilisateur'
        verbose_name_plural = 'Utilisateurs'
        indexes = [
            models.Index(fields=['tenant_id']),
            models.Index(fields=['email']),
            models.Index(fields=['is_active']),
        ]
        # Contrainte d'unicité : un email par tenant
        constraints = [
            models.UniqueConstraint(
                fields=['email', 'tenant_id'],
                name='unique_email_per_tenant'
            )
        ]
    
    def __str__(self):
        return f"{self.email} ({self.tenant_id})"
    
    @property
    def full_name(self):
        """Retourne le nom complet de l'utilisateur"""
        return f"{self.first_name} {self.last_name}".strip()
    
    @property
    def display_name(self):
        """Retourne le nom d'affichage préféré"""
        if self.full_name:
            return self.full_name
        elif self.username:
            return self.username
        return self.email.split('@')[0]
    
    def get_tenant_info(self):
        """Récupérer les informations du tenant depuis le service tenant"""
        try:
            response = requests.get(
                f"{settings.TENANT_SERVICE_URL}/api/tenants/{self.tenant_id}/",
                timeout=5
            )
            if response.status_code == 200:
                return response.json()
        except requests.RequestException:
            pass
        return None
    
    def is_tenant_admin(self):
        """Vérifier si l'utilisateur est admin de son tenant"""
        # Logique à implémenter selon vos besoins
        # Par exemple, vérifier un champ role ou permissions spécifiques
        return self.is_staff
    
    def save(self, *args, **kwargs):
        """Override save pour validation supplémentaire"""
        if not self.username:
            self.username = self.email.split('@')[0]
        
        super().save(*args, **kwargs)


class UserProfile(models.Model):
    """
    Profil étendu de l'utilisateur (optionnel)
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField('Biographie', blank=True)
    website = models.URLField('Site web', blank=True)
    company_role = models.CharField('Rôle dans l\'entreprise', max_length=100, blank=True)
    department = models.CharField('Département', max_length=100, blank=True)
    
    # Préférences
    email_notifications = models.BooleanField('Notifications email', default=True)
    sms_notifications = models.BooleanField('Notifications SMS', default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_profiles'
        verbose_name = 'Profil utilisateur'
        verbose_name_plural = 'Profils utilisateurs'
    
    def __str__(self):
        return f"Profil de {self.user.email}"


class UserSession(models.Model):
    """
    Modèle pour traquer les sessions actives (optionnel, pour sécurité avancée)
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    session_key = models.CharField(max_length=40, unique=True)
    ip_address = models.GenericIPAddressField('Adresse IP')
    user_agent = models.TextField('User Agent')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_sessions'
        verbose_name = 'Session utilisateur'
        verbose_name_plural = 'Sessions utilisateurs'
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['session_key']),
        ]
    
    def __str__(self):
        return f"Session de {self.user.email} - {self.ip_address}"
