from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import requests
from django.conf import settings
from .models import User, UserProfile


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Serializer personnalisé pour l'obtention des tokens JWT avec tenant_id
    """
    def validate(self, attrs):
        data = super().validate(attrs)
        
        # Ajouter des informations sur l'utilisateur et le tenant dans le token
        refresh = self.get_token(self.user)
        refresh['tenant_id'] = str(self.user.tenant_id)
        refresh['user_id'] = str(self.user.id)
        refresh['email'] = self.user.email
        refresh['full_name'] = self.user.full_name
        
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)
        
        # Ajouter les infos utilisateur dans la réponse
        data['user'] = {
            'id': str(self.user.id),
            'email': self.user.email,
            'username': self.user.username,
            'first_name': self.user.first_name,
            'last_name': self.user.last_name,
            'tenant_id': str(self.user.tenant_id),
            'is_verified': self.user.is_verified,
            'avatar': self.user.avatar_url,
            'phone': self.user.phone,
        }
        
        return data

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        
        # Ajouter des claims personnalisés
        token['tenant_id'] = str(user.tenant_id)
        token['user_id'] = str(user.id)
        token['email'] = user.email
        token['is_verified'] = user.is_verified
        
        return token


# ✅ SERIALIZERS MANQUANTS POUR LE FRONTEND
class UserLoginSerializer(serializers.Serializer):
    """
    Serializer pour la connexion utilisateur
    """
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        required=True,
        style={'input_type': 'password'},
        write_only=True
    )
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            # La validation sera faite dans la vue
            return attrs
        else:
            raise serializers.ValidationError('Email et mot de passe requis.')


class UserDetailSerializer(serializers.ModelSerializer):
    """
    Serializer détaillé pour les informations utilisateur
    Compatible avec le frontend existant
    """
    full_name = serializers.ReadOnlyField()
    tenant_id = serializers.ReadOnlyField()
    avatar = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'username', 'first_name', 'last_name',
            'full_name', 'phone', 'avatar', 'language', 'timezone',
            'is_verified', 'date_joined', 'tenant_id'
        ]
        read_only_fields = [
            'id', 'email', 'date_joined', 'tenant_id', 'is_verified'
        ]
    
    def get_avatar(self, obj):
        return obj.avatar_url


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer pour changer le mot de passe (version avec contexte request)
    """
    old_password = serializers.CharField(
        required=True,
        style={'input_type': 'password'},
        write_only=True
    )
    new_password = serializers.CharField(
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'},
        write_only=True
    )
    
    def validate_old_password(self, value):
        """Valider l'ancien mot de passe"""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Ancien mot de passe incorrect.")
        return value
    
    def save(self):
        """Sauvegarder le nouveau mot de passe"""
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer pour changer le mot de passe
    """
    old_password = serializers.CharField(
        required=True,
        style={'input_type': 'password'},
        write_only=True
    )
    new_password = serializers.CharField(
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'},
        write_only=True
    )
    new_password_confirm = serializers.CharField(
        required=True,
        style={'input_type': 'password'},
        write_only=True
    )
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                "new_password": "Les nouveaux mots de passe ne correspondent pas."
            })
        return attrs


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer pour l'inscription d'un nouvel utilisateur
    """
    password = serializers.CharField(
        write_only=True, 
        required=True, 
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    password2 = serializers.CharField(
        write_only=True, 
        required=True,
        style={'input_type': 'password'}
    )
    company = serializers.CharField(
        write_only=True, 
        required=True,
        help_text="Nom de l'entreprise"
    )
    
    class Meta:
        model = User
        fields = [
            'email', 'username', 'first_name', 'last_name', 
            'password', 'password2', 'phone', 'company'
        ]
        extra_kwargs = {
            'email': {'required': True},
            'first_name': {'required': True},
            'last_name': {'required': True},
        }
    
    def validate(self, attrs):
        """Validation personnalisée"""
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({
                "password": "Les mots de passe ne correspondent pas."
            })
        return attrs
    
    def create(self, validated_data):
        """Créer un nouvel utilisateur avec gestion du tenant"""
        password = validated_data.pop('password')
        validated_data.pop('password2')
        company = validated_data.pop('company')
        
        final_tenant_id = self._create_new_tenant(company)
        validated_data['tenant_id'] = final_tenant_id
        
        user = User.objects.create_user(
            password=password,
            **validated_data
        )
        
        UserProfile.objects.create(user=user)
        
        return user
    
    def _create_new_tenant(self, company_name):
        """Créer un nouveau tenant avec le nom de l'entreprise"""
        try:
            response = requests.post(
                f"{settings.TENANT_SERVICE_URL}/api/tenants/",
                json={
                    "name": company_name,
                    "is_active": True
                },
                timeout=5
            )
            if response.status_code == 201:
                return response.json()['id']
            else:
                raise serializers.ValidationError({
                    "company": "Impossible de créer l'entreprise. Ce nom existe peut-être déjà."
                })
        except requests.RequestException:
            raise serializers.ValidationError({
                "company": "Impossible de créer l'entreprise. Réessayez plus tard."
            })


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer pour afficher les informations d'un utilisateur
    """
    full_name = serializers.ReadOnlyField()
    display_name = serializers.ReadOnlyField()
    tenant_info = serializers.SerializerMethodField()
    avatar = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'username', 'first_name', 'last_name',
            'full_name', 'display_name', 'phone', 'avatar',
            'language', 'timezone', 'is_verified', 'date_joined',
            'tenant_id', 'tenant_info'
        ]
        read_only_fields = [
            'id', 'email', 'date_joined', 'tenant_id', 'is_verified'
        ]
    
    def get_avatar(self, obj):
        return obj.avatar_url
    
    def get_tenant_info(self, obj):
        """Récupérer les informations du tenant"""
        try:
            response = requests.get(
                f"{settings.TENANT_SERVICE_URL}/api/tenants/{obj.tenant_id}/",
                timeout=5
            )
            if response.status_code == 200:
                return response.json()
            return None
        except requests.RequestException:
            return None


class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer pour la mise à jour des informations utilisateur
    """
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'phone', 'avatar',
            'language', 'timezone'
        ]
    
    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer pour le profil étendu de l'utilisateur
    """
    user = UserDetailSerializer(read_only=True)
    
    class Meta:
        model = UserProfile
        fields = [
            'user', 'bio', 'company_role', 'notifications_enabled',
            'theme_preference', 'created_at', 'updated_at'
        ]


class EmailVerificationSerializer(serializers.Serializer):
    """
    Serializer pour la vérification d'email
    """
    token = serializers.CharField(required=True)
    
    def validate_token(self, value):
        # Logique de validation du token de vérification
        # À implémenter selon vos besoins (JWT, token dans DB, etc.)
        return value


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer pour demander une réinitialisation de mot de passe
    """
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value):
        try:
            User.objects.get(email=value)
            return value
        except User.DoesNotExist:
            raise serializers.ValidationError("Aucun utilisateur avec cet email.")


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer pour confirmer la réinitialisation de mot de passe
    """
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    new_password_confirm = serializers.CharField(
        required=True,
        style={'input_type': 'password'}
    )
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                "new_password": "Les mots de passe ne correspondent pas."
            })
        return attrs
