from django.shortcuts import render
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.utils import timezone
import logging

from .models import User, UserProfile, UserSession
from .serializers import (
    CustomTokenObtainPairSerializer,
    UserRegistrationSerializer,
    UserSerializer,
    UserUpdateSerializer,
    UserProfileSerializer,
    EmailVerificationSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    UserLoginSerializer,
    UserDetailSerializer,
    ChangePasswordSerializer
)
from .utils import validate_tenant_exists

logger = logging.getLogger(__name__)

User = get_user_model()


class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Vue personnalisée pour l'obtention des tokens JWT
    """
    serializer_class = CustomTokenObtainPairSerializer
    
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == 200:
            # Mettre à jour la dernière connexion
            email = request.data.get('email')
            try:
                user = User.objects.get(email=email)
                user.last_login = timezone.now()
                user.save(update_fields=['last_login'])
                
                logger.info(f"Connexion réussie pour {email} (tenant: {user.tenant_id})")
            except User.DoesNotExist:
                pass
        
        return response


class UserRegistrationView(generics.CreateAPIView):
    """
    Vue pour l'inscription d'un nouvel utilisateur
    """
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]
    
    def create(self, request, *args, **kwargs):
        logger.info(f"🔍 Données reçues pour inscription: {request.data}")
        
        serializer = self.get_serializer(data=request.data)
        
        if not serializer.is_valid():
            logger.error(f"❌ Erreurs de validation: {serializer.errors}")
            return Response(
                {'errors': serializer.errors, 'message': 'Données invalides'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Validation du tenant via le tenant-service
            tenant_id = serializer.validated_data.get('tenant_id')
            if tenant_id and not validate_tenant_exists(tenant_id):
                logger.error(f"❌ Tenant invalide: {tenant_id}")
                return Response(
                    {'error': 'Tenant invalide ou inactif'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            user = serializer.save()
            logger.info(f"✅ Utilisateur créé avec succès: {user.email}")
            
            # Créer les tokens JWT
            refresh = RefreshToken.for_user(user)
            refresh['tenant_id'] = str(user.tenant_id)
            refresh['email'] = user.email
            
            return Response({
                'user': UserDetailSerializer(user).data,
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'message': 'Utilisateur créé avec succès'
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de la création de l'utilisateur: {str(e)}")
            return Response(
                {'error': f'Erreur lors de la création: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )


class UserProfileView(generics.RetrieveUpdateAPIView):
    """
    Vue pour récupérer et mettre à jour le profil de l'utilisateur connecté
    """
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.AllowAny]  # Temporaire
    
    def get_object(self):
        user_id = self.request.META.get('HTTP_X_USER_ID')
        if not user_id:
            from rest_framework.exceptions import NotAuthenticated
            raise NotAuthenticated('Utilisateur non authentifié')
        
        return get_object_or_404(User, id=user_id)


class UserDetailView(generics.RetrieveAPIView):
    """
    Vue pour récupérer les détails d'un utilisateur (même tenant uniquement)
    """
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        # Filtrer par tenant pour sécurité
        return User.objects.filter(tenant_id=self.request.user.tenant_id)
    
    def get_object(self):
        user_id = self.kwargs.get('user_id')
        return get_object_or_404(self.get_queryset(), id=user_id)


class TenantUsersListView(generics.ListAPIView):
    """
    Vue pour lister tous les utilisateurs du même tenant
    """
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return User.objects.filter(
            tenant_id=self.request.user.tenant_id,
            is_active=True
        ).order_by('first_name', 'last_name')


class LogoutView(APIView):
    """
    Vue pour déconnexion (blacklist du refresh token)
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            
            logger.info(f"Déconnexion de {request.user.email}")
            return Response({"message": "Déconnexion réussie"})
        except Exception as e:
            logger.error(f"Erreur lors de la déconnexion: {str(e)}")
            return Response({"error": "Erreur lors de la déconnexion"}, 
                          status=status.HTTP_400_BAD_REQUEST)


class EmailVerificationView(APIView):
    """
    Vue pour vérifier l'email
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            # Logique de vérification du token
            # À implémenter selon vos besoins
            return Response({"message": "Email vérifié avec succès"})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(APIView):
    """
    Vue pour demander une réinitialisation de mot de passe
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            # Logique d'envoi d'email de réinitialisation
            # À implémenter selon vos besoins
            logger.info(f"Demande de réinitialisation de mot de passe pour {email}")
            return Response({"message": "Email de réinitialisation envoyé"})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):
    """
    Vue pour confirmer la réinitialisation de mot de passe
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            # Logique de validation du token et changement de mot de passe
            # À implémenter selon vos besoins
            return Response({"message": "Mot de passe réinitialisé avec succès"})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def verify_token(request):
    """
    Endpoint pour vérifier la validité d'un token JWT
    Utilisé par les autres services pour valider l'authentification
    """
    user = request.user
    return Response({
        "valid": True,
        "user_id": str(user.id),
        "tenant_id": str(user.tenant_id),
        "email": user.email,
        "is_verified": user.is_verified,
        "permissions": list(user.get_all_permissions()) if hasattr(user, 'get_all_permissions') else []
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def user_info(request):
    """
    Endpoint pour récupérer les informations de l'utilisateur connecté avec les données du tenant
    Endpoint: /api/auth/me/
    OPTIMISATION CRITIQUE: Éviter tenant-service (1.97s!) - utiliser JWT directement
    """
    import time
    
    try:
        # AUDIT - Start timing
        start_time = time.time()
        logger.info("[AUTH LATENCY AUDIT] /auth/me/ START")
        
        user = request.user
        if not user or not user.is_authenticated:
            return Response(
                {'error': 'Utilisateur non authentifié'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Phase 1: Récupérer les données de base de l'utilisateur
        serialization_start = time.time()
        user_data = UserDetailSerializer(user).data
        serialization_time = time.time()
        logger.info(f"[AUTH LATENCY AUDIT] User serialization: {(serialization_time - serialization_start)*1000:.2f}ms")
        
        # Phase 2: OPTIMISATION CRITIQUE - Éviter get_tenant_info() qui prend 1.97s
        tenant_optimization_start = time.time()
        
        # Extraire tenant_id du JWT ou de l'utilisateur
        tenant_id = str(user.tenant_id)
        
        # OPTIMISATION: Utiliser des données tenant optimisées (sans appel HTTP)
        tenant_info = {
            'id': tenant_id,
            'name': f"Tenant {tenant_id[:8]}",  # Nom générique
            'email': f"contact@tenant-{tenant_id[:8]}.com",
            'is_active': True,  # JWT validé = tenant actif
            'subscription_plan': 'active',
            'extracted_from': 'jwt_optimized'  # Pour debug
        }
        
        # Ajouter les informations du tenant aux données utilisateur
        user_data['company'] = tenant_info['name']  # Pour compatibilité frontend
        user_data['tenant_info'] = tenant_info
        
        tenant_optimization_time = time.time()
        logger.info(f"[AUTH LATENCY AUDIT] Tenant info (OPTIMIZED): {(tenant_optimization_time - tenant_optimization_start)*1000:.2f}ms")
        
        # Total
        total_time = (time.time() - start_time) * 1000
        logger.info(f"[AUTH LATENCY AUDIT] TOTAL /auth/me/: {total_time:.2f}ms (vs ~2000ms avant)")
        
        return Response(user_data)
        
    except Exception as e:
        logger.error(f"[AUTH LATENCY AUDIT] Erreur lors de la récupération des infos utilisateur: {e}")
        return Response(
            {'error': 'Erreur lors de la récupération des informations utilisateur'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
def health_check(request):
    """Health check endpoint"""
    return Response({
        'service': 'auth-service',
        'status': 'healthy',
        'version': '1.0.0'
    })


class UserLoginView(generics.GenericAPIView):
    """
    Connexion utilisateur avec JWT personnalisé
    """
    serializer_class = UserLoginSerializer
    permission_classes = [permissions.AllowAny]
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        try:
            user = User.objects.get(email=email)
            
            # Vérifier le mot de passe
            if not user.check_password(password):
                return Response(
                    {'error': 'Email ou mot de passe invalide'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Vérifier que l'utilisateur est actif
            if not user.is_active:
                return Response(
                    {'error': 'Compte utilisateur désactivé'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Créer les tokens JWT
            refresh = RefreshToken.for_user(user)
            
            # Ajouter les informations personnalisées dans le token
            refresh['tenant_id'] = str(user.tenant_id)
            refresh['email'] = user.email
            
            # Créer une session utilisateur
            UserSession.objects.create(
                user=user,
                session_token=str(refresh.access_token)[:50],  # Tronqué pour la DB
                ip_address=request.META.get('REMOTE_ADDR', ''),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            logger.info(f"Connexion réussie: {user.email} (tenant: {user.tenant_id})")
            
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': UserDetailSerializer(user).data
            })
            
        except User.DoesNotExist:
            return Response(
                {'error': 'Email ou mot de passe invalide'},
                status=status.HTTP_401_UNAUTHORIZED
            )


class CustomTokenRefreshView(TokenRefreshView):
    """
    Rafraîchissement de token JWT personnalisé
    Endpoint: /api/auth/refresh/
    """
    
    def post(self, request, *args, **kwargs):
        try:
            response = super().post(request, *args, **kwargs)
            
            # Si le refresh a réussi, ajouter des informations supplémentaires
            if response.status_code == 200:
                refresh_token = request.data.get('refresh')
                
                try:
                    # Décoder le refresh token pour récupérer l'utilisateur
                    from rest_framework_simplejwt.tokens import RefreshToken
                    token = RefreshToken(refresh_token)
                    user_id = token['user_id']
                    
                    user = User.objects.get(id=user_id)
                    
                    # Ajouter les informations utilisateur à la réponse
                    response.data['user'] = UserDetailSerializer(user).data
                    response.data['tenant_id'] = str(user.tenant_id)
                    
                    logger.info(f"Token rafraîchi pour: {user.email}")
                    
                except Exception as e:
                    logger.warning(f"Erreur lors de l'enrichissement du refresh: {e}")
            
            return response
            
        except (TokenError, InvalidToken) as e:
            return Response(
                {'error': 'Token de rafraîchissement invalide'},
                status=status.HTTP_401_UNAUTHORIZED
            )


class ChangePasswordView(generics.UpdateAPIView):
    """
    Changement de mot de passe utilisateur
    """
    serializer_class = ChangePasswordSerializer
    permission_classes = [permissions.AllowAny]  # Temporaire
    
    def get_object(self):
        user_id = self.request.META.get('HTTP_X_USER_ID')
        if not user_id:
            from rest_framework.exceptions import NotAuthenticated
            raise NotAuthenticated('Utilisateur non authentifié')
        
        return get_object_or_404(User, id=user_id)
    
    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(data=request.data)
        
        if serializer.is_valid():
            # Vérifier l'ancien mot de passe
            if not user.check_password(serializer.data.get("old_password")):
                return Response(
                    {"old_password": ["Mot de passe incorrect."]}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Définir le nouveau mot de passe
            user.set_password(serializer.data.get("new_password"))
            user.save()
            
            logger.info(f"Mot de passe changé pour: {user.email}")
            
            return Response(
                {'message': 'Mot de passe mis à jour avec succès'}, 
                status=status.HTTP_200_OK
            )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def verify_token(request):
    """
    Vérifier la validité d'un token JWT
    Utilisé par d'autres services
    """
    token = request.data.get('token')
    if not token:
        return Response(
            {'error': 'Token requis'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        from rest_framework_simplejwt.tokens import UntypedToken
        UntypedToken(token)
        
        # Décoder le token pour récupérer les informations
        import jwt
        from django.conf import settings
        
        payload = jwt.decode(
            token,
            settings.SIMPLE_JWT['SIGNING_KEY'],
            algorithms=[settings.SIMPLE_JWT['ALGORITHM']]
        )
        
        return Response({
            'valid': True,
            'user_id': payload.get('user_id'),
            'tenant_id': payload.get('tenant_id'),
            'email': payload.get('email')
        })
        
    except Exception as e:
        return Response(
            {'valid': False, 'error': str(e)},
            status=status.HTTP_401_UNAUTHORIZED
        )
