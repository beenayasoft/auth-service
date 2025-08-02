from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    CustomTokenObtainPairView,
    UserRegistrationView,
    UserProfileView,
    UserDetailView,
    TenantUsersListView,
    LogoutView,
    EmailVerificationView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    verify_token,
    user_info,
    UserLoginView,
    CustomTokenRefreshView,
    ChangePasswordView,
    UserInfoView,
    UserAvatarUploadView,
)

app_name = 'authentication'

urlpatterns = [
    # Authentification
    path('login/', CustomTokenObtainPairView.as_view(), name='login'),
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Gestion des utilisateurs
    path('profile/', UserProfileView.as_view(), name='user_profile'),
    path('users/<uuid:user_id>/', UserDetailView.as_view(), name='user_detail'),
    path('users/', TenantUsersListView.as_view(), name='tenant_users'),
    
    # Vérification d'email
    path('email/verify/', EmailVerificationView.as_view(), name='email_verify'),
    
    # Réinitialisation de mot de passe
    path('password/reset/request/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    
    # Endpoints pour les autres services
    path('verify-token/', verify_token, name='verify_token'),
    path('user-info/', user_info, name='user_info'),
    
    # ✅ NOUVEAUX ENDPOINTS POUR LE FRONTEND
    path('me/', UserInfoView.as_view(), name='user_info'),
    path('refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    
    # Profil utilisateur
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('avatar/', UserAvatarUploadView.as_view(), name='avatar_upload'),
]
