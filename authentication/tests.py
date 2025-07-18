from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth import get_user_model
from unittest.mock import patch, Mock
import uuid

User = get_user_model()


class UserModelTestCase(TestCase):
    """Tests pour le modèle User"""
    
    def setUp(self):
        self.tenant_id = uuid.uuid4()
    
    @patch('authentication.models.UserManager._validate_tenant')
    def test_create_user(self, mock_validate):
        """Test de création d'un utilisateur"""
        mock_validate.return_value = True
        
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            tenant_id=self.tenant_id,
            first_name='Test',
            last_name='User'
        )
        
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.tenant_id, self.tenant_id)
        self.assertTrue(user.check_password('testpass123'))
        self.assertFalse(user.is_staff)
        self.assertTrue(user.is_active)
    
    def test_user_str_representation(self):
        """Test de la représentation string de l'utilisateur"""
        user = User(email='test@example.com', tenant_id=self.tenant_id)
        self.assertEqual(str(user), f'test@example.com ({self.tenant_id})')
    
    def test_full_name_property(self):
        """Test de la propriété full_name"""
        user = User(first_name='John', last_name='Doe')
        self.assertEqual(user.full_name, 'John Doe')


class AuthenticationAPITestCase(APITestCase):
    """Tests pour les APIs d'authentification"""
    
    def setUp(self):
        self.tenant_id = uuid.uuid4()
        self.registration_url = reverse('authentication:register')
        self.login_url = reverse('authentication:login')
    
    @patch('authentication.serializers.UserRegistrationSerializer._create_new_tenant')
    def test_user_registration(self, mock_create_tenant):
        """Test d'inscription d'un utilisateur"""
        mock_create_tenant.return_value = self.tenant_id
        
        data = {
            'email': 'newuser@example.com',
            'password': 'strongpassword123',
            'password_confirm': 'strongpassword123',
            'first_name': 'New',
            'last_name': 'User',
            'tenant_name': 'New Company'
        }
        
        response = self.client.post(self.registration_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('tokens', response.data)
        self.assertIn('user', response.data)
    
    @patch('authentication.models.UserManager._validate_tenant')
    def test_user_login(self, mock_validate):
        """Test de connexion d'un utilisateur"""
        mock_validate.return_value = True
        
        # Créer un utilisateur de test
        user = User.objects.create_user(
            email='testuser@example.com',
            password='testpass123',
            tenant_id=self.tenant_id
        )
        
        data = {
            'email': 'testuser@example.com',
            'password': 'testpass123'
        }
        
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
    
    def test_invalid_login(self):
        """Test de connexion avec des identifiants invalides"""
        data = {
            'email': 'invalid@example.com',
            'password': 'wrongpass'
        }
        
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class UserProfileAPITestCase(APITestCase):
    """Tests pour l'API de profil utilisateur"""
    
    def setUp(self):
        self.tenant_id = uuid.uuid4()
        
        with patch('authentication.models.UserManager._validate_tenant', return_value=True):
            self.user = User.objects.create_user(
                email='testuser@example.com',
                password='testpass123',
                tenant_id=self.tenant_id,
                first_name='Test',
                last_name='User'
            )
        
        self.profile_url = reverse('authentication:user_profile')
    
    def test_get_user_profile(self):
        """Test de récupération du profil utilisateur"""
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.profile_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.user.email)
        self.assertEqual(response.data['tenant_id'], str(self.user.tenant_id))
    
    def test_update_user_profile(self):
        """Test de mise à jour du profil utilisateur"""
        self.client.force_authenticate(user=self.user)
        
        data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'phone': '+33123456789'
        }
        
        response = self.client.patch(self.profile_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.phone, '+33123456789')
    
    def test_unauthenticated_access(self):
        """Test d'accès non authentifié au profil"""
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
