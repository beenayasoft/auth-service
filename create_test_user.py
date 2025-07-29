#!/usr/bin/env python
"""
Script pour créer un utilisateur de test
"""
import os
import sys
import django
import uuid

# Ajouter le chemin du projet
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_service.settings')

# Initialiser Django
django.setup()

from authentication.models import User

def create_test_user():
    """Créer un utilisateur de test avec un tenant UUID"""
    
    # Générer un tenant_id de test
    test_tenant_id = str(uuid.uuid4())
    
    # Données de l'utilisateur de test
    email = "test@example.com"
    password = "test123"
    
    print(f"Création de l'utilisateur de test...")
    print(f"Email: {email}")
    print(f"Password: {password}")
    print(f"Tenant ID: {test_tenant_id}")
    
    try:
        # Vérifier si l'utilisateur existe déjà
        if User.objects.filter(email=email).exists():
            print("[INFO] Un utilisateur avec cet email existe deja.")
            user = User.objects.get(email=email)
            print(f"Utilisateur existant: {user}")
            return user
        
        # Créer l'utilisateur
        user = User.objects.create_user(
            email=email,
            password=password,
            tenant_id=test_tenant_id,
            first_name="Test",
            last_name="User",
            is_active=True
        )
        
        print(f"[OK] Utilisateur cree avec succes: {user}")
        print(f"ID: {user.id}")
        print(f"Email: {user.email}")
        print(f"Tenant ID: {user.tenant_id}")
        
        return user
        
    except Exception as e:
        print(f"[ERREUR] Erreur lors de la creation: {e}")
        return None

if __name__ == "__main__":
    create_test_user()