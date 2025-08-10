"""
SOA-compliant utilities for auth-service
Communication via API Gateway uniquement - SOA 100%
"""
import asyncio
import logging
from typing import Optional, Dict, Any
from django.conf import settings

logger = logging.getLogger(__name__)


def get_service_client():
    """Factory pour créer un ServiceClient configuré pour auth-service"""
    # Pour l'instant, utiliser requests directement
    # TODO: Implémenter ServiceClient quand l'infrastructure sera stable
    import requests
    return requests


async def validate_tenant_exists_soa(tenant_id: str, auth_token: Optional[str] = None) -> bool:
    """
    Valide qu'un tenant existe et est actif - VERSION SOA 100%
    Communication via API Gateway uniquement
    
    Args:
        tenant_id: UUID du tenant à valider
        auth_token: Token JWT optionnel pour l'authentification
        
    Returns:
        bool: True si le tenant existe et est actif, False sinon
    """
    try:
        client = get_service_client()
        
        # Communication via API Gateway
        response = await client.get(
            f"/api/tenants/{tenant_id}/validate/",
            tenant_id=tenant_id,
            auth_token=auth_token
        )
        
        if response.status_code == 200:
            data = response.json()
            logger.info(f"✅ Tenant {tenant_id} validé via API Gateway")
            return data.get('is_valid', False) and data.get('is_active', False)
            
        logger.warning(f"⚠️  Tenant {tenant_id} invalide (status: {response.status_code})")
        return False
        
    except Exception as e:
        logger.error(f"❌ Erreur lors de la validation SOA du tenant {tenant_id}: {e}")
        # En mode dégradé, on peut toujours autoriser (à évaluer selon le contexte)
        return False


async def get_tenant_info_soa(tenant_id: str, auth_token: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Récupère les informations complètes d'un tenant - VERSION SOA 100%
    Communication via API Gateway uniquement
    
    Args:
        tenant_id: UUID du tenant
        auth_token: Token JWT pour l'authentification
        
    Returns:
        dict: Informations du tenant ou None si erreur
    """
    try:
        client = get_service_client()
        
        # Communication via API Gateway
        response = await client.get(
            f"/api/tenants/{tenant_id}/",
            tenant_id=tenant_id,
            auth_token=auth_token
        )
        
        if response.status_code == 200:
            tenant_data = response.json()
            logger.info(f"✅ Informations tenant {tenant_id} récupérées via API Gateway")
            return {
                'id': tenant_data.get('id'),
                'name': tenant_data.get('name'),
                'email': tenant_data.get('email'),
                'phone': tenant_data.get('phone'),
                'website': tenant_data.get('website'),
                'subscription_plan': tenant_data.get('subscription_plan'),
                'is_active': tenant_data.get('is_active'),
                'is_trial': tenant_data.get('is_trial'),
                'created_at': tenant_data.get('created_at')
            }
        else:
            logger.warning(f"⚠️  Tenant {tenant_id} non trouvé via API Gateway (status: {response.status_code})")
            return None
            
    except Exception as e:
        logger.error(f"❌ Erreur lors de la récupération SOA du tenant {tenant_id}: {e}")
        return None


async def create_tenant_soa(company_name: str, auth_token: Optional[str] = None) -> Optional[str]:
    """
    Créer un nouveau tenant - VERSION SOA 100%
    Communication via API Gateway uniquement
    
    Args:
        company_name: Nom de l'entreprise
        auth_token: Token JWT pour l'authentification
        
    Returns:
        str: ID du tenant créé ou None si erreur
    """
    try:
        client = get_service_client()
        
        # Communication via API Gateway
        response = await client.post(
            "/api/tenants/",
            json={
                "name": company_name,
                "is_active": True
            },
            auth_token=auth_token
        )
        
        if response.status_code == 201:
            tenant_data = response.json()
            tenant_id = tenant_data.get('id')
            logger.info(f"✅ Nouveau tenant créé via API Gateway: {tenant_id}")
            return tenant_id
        else:
            logger.error(f"❌ Erreur création tenant via API Gateway (status: {response.status_code}): {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"❌ Erreur lors de la création SOA du tenant '{company_name}': {e}")
        return None


def run_async_in_sync(async_func, *args, **kwargs):
    """
    Utilitaire pour exécuter une fonction async dans un contexte synchrone Django
    Nécessaire pour la migration progressive des fonctions sync vers async
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(async_func(*args, **kwargs))


# ===== Fonctions de transition (Sync → Async) =====
# Ces fonctions permettent une migration progressive

def validate_tenant_exists_sync(tenant_id: str, auth_token: Optional[str] = None) -> bool:
    """Version synchrone transitoire pour validate_tenant_exists_soa"""
    return run_async_in_sync(validate_tenant_exists_soa, tenant_id, auth_token)


def get_tenant_info_sync(tenant_id: str, auth_token: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Version synchrone transitoire pour get_tenant_info_soa"""
    return run_async_in_sync(get_tenant_info_soa, tenant_id, auth_token)


def create_tenant_sync(company_name: str, auth_token: Optional[str] = None) -> Optional[str]:
    """Version synchrone transitoire pour create_tenant_soa"""
    return run_async_in_sync(create_tenant_soa, company_name, auth_token)