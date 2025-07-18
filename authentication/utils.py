import requests
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


def validate_tenant_exists(tenant_id):
    """
    Valide qu'un tenant existe et est actif
    
    Args:
        tenant_id: UUID du tenant à valider
        
    Returns:
        bool: True si le tenant existe et est actif, False sinon
    """
    try:
        response = requests.get(
            f"{settings.TENANT_SERVICE_URL}/api/tenants/{tenant_id}/",
            timeout=5
        )
        if response.status_code == 200:
            tenant_data = response.json()
            return tenant_data.get('is_active', False)
        return False
    except requests.RequestException as e:
        logger.error(f"Erreur lors de la validation du tenant {tenant_id}: {e}")
        return False


def get_tenant_info(tenant_id):
    """
    Récupère les informations complètes d'un tenant depuis le tenant-service
    
    Args:
        tenant_id: UUID du tenant
        
    Returns:
        dict: Informations du tenant ou None si erreur
    """
    try:
        response = requests.get(
            f"{settings.TENANT_SERVICE_URL}/api/tenants/{tenant_id}/",
            timeout=5
        )
        if response.status_code == 200:
            tenant_data = response.json()
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
            logger.warning(f"Tenant {tenant_id} non trouvé (status: {response.status_code})")
            return None
    except requests.RequestException as e:
        logger.error(f"Erreur lors de la récupération du tenant {tenant_id}: {e}")
        return None


def get_client_ip(request):
    """
    Récupère l'adresse IP du client
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def determine_device_name(user_agent):
    """
    Détermine le nom de l'appareil à partir du user-agent
    """
    user_agent = user_agent.lower()
    device_name = "Inconnu"
    
    # Détection simple du type d'appareil
    if "iphone" in user_agent:
        device_name = "iPhone"
    elif "ipad" in user_agent:
        device_name = "iPad"
    elif "android" in user_agent:
        device_name = "Android"
    elif "windows" in user_agent:
        device_name = "Windows"
    elif "mac" in user_agent:
        device_name = "Mac"
    elif "linux" in user_agent:
        device_name = "Linux"
    
    return device_name
