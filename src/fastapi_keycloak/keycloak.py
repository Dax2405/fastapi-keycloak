from functools import wraps
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer
from .config import settings
import logging
from keycloak import KeycloakOpenID

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

keycloak_openid = KeycloakOpenID(
    server_url=settings.KEYCLOAK_SERVER_URL,
    realm_name=settings.KEYCLOAK_REALM,
    client_id=settings.KEYCLOAK_CLIENT_ID,
    client_secret_key=settings.KEYCLOAK_CLIENT_SECRET,
    verify=True
)

config_well_known = keycloak_openid.well_known()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        decoded_token = keycloak_openid.decode_token(token, validate=True)
        username = decoded_token['preferred_username']
        logger.info(f"Decoded token: {decoded_token}")

        issuer = decoded_token["iss"]
        expected_issuer = f"{settings.KEYCLOAK_SERVER_URL}/realms/{settings.KEYCLOAK_REALM}"
        if issuer != expected_issuer:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid issuer")

        logger.info(f"username: {username}")
        return decoded_token

    except Exception as e:
        logger.error(f"e: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


def get_current_user(token: str = Security(oauth2_scheme)):
    payload = verify_token(token)

    user_id = payload.get("sub")
    username = payload.get("preferred_username")
    email = payload.get("email")
    roles = payload.get("realm_access", {}).get("roles", [])

    if not user_id or not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="User information not found in the token")

    user = {
        "id": user_id,
        "username": username,
        "email": email,
        "roles": roles
    }

    return user


def role_required(required_roles: list):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = kwargs.get('token')
            if token is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token not provided"
                )
            user = get_current_user(token)
            user_roles = user.get("roles", [])
            if not any(role in user_roles for role in required_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You do not have access to this resource"
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator
