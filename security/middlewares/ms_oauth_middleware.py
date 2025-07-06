import logging
import requests
import jwt
from jwt import PyJWKClient

from django.conf import settings
from django.http import JsonResponse
from django.urls import resolve
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin

from security.models import User

logger = logging.getLogger(__name__)

# Settings: Microsoft Identity Config
MS_TENANT_ID = settings.MICROSOFT_TENANT_ID  # e.g., 'common', 'yourtenant.onmicrosoft.com', or tenant GUID
MS_CLIENT_ID = settings.MICROSOFT_CLIENT_ID
OPENID_CONFIG_URL = f"https://login.microsoftonline.com/{MS_TENANT_ID}/v2.0/.well-known/openid-configuration"

class MicrosoftJWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Resolve paths to allow bypass (login, static, etc.)
        try:
            resolver_match = resolve(request.path)
            if resolver_match.url_name in ["login", "callback", "logout"]:
                return
        except Exception as e:
            logger.warning(f"Failed to resolve path: {e}")
            return

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JsonResponse({"detail": "Authorization header missing or invalid."}, status=401)

        token = auth_header.split(" ")[1]

        try:
            # Fetch OpenID configuration
            oidc_config = requests.get(OPENID_CONFIG_URL).json()
            issuer = oidc_config["issuer"]
            jwks_uri = oidc_config["jwks_uri"]

            # Get JWKS
            jwks = requests.get(jwks_uri).json()

            rsa_key = self.get_rsa_key(jwks, token)
            if not rsa_key:
                return JsonResponse({"detail": "Unable to find signing key."}, status=401)

            # Decode and validate the token
            unverified = jwt.decode(token, options={"verify_signature": False})
            audience = unverified.get("aud")

            decoded_token = jwt.decode(
                token,
                rsa_key,
                algorithms=["RS256"],
                audience=audience,
                issuer=issuer,
            )
        except jwt.ExpiredSignatureError:
            return JsonResponse({"detail": "Token expired."}, status=401)
        except jwt.InvalidTokenError as e:
            logger.warning(f"JWT validation failed: {str(e)}")
            return JsonResponse({"detail": "Invalid token."}, status=401)
        except Exception as e:
            logger.error(f"Error validating Microsoft token: {str(e)}")
            return JsonResponse({"detail": "Authentication error."}, status=503)

        email = decoded_token.get("preferred_username") or decoded_token.get("email")
        name = decoded_token.get("name", "")

        if not email:
            return JsonResponse({"detail": "Email not found in token."}, status=403)

        user = self.get_or_create_user(email, name)
        request.user = user

    def get_rsa_key(self, jwks_url, token):
      
        try:
            jwk_client = PyJWKClient(jwks_url)
            signing_key = jwk_client.get_signing_key_from_jwt(token)
            return signing_key.key
        except Exception as e:
            logger.error(f"Failed to get signing key: {e}")
            return None

    def get_or_create_user(self, email, full_name):
        parts = full_name.strip().split(" ", 1)
        first_name = parts[0]
        last_name = parts[1] if len(parts) > 1 else ""

        user, created = User.objects.get_or_create(
            email=email,
            defaults={"first_name": first_name, "last_name": last_name},
        )

        if email in settings.ADMIN_EMAILS:
            user.is_staff = True
            user.is_superuser = True
        else:
            user.is_staff = False
            user.is_superuser = False

        user.last_login = timezone.now()
        user.save()
        return user
