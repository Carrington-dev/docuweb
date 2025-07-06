from msal import ConfidentialClientApplication
from django.conf import settings
from django.shortcuts import redirect
from django.http import JsonResponse
from django.contrib.auth import get_user_model, login, logout
from msal import ConfidentialClientApplication
from jose import jwt
import time
import logging
from urllib.parse import urlencode
from django.shortcuts import redirect
from django.contrib.auth import logout
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

def auth_login(request):
    msal_app = ConfidentialClientApplication(
        client_id=settings.AZURE_AD_CLIENT_ID,
        client_credential=settings.AZURE_AD_CLIENT_SECRET,
        authority=settings.AZURE_AD_AUTHORITY,
    )
    auth_url = msal_app.get_authorization_request_url(
        scopes=settings.AZURE_AD_SCOPE,
        redirect_uri=settings.AZURE_AD_REDIRECT_URI,
    )
    return redirect(auth_url)



def auth_callback(request):
    code = request.GET.get("code")
    logger.info(f"Logging out Missing code: {code}")

    if not code:
        return JsonResponse({"error": "Missing code"}, status=400)
    #     return JsonResponse({
    #         "error": "Missing code",
    #         "query_params": request.GET.dict()
    #     }, status=400)


    msal_app = ConfidentialClientApplication(
        client_id=settings.AZURE_AD_CLIENT_ID,
        client_credential=settings.AZURE_AD_CLIENT_SECRET,
        authority=settings.AZURE_AD_AUTHORITY,
    )

    result = msal_app.acquire_token_by_authorization_code(
        code,
        scopes=settings.AZURE_AD_SCOPE,
        redirect_uri=settings.AZURE_AD_REDIRECT_URI,
    )

    if "id_token_claims" not in result:
        return JsonResponse({"error": "Token acquisition failed", "details": result}, status=400)

    claims = result["id_token_claims"]
    email = claims.get("preferred_username") or claims.get("email")

    # Optionally create or update user in your DB
    User = get_user_model()
    user, created = User.objects.get_or_create(
        email=claims["email"],
        defaults={
            "first_name": claims.get("given_name", ""),
            "last_name": claims.get("family_name", ""),
        },
    )
    user.backend = "django.contrib.auth.backends.ModelBackend"
    email = user.email
    if email in settings.ADMIN_EMAILS:
        user.is_staff = True
        user.is_superuser = True
    else:
        user.is_staff = False
        user.is_superuser = False

    user.save()
    # Check why verification screen isn't popping up

    login(request, user)

    next = request.session.get("next", None)
    if next:
        return redirect(request.build_absolute_uri(next))
    # ...

    jwt_token = jwt.encode({
        "sub": claims["oid"],
        "email": email,
        "name": claims.get("name"),
        "exp": int(time.time()) + 3600,
    }, settings.JWT_SECRET, algorithm="HS256")

    return JsonResponse({"token": jwt_token})


@csrf_exempt
def protected_view(request):
    if not hasattr(request, "user_email"):
        return JsonResponse({"error": "Unauthorized"}, status=401)
    return JsonResponse({"message": f"Hello, {request.user_email}!"})



@csrf_exempt
def logout_view(request):
    # Optionally get the Microsoft ID token
    id_token = request.session.pop("id_token", None)

    # Construct logout parameters
    logout_params = {
        "post_logout_redirect_uri": settings.POST_LOGOUT_REDIRECT_URI,
    }
    if id_token:
        logout_params["id_token_hint"] = id_token  # Optional for Microsoft

    logout_url = (
        f"https://login.microsoftonline.com/{settings.AZURE_AD_TENANT_ID}/oauth2/v2.0/logout?"
        f"{urlencode(logout_params)}"
    )

    logger.info(f"Logging out user and redirecting to Microsoft logout: {logout_url}")

    # Clear Django session after logout redirect is created
    logout(request)

    return redirect(logout_url)