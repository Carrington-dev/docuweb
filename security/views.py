import logging
import os
import uuid
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.shortcuts import redirect
from oauthlib.oauth2 import WebApplicationClient

logger = logging.getLogger(__name__)

if settings.IS_LOCAL:
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

def microsoft_login(request):
    client = WebApplicationClient(settings.MICROSOFT_CLIENT_ID)

    state = str(uuid.uuid4())
    request.session["oauth_state"] = state
    request.session["next"] = request.GET.get("next", "")

    auth_url = client.prepare_request_uri(
        settings.MICROSOFT_AUTHORIZE_URL,
        redirect_uri=settings.MICROSOFT_REDIRECT_URI,
        scope=["openid", "profile", "email", "offline_access", "User.Read"],
        state=state,
        response_mode="query",
        prompt="select_account",
    )

    logger.info(f"Redirecting to Microsoft login: {auth_url}")
    return redirect(auth_url)

def microsoft_callback(request):
    client = WebApplicationClient(settings.MICROSOFT_CLIENT_ID)

    auth_code = request.GET.get("code")

    token_url, headers, body = client.prepare_token_request(
        settings.MICROSOFT_TOKEN_URL,
        authorization_response=request.build_absolute_uri(),
        redirect_url=settings.MICROSOFT_REDIRECT_URI,
        code=auth_code,
    )

    if isinstance(body, str):
        body = dict(param.split("=") for param in body.split("&"))
    if "client_id" in body:
        body.pop("client_id")
    body["redirect_uri"] = settings.MICROSOFT_REDIRECT_URI

    response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(settings.MICROSOFT_CLIENT_ID, settings.MICROSOFT_CLIENT_SECRET),
    )

    client.parse_request_body_response(response.text)

    request.session["id_token"] = client.token.get("id_token")

    # Fetch user info from Microsoft Graph
    userinfo_response = requests.get(
        settings.MICROSOFT_USERINFO_URL,
        headers={"Authorization": f"Bearer {client.token['access_token']}"},
    )

    user_info = userinfo_response.json()
    User = get_user_model()

    user, created = User.objects.get_or_create(
        email=user_info["email"],
        defaults={
            "first_name": user_info.get("given_name", ""),
            "last_name": user_info.get("family_name", ""),
        },
    )

    user.backend = "django.contrib.auth.backends.ModelBackend"
    if user.email in settings.ADMIN_EMAILS:
        user.is_staff = True
        user.is_superuser = True
    else:
        user.is_staff = False
        user.is_superuser = False

    user.save()
    login(request, user)

    next = request.session.get("next")
    return redirect(next or settings.LOGIN_REDIRECT_URL)

def microsoft_logout(request):
    id_token = request.session.pop("id_token", None)
    logout_params = {
        "post_logout_redirect_uri": request.build_absolute_uri(settings.LOGIN_URL),
    }
    if id_token:
        logout_params["id_token_hint"] = id_token

    logout_url = f"{settings.MICROSOFT_LOGOUT_URL}?{urlencode(logout_params)}"

    logger.info(f"Redirecting to Microsoft logout: {logout_url}")
    logout(request)
    return redirect(logout_url)


import requests
from jose import jwt as jose_jwt
from django.conf import settings
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view
from .utils.jwt import generate_jwt

User = get_user_model()

@api_view(['POST'])
def microsoft_callback(request):
    code = request.data.get('code')
    if not code:
        return JsonResponse({'error': 'Missing code'}, status=400)

    tenant_id = settings.MICROSOFT['TENANT_ID']
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    data = {
        'client_id': settings.MICROSOFT['CLIENT_ID'],
        'client_secret': settings.MICROSOFT['CLIENT_SECRET'],
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': settings.MICROSOFT['REDIRECT_URI'],
    }

    headers = { 'Content-Type': 'application/x-www-form-urlencoded' }

    token_res = requests.post(token_url, data=data, headers=headers)
    if token_res.status_code != 200:
        return JsonResponse({'error': 'Token exchange failed'}, status=400)

    tokens = token_res.json()
    id_token = tokens.get('id_token')

    claims = jose_jwt.decode(id_token, options={"verify_signature": False})
    email = claims.get('preferred_username')
    first_name = claims.get('given_name', '')
    last_name = claims.get('family_name', '')

    user, created = User.objects.get_or_create(email=email, defaults={
        'first_name': first_name,
        'last_name': last_name,
        'username': email,
    })

    jwt_token = generate_jwt(user)

    response = JsonResponse({'status': 'ok'})
    response.set_cookie(
        key='jwt',
        value=jwt_token,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite='Lax'
    )
    return response
