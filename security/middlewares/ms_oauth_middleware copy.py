import requests
import jwt
import json
from jose import jwk, jwt as jose_jwt
from jose.utils import base64url_decode
from django.conf import settings
from django.http import JsonResponse, HttpResponseRedirect
from django.contrib.auth import get_user_model

User = get_user_model()

class MicrosoftOAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.token_url = settings.MICROSOFT_AUTH["TOKEN_URL"]
        self.client_id = settings.MICROSOFT_AUTH["CLIENT_ID"]
        self.client_secret = settings.MICROSOFT_AUTH["CLIENT_SECRET"]
        self.redirect_uri = settings.MICROSOFT_AUTH["REDIRECT_URI"]
        self.jwks_uri = settings.MICROSOFT_AUTH["JWKS_URI"]
        self.issuer = settings.MICROSOFT_AUTH["ISSUER"]

    def __call__(self, request):
        if request.path == "/api/auth/callback" and request.method == "GET":
            code = request.GET.get("code")
            if not code:
                return JsonResponse({"error": "Missing code"}, status=400)

            token_data = self.exchange_code_for_token(code)
            if "id_token" not in token_data:
                return JsonResponse({"error": "No ID token"}, status=401)

            claims = self.validate_token(token_data["id_token"])
            if not claims:
                return JsonResponse({"error": "Invalid token"}, status=403)

            # Create or update user
            user, _ = User.objects.get_or_create(email=claims["preferred_username"], defaults={"username": claims["name"]})

            # Issue JWT to frontend
            frontend_jwt = jwt.encode(
                {"user_id": user.id, "email": user.email},
                settings.SECRET_KEY,
                algorithm="HS256"
            )

            # Redirect with JWT as a query param or set cookie
            redirect_uri = f"{settings.MICROSOFT_AUTH['FRONTEND_REDIRECT_URI']}?token={frontend_jwt}"
            return HttpResponseRedirect(redirect_uri)

        return self.get_response(request)

    def exchange_code_for_token(self, code):
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        response = requests.post(self.token_url, data=data)
        return response.json()

    def validate_token(self, id_token):
        jwks = requests.get(self.jwks_uri).json()
        headers = jwt.get_unverified_header(id_token)

        key = next((k for k in jwks["keys"] if k["kid"] == headers["kid"]), None)
        if not key:
            return None

        public_key = jwk.construct(key)
        message, encoded_signature = id_token.rsplit(".", 1)
        decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))

        if not public_key.verify(message.encode("utf-8"), decoded_signature):
            return None

        claims = jose_jwt.get_unverified_claims(id_token)
        if claims.get("iss") != self.issuer or claims.get("aud") != self.client_id:
            return None

        return claims
