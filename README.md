# Django Microsoft Azure AD Authentication with JWT

This project demonstrates how to integrate **Microsoft Azure Active Directory (Azure AD)** authentication with a Django backend using the **OAuth 2.0 Authorization Code Flow**. Upon successful login, a JWT token is issued to the frontend (e.g., Next.js) for use in subsequent API requests.

## 🛠️ Tech Stack

- Python + Django
- Microsoft Identity Platform (Azure AD)
- OAuth 2.0 Authorization Code Flow
- JSON Web Tokens (JWT)
- `python-jose`, `requests`, `djangorestframework`

---

## 🚀 Features

- Azure AD login via Microsoft Identity Platform
- Backend `/api/auth/callback` endpoint to process OAuth 2.0 redirect
- Verifies and decodes Microsoft-issued access tokens
- Issues custom JWT for use with Django-based API
- Stateless auth (ideal for SPAs, microservices, mobile apps)

---

## 📦 Installation

1. **Clone the repo**

```bash
git clone https://github.com/your-org/django-azure-ad-jwt.git
cd django-azure-ad-jwt
````

2. **Create and activate a virtual environment**

```bash
python -m venv venv
source venv/bin/activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

---

## ⚙️ Azure AD Setup

1. Go to [Azure Portal](https://portal.azure.com)
2. Register a new app in **Azure Active Directory > App registrations**
3. Note the following:

   * `Client ID`
   * `Tenant ID`
   * `Client Secret` (under "Certificates & Secrets")
4. Set redirect URI to:

```
http://localhost:8000/api/auth/callback
```

---

## 🔐 Django Settings

In `settings.py`, add:

```python
AZURE_AD_CLIENT_ID = "your-client-id"
AZURE_AD_CLIENT_SECRET = "your-client-secret"
AZURE_AD_TENANT_ID = "your-tenant-id"
AZURE_AD_AUTHORITY = f"https://login.microsoftonline.com/{AZURE_AD_TENANT_ID}"
AZURE_AD_REDIRECT_URI = "http://localhost:8000/api/auth/callback"
AZURE_AD_SCOPE = ["User.Read"]
AZURE_AD_JWK_SET_URL = f"https://login.microsoftonline.com/{AZURE_AD_TENANT_ID}/discovery/v2.0/keys"
SECRET_KEY = "your-django-secret"
JWT_SECRET = "your-jwt-secret"
```

---

## 🧠 Flow Summary

1. User clicks "Login with Microsoft"
2. Redirects to Microsoft login page
3. After login, Microsoft redirects to `/api/auth/callback?code=...`
4. Django exchanges code for tokens (access\_token + id\_token)
5. Verifies ID token, extracts user info
6. Issues a signed JWT token from Django
7. Frontend stores and uses JWT for future requests

---

## 🧪 Endpoint Overview

### `/api/auth/login`

Redirects the user to Microsoft for authentication.

### `/api/auth/callback`

Handles the OAuth 2.0 callback, verifies token, creates/updates user, issues JWT.

### Example Callback View:

```python
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.conf import settings
import requests
from jose import jwt
import time

@csrf_exempt
def auth_callback(request):
    code = request.GET.get("code")

    # Step 1: Exchange code for token
    token_url = f"{settings.AZURE_AD_AUTHORITY}/oauth2/v2.0/token"
    data = {
        "client_id": settings.AZURE_AD_CLIENT_ID,
        "client_secret": settings.AZURE_AD_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": settings.AZURE_AD_REDIRECT_URI,
        "scope": " ".join(settings.AZURE_AD_SCOPE),
    }
    response = requests.post(token_url, data=data)
    token_response = response.json()
    id_token = token_response.get("id_token")

    # Step 2: Decode and verify ID token
    jwks = requests.get(settings.AZURE_AD_JWK_SET_URL).json()
    claims = jwt.decode(id_token, jwks, algorithms=["RS256"], options={"verify_aud": False})

    # Step 3: Issue custom JWT
    custom_jwt = jwt.encode({
        "sub": claims["sub"],
        "email": claims["preferred_username"],
        "exp": int(time.time()) + 3600,
    }, settings.JWT_SECRET, algorithm="HS256")

    return JsonResponse({"token": custom_jwt})
```

---

## 🔄 Middleware (Optional)

To protect your API views with JWT:

```python
from django.utils.deprecation import MiddlewareMixin
from jose import jwt
from django.conf import settings
from django.http import JsonResponse

class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return

        try:
            token = auth_header.split()[1]
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
            request.user_email = payload["email"]
        except Exception:
            return JsonResponse({"error": "Invalid or expired token"}, status=401)
```

Add to `MIDDLEWARE` in `settings.py`.

---

## 📄 License

MIT License © 2025 \[Your Name / Company]

---

## 🙋‍♂️ Questions?

Open an issue or contact us at [support@stemgon.com](mailto:support@stemgon.com)

```

---

Let me know if you'd like a version that uses **cookies for storing JWTs**, adds **refresh token support**, or integrates with **Next.js frontend**.
```
