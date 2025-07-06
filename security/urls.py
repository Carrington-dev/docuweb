# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path("auth/login", views.microsoft_login, name="microsoft_login"),
    path("auth/callback", views.microsoft_callback, name="microsoft_callback"),
    path("auth/logout", views.microsoft_logout, name="microsoft_logout"),
]
