from django.urls import path
from . import views

urlpatterns = [
    path('auth/login', views.auth_login, name='auth_login'),
    path('auth/logout', views.logout_view, name='auth_logout'),
    path('auth/callback', views.auth_callback, name='auth_callback'),
    path('protected', views.protected_view, name='protected_view'),
]
