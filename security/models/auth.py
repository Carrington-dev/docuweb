import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser

from security.managers import UserManager

class User(AbstractUser):
    id = models.UUIDField( 
         primary_key = True, 
         default = uuid.uuid4, 
         editable = False)
    email = models.EmailField( max_length=254, unique=True)
    first_name = models.CharField( max_length=254)
    last_name = models.CharField( max_length=254)
    username = models.CharField(max_length=254, unique=True)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)


    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = [ "username" ]

    def __str__(self):
        return f"{self.email} {self.username} @ {str(self.id)[:20]}"

    def __unicode__(self):
        return f"{self.email} {self.username} @ {str(self.id)[:20]}"
    
    class Meta:
        ordering = [ "email", "username" ]