from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

class CustomUser(AbstractUser):
    full_name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15, unique=True)
    is_active_now = models.BooleanField(default=False,null=True, blank=True)
    last_active = models.DateTimeField(null=True, blank=True)

    