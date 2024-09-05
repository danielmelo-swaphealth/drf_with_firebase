from django.db import models
import uuid


class User(models.Model):
    id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)
    email = models.EmailField(max_length=254, unique=True, verbose_name='email address')
    password = models.CharField(max_length=128)
    firebase_uid = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"Email: {self.email} | Firebase_uid: {self.firebase_uid}"