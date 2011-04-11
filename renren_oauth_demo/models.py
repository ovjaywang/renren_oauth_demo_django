# File: models.py -*- Encoding: utf-8 -*-

from django.db import models
from django.contrib.auth.models import User


class Profile(models.Model):
    user = models.ForeignKey(User)
    name = models.CharField(u'Name', max_length=40)
    avatar = models.CharField(u'Avatar', max_length=200)
    access_token = models.CharField(u'Access Token', max_length=200)

    def __repr__(self):
        return self.name
