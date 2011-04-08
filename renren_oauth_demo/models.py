# File: models.py -*- Encoding: utf-8 -*-

from django.db import models


class User(models.Model):
    user_id = models.CharField(u'ID', max_length=100)
    name = models.CharField(u'Name', max_length=100)
    avatar = models.CharField(u'Avatar', max_length=200)
    access_token = models.CharField(u'Access Token', max_length=200)

    def __repr__(self):
        return self.name
