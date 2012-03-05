# -*- Encoding: utf-8 -*-

import hashlib
import time
import urllib

from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.utils import simplejson as json
from django.utils.encoding import smart_str

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required

from models import Profile

# Copyright 2010 RenRen
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""A barebones Django application that uses RenRen for login.

This application uses OAuth 2.0 directly rather than relying on
renren's JavaScript SDK for login. It also accesses the RenRen API
directly using the Python SDK. It is designed to illustrate how easy
it is to use the renren Platform without any third party code.

Before runing the demo, you have to register a RenRen Application and
modify the root domain.  e.g. If you specify the redirect_uri as
"http://www.example.com/example_uri". The root domain must be
"example.com"
"""

RENREN_AUTHORIZATION_URI = "http://graph.renren.com/oauth/authorize"
RENREN_ACCESS_TOKEN_URI = "http://graph.renren.com/oauth/token"
RENREN_SESSION_KEY_URI = "http://graph.renren.com/renren_api/session_key"
RENREN_API_SERVER = "http://api.renren.com/restserver.do"


def home(request):
    return render_to_response("home.html", {'user': request.user})


def renren_login(request):
    args = dict(client_id=settings.RENREN_APP_API_KEY,
                redirect_uri=request.build_absolute_uri(request.path))

    error = request.GET.get("error", None)
    verification_code = request.GET.get("code", None)

    if error:
        args["error"] = error
        args["error_description"] = request.GET.get("error_description", None)
        args["error_uri"] = request.GET.get("error_uri", None)
        args = dict(error=args)
        return render_to_response('error.html', args)
    elif verification_code:
        scope = request.GET.get("scope", None)
        scope_array = str(scope).split("[\\s,+]")
        response_state = request.GET.get("state", None)
        args["client_secret"] = settings.RENREN_APP_SECRET_KEY
        args["code"] = verification_code
        args["grant_type"] = "authorization_code"
        response = urllib.urlopen(RENREN_ACCESS_TOKEN_URI + "?" + urllib.urlencode(args)).read()
        access_token = json.loads(response)["access_token"]

        # Obtain session key
        session_key_request_args = {"oauth_token": access_token}
        response = urllib.urlopen(RENREN_SESSION_KEY_URI + "?" + urllib.urlencode(session_key_request_args)).read()
        session_key = str(json.loads(response)["renren_token"]["session_key"])

        # Obtain the user's base info
        params = {"method": "users.getInfo", "fields": "name,tinyurl"}
        api_client = RenRenAPIClient(session_key, settings.RENREN_APP_API_KEY, settings.RENREN_APP_SECRET_KEY)
        response = api_client.request(params)

        if type(response) is list:
            response = response[0]

        uid = response["uid"]
        name = response["name"]
        avatar = response["tinyurl"]

        user, user_created = User.objects.get_or_create(username=uid)

        if user_created:
            user.email = '%s@renren.com' % uid

        user.set_password(access_token)
        user.save()

        profile, profile_created = Profile.objects.get_or_create(user=user, name=name, avatar=avatar)
        profile.access_token = access_token
        profile.save()

        # Authenticate the user and log them in using Django's pre-built
        # functions for these things.
        user = authenticate(username=uid, password=access_token)
        login(request, user)
        return HttpResponseRedirect('/')
    else:
        args["response_type"] = "code"
        args["scope"] = "publish_feed email status_update"
        args["state"] = "1 23 abc&?|."
        return HttpResponseRedirect(RENREN_AUTHORIZATION_URI + "?" + urllib.urlencode(args))


@login_required
def renren_logout(request):
    logout(request)
    return HttpResponseRedirect('/')


@login_required
def new_status(request):
    # Obtain session key
    session_key_request_args = {"oauth_token": request.user.get_profile().access_token}
    response = urllib.urlopen(RENREN_SESSION_KEY_URI + "?" + urllib.urlencode(session_key_request_args)).read()
    session_key = str(json.loads(response)["renren_token"]["session_key"])

    # Post a status
    params = {"method": "status.set", "status": smart_str(u"OAuth 2.0 脚本发布测试.")}
    api_client = RenRenAPIClient(session_key, settings.RENREN_APP_API_KEY, settings.RENREN_APP_SECRET_KEY)
    response = api_client.request(params)

    return HttpResponse(response)


class RenRenAPIClient(object):
    def __init__(self, session_key=None, api_key=None, secret_key=None):
        self.session_key = session_key
        self.api_key = api_key
        self.secret_key = secret_key

    def request(self, params=None):
        """Request Renren API server with the given params.
        """
        params["api_key"] = self.api_key
        params["call_id"] = str(int(time.time() * 1000))
        params["format"] = "json"
        params["session_key"] = self.session_key
        params["v"] = '1.0'
        sig = self.hash_params(params)
        params["sig"] = sig

        post_data = None if params is None else urllib.urlencode(params)

        fileobj = urllib.urlopen(RENREN_API_SERVER, post_data)

        try:
            s = fileobj.read()
            response = json.loads(s)
        finally:
            fileobj.close()
        if type(response) is not list and response["error_code"]:
            raise RenRenAPIError(response["error_code"], response["error_msg"])
        return response

    def hash_params(self, params=None):
        hasher = hashlib.md5("".join(["%s=%s" % (self._to_utf8(x), self._to_utf8(params[x])) for x in sorted(params.keys())]))
        hasher.update(self.secret_key)
        return hasher.hexdigest()

    def _to_utf8(self, s):
        """Detect if a string is unicode and encode as utf-8 if necessary."""
        return isinstance(s, unicode) and s.encode('utf-8') or str(s)


class RenRenAPIError(Exception):
    def __init__(self, code, message):
        Exception.__init__(self, message)
        self.code = code
