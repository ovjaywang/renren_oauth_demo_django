# -*- Encoding: utf-8 -*-

import base64
import Cookie
import email
import hashlib
import hmac
import os
import time
import urllib
from functools import wraps

from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.utils import simplejson as json
from django.utils.encoding import smart_str

from models import User

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

RENREN_APP_API_KEY = "fee11992a4ac4caabfca7800d233f814"
RENREN_APP_SECRET_KEY = "a617e78710454b12aab68576382e8e14"


RENREN_AUTHORIZATION_URI = "http://graph.renren.com/oauth/authorize"
RENREN_ACCESS_TOKEN_URI = "http://graph.renren.com/oauth/token"
RENREN_SESSION_KEY_URI = "http://graph.renren.com/renren_api/session_key"
RENREN_API_SERVER = "http://api.renren.com/restserver.do"


def _set_cookie(response, name, value, domain=None, path="/", expires=None):
    """Generates and signs a cookie for the give name/value"""
    timestamp = str(int(time.time()))
    value = base64.b64encode(value)
    signature = _cookie_signature(value, timestamp)
    cookie = Cookie.BaseCookie()
    cookie[name] = "|".join([value, timestamp, signature])
    cookie[name]["path"] = path
    if domain:
        cookie[name]["domain"] = domain
    if expires:
        cookie[name]["expires"] = email.utils.formatdate(
            expires, localtime=False, usegmt=True)
    response['Set-Cookie'] = cookie.output()[12:]


def _parse_cookie(value):
    """Parses and verifies a cookie value from set_cookie"""
    if not value:
        return

    parts = value.split("|")
    if len(parts) != 3:
        return

    if _cookie_signature(parts[0], parts[1]) != parts[2]:
        return

    timestamp = int(parts[1])
    if timestamp < time.time() - 30 * 86400:
        return

    try:
        return base64.b64decode(parts[0]).strip()
    except:
        return


def _cookie_signature(*parts):
    """Generates a cookie signature.

    We use the renren app secret since it is different for every app (so
    people using this example don't accidentally all use the same secret).
    """
    hash = hmac.new(RENREN_APP_SECRET_KEY, digestmod=hashlib.sha1)
    for part in parts:
        hash.update(part)
    return hash.hexdigest()


def inject_current_user(f):
    @wraps(f)
    def decorated_function(request, *args, **kwargs):
        if not hasattr(request, 'current_user'):
            user_id = _parse_cookie(request.COOKIES.get("renren_user"))
            if user_id:
                try:
                    current_user = User.objects.get(user_id=user_id)
                    setattr(request, 'current_user', current_user)
                except User.DoesNotExist:
                    setattr(request, 'current_user', None)
            else:
                setattr(request, 'current_user', None)
        return f(request, *args, **kwargs)
    return decorated_function


def login_required(f):
    @wraps(f)
    def decorated_function(request, *args, **kwargs):
        if request.current_user is None:
            return HttpResponseRedirect('/')
        return f(request, *args, **kwargs)
    return decorated_function


@inject_current_user
def home(request):
    return render_to_response("home.html", {'current_user': request.current_user})


def login(request):
    args = dict(client_id=RENREN_APP_API_KEY,
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
        args["client_secret"] = RENREN_APP_SECRET_KEY
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
        api_client = RenRenAPIClient(session_key, RENREN_APP_API_KEY, RENREN_APP_SECRET_KEY)
        response = api_client.request(params)

        if type(response) is list:
            response = response[0]

        user_id = response["uid"]
        name = response["name"]
        avatar = response["tinyurl"]

        try:
            user = User.objects.get(user_id=user_id)
        except User.DoesNotExist:
            user = User()

        user.user_id = user_id
        user.name = name
        user.avatar = avatar
        user.access_token = access_token

        user.save()

        response = HttpResponseRedirect('/')
        _set_cookie(response, 'renren_user', str(user_id),
                    expires=time.time() + 30 * 86400)
        return response
    else:
        args["response_type"] = "code"
        args["scope"] = "publish_feed email status_update"
        args["state"] = "1 23 abc&?|."
        return HttpResponseRedirect(RENREN_AUTHORIZATION_URI + "?" + urllib.urlencode(args))


@inject_current_user
@login_required
def logout(request):
    response = HttpResponseRedirect('/')
    _set_cookie(response, "renren_user", "", expires=time.time() - 86400)
    return response


@inject_current_user
@login_required
def new_status(request):
    # Obtain session key
    session_key_request_args = {"oauth_token": request.current_user.access_token}
    response = urllib.urlopen(RENREN_SESSION_KEY_URI + "?" + urllib.urlencode(session_key_request_args)).read()
    session_key = str(json.loads(response)["renren_token"]["session_key"])

    # Post a status
    params = {"method": "status.set", "status": smart_str(u"OAuth 2.0 脚本发布测试.")}
    api_client = RenRenAPIClient(session_key, RENREN_APP_API_KEY, RENREN_APP_SECRET_KEY)
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
