# FIXME: import statements
import base64
import logging
import time
import uuid
import datetime

import time
import uuid
import os
import re
import json
import hashlib
import netifaces as nif

from Crypto.PublicKey.RSA import importKey
from werkzeug.security import check_password_hash, gen_salt

from urllib.parse import urlparse

from Crypto.PublicKey.RSA import importKey
import jwt

import traceback


from flask import request, Response

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"

# TODO: get_*_dict functions could be a fabric - need to aggregate the process of creating a dictionary

# FIXME: all parameters must contain a type definition, where possible
# FIXME: arguments must be compressed as kwargs where possible

logger = logging.getLogger(__name__)

settings = {
    'site_url': 'http://localhost:8088',
    'expires_in': 3600
}


# FIXME: function name
def get_user_dic(username, email, user_uuid=None, first_name=None, last_name=None, password=None, department=None,
                 u_clients=[], u_groups=[], idp="magen", position=None, role="standard", display_name=None,
                 email_verified=True, photo=None, local=None):
    dic = {}
    if user_uuid is None:
        dic['uuid'] = str(uuid.uuid4())
    else:
        dic['uuid'] = user_uuid
    dic["username"] = username
    dic["password"] = password
    dic["first_name"] = first_name
    dic["last_name"] = last_name
    dic["u_clients"] = u_clients
    dic["department"] = department
    dic["u_groups"] = u_groups
    dic["position"] = position
    dic["display_name"] = display_name
    dic["role"] = role
    dic["idp"] = idp
    dic["email"] = email
    dic["email_verified"] = email_verified
    dic["photo"] = photo
    dic["local"] = local
    return dic


# FIXME: user var name is vauge. Must be renamed into username
# FIXME: What is device_id? in payload it's value might be 'mac', 'iphone', 'ipad'..
# Why is it _id_ then? Should it be name? type? if type then these options make more sence:
# PC/linux/mac/android/ios
# FIXME: function name is not concrete. it should be generate_magen_client_dict() or build_magen_client_dict()
def get_magen_client_dic(user, device_id, mc_id=None, ip=None, mac=None, revision=None):
    # FIXME: id is a built-in name
    if mc_id is None:
        id = get_magen_client_id(user, device_id)
    else:
        id = mc_id
    dic = {
        "mc_id": id,
        "user": user,
        "device_id": device_id,
        "ip": ip,
        "mac": mac,
        "revision": revision
    }
    return dic


# FIXME: id is a built-in name
# FIXME: function name
def get_magen_group_dic(groupname, id):
    dic = {
        "ug_name": groupname,
        "ug_id": id
    }
    return dic


# FIXME: function name
# FIXME: the choice for jwt algorithms should be limited
def get_oauth_client_dic(client_name, redirect_uris=None, default_scopes=[], jwt_alg="RS256", client_id=None, client_secret=None, response_type="code"):
    client_dic={}

    client_dic["client_name"] = client_name
    client_dic["response_type"] = response_type
    client_dic["redirect_uris"] = redirect_uris
    client_dic["default_scopes"] = default_scopes
    client_dic["jwt_alg"] = jwt_alg
    client_dic["client_id"] = client_id
    client_dic["client_secret"] = client_secret
    return client_dic


# FIXME: remove these functions. Better to use urlparse directly
# FIXME: name is wrong. url is not encoded
def get_the_encoded_url(str):
    o = urlparse(str)
    return o.geturl()


def get_schema_from_url(str):
    o = urlparse(str)
    return o.scheme


def get_port_from_url(str):
    o = urlparse(str)
    return o.port


# FIXME: found 1 usage in unused method (loging_handler() from  oidc_provider.py)
def get_org_url(str):
    str = str.replace('&', '|||')
    # str=str.replace('')
    return str


# FIXME: no usages found
def get_org_url2(str):
    str = str.replace('|||', '&')
    # str=str.replace('')
    return str


# FIXME: No Usages
def load_properties(self, filepath, key, sep='=', comment_char='#'):
    """
    Read the file passed as parameter as a properties file.
    """
    # print filepath
    filepath = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'local-idp-server/' + filepath)
    props = {}
    with open(filepath, "rt") as f:
        for line in f:
            l = line.strip()
            if l and not l.startswith(comment_char):
                key_value = l.split(sep)
                props[key_value[0].strip()] = key_value[1].strip('" \t')
    # print props
    return props


# FIXME: typo in name
def get_hakersafe_uri(request):
    uri = request.base_url
    if request.query_string:
        uri += '?' + request.query_string.decode('utf-8')
    return uri

# FIXME: this function is never used. it depends on a current flask request
# FIXME: it gets called in oidc_provider byt result is never used
# FIXME: it should have request as a parameter
# FIXME: rename
# FIXME: it could be moved to oidc_provider as this function is very context specific
def get_params():
    uri = get_hakersafe_uri(request)
    http_method = request.method
    headers = dict(request.headers)
    if 'wsgi.input' in headers:
        del headers['wsgi.input']
    if 'wsgi.errors' in headers:
        del headers['wsgi.errors']
    body = request.form.to_dict()
    return uri, http_method, body, headers


# FIXME: no usages found
def create_response(headers, body, status):
    """Create response class for Flask."""
    response = Response(body or '')
    for k, v in headers.items():
        response.headers[str(k)] = v

    response.status_code = status
    return response


# FIXME: 1 usage found in oidc provider in authorize_handler() method
# FIXME: this should not be a function at all - very confusing name and useless
def create_code():
    code = uuid.uuid4().hex
    return code


# FIXME: no usages found
def randomstr(string_length=40):
    random = str(uuid.uuid4())
    random = random.upper()
    random = random.replace("-", "")
    return random[0:string_length]


# FIXME: rename
def get_expire_time(t=100):
    exp = datetime.datetime.now() + datetime.timedelta(seconds=t)
    return exp

# FIXME: this function is useless
def get_now_time():
    now = datetime.datetime.now
    return now

# FIXME: this function is useless
def get_rand_token(s=40):
    return gen_salt(s)

# FIXME: this function is useless
def reverse_string(string):
    return string[::-1]


def printErrorLog():
    print('>>>>>>>>>>>> traceback <<<<<<<<<<<<<')
    traceback.print_exc()
    print('>>>>>>>>>>>> end of traceback <<<<<<')


def create_id_token(user, aud, nonce, expire, issuer, request=None):
    sub = user.username

    # TODO: Convert datetimes into timestamps.
    # FIXME: Use UTC time
    now = datetime.datetime.utcnow()
    logger.debug(round(now.timestamp()))
    # FIXME: conversion to seconds could be performed in another function
    iat_time = int(now.timestamp())
    exp_time = int((now + datetime.timedelta(seconds=expire)).timestamp())
    user_auth_time = user.last_login
    auth_time = int(user_auth_time.timestamp())

    # print('iat_time=====' + str(iat_time))
    # print('exp_time=====' + str(exp_time))
    # print('auth_time=====' + str(auth_time))

    dic = {
        'iss': issuer,
        'sub': sub,
        'aud': str(aud),
        'exp': exp_time,
        'iat': iat_time,
        'auth_time': auth_time,
    }
    logger.debug('###################### create_id_token 16 ########################')
    if nonce:  # FIXME: nonce is a required parameter
        dic['nonce'] = str(nonce)

    return dic



# FIXME: No usages found
def encode_id_token(payload, client):
    secret = client.client_secret
    alg = client.jwt_alg
    logger.debug('=======  alg ======== %s', alg)
    encoded_token = jwt.encode(payload, secret, algorithm=alg)
    decoded_payload = jwt.decode(encoded_token, secret, algorithm=alg, options={'verify_aud': False})
    return encoded_token


# FIXME: no usages found
def extract_access_token(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers.get('Authorization', '')
        if re.compile('^Bearer\s{1}.+$').match(auth_header):
            access_token = auth_header.split()[1]
    else:
        access_token = request.GET.get('access_token', '')

    return access_token


# FIXME: re-name
# FIXME: it's not a json response. it returns flask.wrappers.Response type
def get_json_response(ret):
    resp = Response(response=ret,
                    status=200,
                    mimetype="application/json")
    resp.cache_control.max_age = 300
    return resp


# FIXME: two functions below must become 1
# FIXME: user param must be renamed to username (user name is implying to be an user object)
def get_magen_client_id(user, device_id):
    data = user + device_id
    # FIXME: utf-8 is a default parameter (may be skipped)
    s = data.encode('utf-8')
    magen_client_id = hashlib.sha256(s).hexdigest()
    return magen_client_id


# FIXME: no usage
def get_guid(data):
    s = data.encode('utf-8')
    guid = hashlib.sha256(s).hexdigest()
    return guid


def mac_for_ip(ip):
    'Returns a list of MACs for interfaces that have given IP, returns None if not found'
    for i in nif.interfaces():
        addrs = nif.ifaddresses(i)
        try:
            if_mac = addrs[nif.AF_LINK][0]['addr']
            if_ip = addrs[nif.AF_INET][0]['addr']
        except:
            if_mac = if_ip = None
        if if_ip == ip:
            return if_mac
    return None





#THIS ARE TESTING

# FIXME: test code must be in tests/
def createClientUuid():
    list_client = []
    list_client.append(str(uuid.uuid4()))
    list_client.append(str(uuid.uuid4()))
    list_client.append(str(uuid.uuid4()))
    return list_client

# FIXME: test code must be in tests/
def createGroupList():
    list_g = []
    list_g.append(1)
    list_g.append(2)
    return list_g

# FIXME: test code must be in tests/
def createUserDictionary(username):
    dic=get_user_dic(username, username, str(uuid.uuid4()), 'Mizanul', 'Chowdhury', 'P@55w0rd13', "development",
                 createClientUuid(), createGroupList(), "magen", "cto", "admin", "Mizanul Chowdhury",True)
    return dic

# FIXME: WTF????? REMOVE
def createGroupDictionary(groupname,id):
    dic = get_magen_group_dic(groupname,id)
    return dic

def createClientDict(user,device_id,mc_id=None):
    if mc_id is None:
        id=get_magen_client_id(user, device_id)
    else:
        id=mc_id
    dic=get_magen_client_dic(user, device_id)
    return dic
