import datetime
from mongoengine import *
from hashlib import md5
import logging
from id.id_service.magenid.idsapp.idsserver.lib.db.models.magen_client_models import *

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"



logger = logging.getLogger(__name__)

CLIENT_TYPE_CHOICES = [
    ('confidential', 'Confidential'),
    ('public', 'Public'),
]

RESPONSE_TYPE_CHOICES = [
    ('code', 'code (Authorization Code Flow)'),
    ('id_token', 'id_token (Implicit Flow)'),
    ('id_token token', 'id_token token (Implicit Flow)'),
]

JWT_ALGS = [
    ('HS256', 'HS256'),
    ('RS256', 'RS256'),
]


class Role(Document):
    role = StringField(required=True, unique=True)



class Domain(Document):
    name = StringField(required=True, unique=True)
    idp = StringField(max_length=50)
    allow = BooleanField()


class Client(Document):
    client_id = StringField(max_length=200, required=True, unique=True)
    client_name = StringField(max_length=20)
    client_secret = StringField(max_length=200, nullable=False)
    response_type = StringField(max_length=40)
    user = ReferenceField(MagenUser)
    redirect_uris = StringField(max_length=200)
    default_scopes = StringField(max_length=200)
    jwt_alg = StringField(max_length=10, default='RS256')
    date_created = DateTimeField(default=datetime.datetime.now)

    client_secret_expires_at = DateTimeField()
    registration_client_uri = StringField(max_length=200)

    grant_types = StringField(max_length=200)
    application_type = StringField(max_length=200)
    contacts = StringField(max_length=200)
    logo_uri = StringField(max_length=200)
    client_uri = StringField(max_length=200)
    policy_uri = StringField(max_length=200)
    tos_uri = StringField(max_length=200)
    jwks_uri = StringField(max_length=200)
    jwks = StringField(max_length=200)
    sector_identifier_uri = StringField(max_length=200)
    subject_type = StringField(max_length=200)
    id_token_signed_response_alg = StringField(max_length=10, default='RS256')
    id_token_encrypted_response_alg = StringField(max_length=10, default='RS256')
    id_token_encrypted_response_enc = StringField(max_length=10, default='RS256')
    userinfo_signed_response_alg = StringField(max_length=10, default='RS256')
    userinfo_encrypted_response_alg = StringField(max_length=10, default='RS256')
    userinfo_encrypted_response_enc = StringField(max_length=10, default='RS256')
    request_object_signing_alg = StringField(max_length=10, default='RS256')
    request_object_encryption_alg = StringField(max_length=10, default='RS256')
    request_object_encryption_enc = StringField(max_length=10, default='RS256')
    token_endpoint_auth_method = StringField(max_length=200)
    token_endpoint_auth_signing_alg = StringField(max_length=200)
    default_max_age = IntField(default=False)
    require_auth_time = BooleanField(default=False)
    default_acr_values = StringField(max_length=200)
    initiate_login_uri = StringField(max_length=200)
    request_uris = StringField(max_length=200)
    device_id = StringField(max_length=200)
    mac = StringField(max_length=200)
    ip = StringField(max_length=200)
    revision = StringField(max_length=200)
    dns_name = StringField(max_length=200)
    client_description = StringField(max_length=200)   #human-readable description
    reuse_refresh_token = BooleanField(default=False)   #do we let someone reuse a refresh token?
    dynamically_registered = BooleanField(default=False)   # was this client dynamically registered?
    allow_introspection = BooleanField(default=False)   #do we let this client call the introspection endpoint?
    id_token_validity_seconds = IntField(default=False)   #timeout for id tokens
    clear_access_tokens_on_refresh = BooleanField(default=False)   # do we clear access tokens on refresh?


    @property
    def client_type(self):
        return 'public'

#=============== token model =====================

class Code(Document):
    code = StringField(max_length=40, required=True)
    nonce = StringField(max_length=40, required=True)
    is_authentication = BooleanField(default=False)
    code_challenge = StringField(max_length=255)
    code_challenge_method = StringField(max_length=255)
    user = ReferenceField(MagenUser)
    client = ReferenceField(Client)
    expires = DateTimeField()
    scopes = StringField(max_length=255)

    def has_expired(self):
        #return datetime.datetime.now() >= self.expires_at
        return False

    class Meta:
        abstract = True


class Grant(Document):
    code = ReferenceField(Code)
    redirect_uri = StringField(max_length=255)
    user = ReferenceField(MagenUser)
    client = ReferenceField(Client)
    expires = DateTimeField()
    scopes = StringField(max_length=255)


class Token(Document):
    access_token = StringField(max_length=40, unique=True)
    refresh_token = StringField(max_length=225, unique=True)
    id_token = StringField(max_length=225, unique=True)
    encoded_token = StringField(max_length=225, unique=True)
    user = ReferenceField(MagenUser)
    client = ReferenceField(Client)
    expires = DateTimeField()
    scopes = StringField(max_length=255)
    mc_id = StringField(max_length=255)


    class Meta:
        verbose_name = u'Token'
        verbose_name_plural = u'Tokens'

class Service(Document):
         state = StringField(max_length=255, unique=True, nullable=False)
         client_id = StringField(max_length=255)
         response_type =  StringField(max_length=255)
         redirect_uri = StringField(max_length=255)
         nonce=StringField(max_length=255)
         default_scopes = StringField(max_length=255)
         code_challenge = StringField(max_length=255)
         code_challenge_method = StringField(max_length=255)
         username = StringField(max_length=255)
         external_token_info = StringField(max_length=2055)


class ExtIdp(Document):
         name = StringField(max_length=255, unique=True, nullable=False)
         desc = StringField(max_length=255)
         client_id = StringField(max_length=255)
         client_secret =  StringField(max_length=255)
         authz_url =  StringField(max_length=255)
         token_url =  StringField(max_length=255)
         token_info_url =  StringField(max_length=255)
         user_info_url =  StringField(max_length=255)
         redirect_uri = StringField(max_length=255)
         scopes = StringField(max_length=255)
         code_challenge = StringField(max_length=255)
         code_challenge_method = StringField(max_length=255)

class RSAKey(Document):

    key = StringField(verbose_name=u'Key')

    class Meta:
        verbose_name = u'RSA Key'
        verbose_name_plural = u'RSA Keys'

    def __str__(self):
        return u'{0}'.format(self.kid)

    def __unicode__(self):
        return self.__str__()

    @property
    def kid(self):
        return  u'{0}'.format(md5(self.key.encode('utf-8')).hexdigest() if self.key else '')
