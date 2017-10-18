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


class Role(mongoengine.Document):
    """Represents Role collection in Mongo DB"""
    role = mongoengine.StringField(required=True, unique=True)


class Domain(mongoengine.Document):
    """Represents Domain collection in Mongo DB"""
    name = mongoengine.StringField(required=True, unique=True)
    idp = mongoengine.StringField(max_length=50)
    allow = mongoengine.BooleanField()


class Client(mongoengine.Document):
    """Represents Client collection in Mongo DB"""
    client_id = mongoengine.StringField(max_length=200, required=True, unique=True)
    client_name = mongoengine.StringField(max_length=20)
    client_secret = mongoengine.StringField(max_length=200, nullable=False)
    response_type = mongoengine.StringField(max_length=40)
    # FIXME: deletion of reference is not handled properly
    # ex.: ReferenceField(User, reverse_delete_rule=CASCADE)
    user = mongoengine.ReferenceField(MagenUser)
    redirect_uris = mongoengine.StringField(max_length=200)
    default_scopes = mongoengine.StringField(max_length=200)
    jwt_alg = mongoengine.StringField(max_length=10, default='RS256')
    date_created = mongoengine.DateTimeField(default=datetime.datetime.now)

    client_secret_expires_at = mongoengine.DateTimeField()
    registration_client_uri = mongoengine.StringField(max_length=200)

    grant_types = mongoengine.StringField(max_length=200)
    application_type = mongoengine.StringField(max_length=200)
    contacts = mongoengine.StringField(max_length=200)
    logo_uri = mongoengine.StringField(max_length=200)
    client_uri = mongoengine.StringField(max_length=200)
    policy_uri = mongoengine.StringField(max_length=200)
    tos_uri = mongoengine.StringField(max_length=200)
    jwks_uri = mongoengine.StringField(max_length=200)
    jwks = mongoengine.StringField(max_length=200)
    sector_identifier_uri = mongoengine.StringField(max_length=200)
    subject_type = mongoengine.StringField(max_length=200)
    id_token_signed_response_alg = mongoengine.StringField(max_length=10, default='RS256')
    id_token_encrypted_response_alg = mongoengine.StringField(max_length=10, default='RS256')
    id_token_encrypted_response_enc = mongoengine.StringField(max_length=10, default='RS256')
    userinfo_signed_response_alg = mongoengine.StringField(max_length=10, default='RS256')
    userinfo_encrypted_response_alg = mongoengine.StringField(max_length=10, default='RS256')
    userinfo_encrypted_response_enc = mongoengine.StringField(max_length=10, default='RS256')
    request_object_signing_alg = mongoengine.StringField(max_length=10, default='RS256')
    request_object_encryption_alg = mongoengine.StringField(max_length=10, default='RS256')
    request_object_encryption_enc = mongoengine.StringField(max_length=10, default='RS256')
    token_endpoint_auth_method = mongoengine.StringField(max_length=200)
    token_endpoint_auth_signing_alg = mongoengine.StringField(max_length=200)
    default_max_age = mongoengine.IntField(default=False)
    require_auth_time = mongoengine.BooleanField(default=False)
    default_acr_values = mongoengine.StringField(max_length=200)
    initiate_login_uri = mongoengine.StringField(max_length=200)
    request_uris = mongoengine.StringField(max_length=200)
    device_id = mongoengine.StringField(max_length=200)
    mac = mongoengine.StringField(max_length=200)
    ip = mongoengine.StringField(max_length=200)
    revision = mongoengine.StringField(max_length=200)
    dns_name = mongoengine.StringField(max_length=200)
    # human-readable description
    client_description = mongoengine.StringField(max_length=200)
    # do we let someone reuse a refresh token?
    reuse_refresh_token = mongoengine.BooleanField(default=False)
    # was this client dynamically registered?
    dynamically_registered = mongoengine.BooleanField(default=False)
    # do we let this client call the introspection endpoint?
    allow_introspection = mongoengine.BooleanField(default=False)
    # timeout for id tokens
    id_token_validity_seconds = mongoengine.IntField(default=False)
    # do we clear access tokens on refresh?
    clear_access_tokens_on_refresh = mongoengine.BooleanField(default=False)

    @property
    def client_type(self):
        """Client type property. now option is only 'public'"""
        return 'public'


class Code(mongoengine.Document):
    """Represents Code collection in Mongo DB"""
    code = mongoengine.StringField(max_length=40, required=True)
    nonce = mongoengine.StringField(max_length=40, required=True)
    is_authentication = mongoengine.BooleanField(default=False)
    code_challenge = mongoengine.StringField(max_length=255)
    code_challenge_method = mongoengine.StringField(max_length=255)
    user = mongoengine.ReferenceField(MagenUser)
    client = mongoengine.ReferenceField(Client)
    expires = mongoengine.DateTimeField()
    scopes = mongoengine.StringField(max_length=255)

    def has_expired(self):
        """For now Code never expires"""
        # return datetime.datetime.now() >= self.expires_at
        return False

    class Meta:
        """Meta class for dynamic inheritance"""
        abstract = True


class Grant(mongoengine.Document):
    """Represents Grant collection in Mongo DB"""
    code = mongoengine.ReferenceField(Code)
    redirect_uri = mongoengine.StringField(max_length=255)
    user = mongoengine.ReferenceField(MagenUser)
    client = mongoengine.ReferenceField(Client)
    expires = mongoengine.DateTimeField()
    scopes = mongoengine.StringField(max_length=255)


class Token(mongoengine.Document):
    """Represents Token collection in Mongo DB"""
    access_token = mongoengine.StringField(max_length=40, unique=True)
    refresh_token = mongoengine.StringField(max_length=225, unique=True)
    id_token = mongoengine.StringField(max_length=225, unique=True)
    encoded_token = mongoengine.StringField(max_length=225, unique=True)
    user = mongoengine.ReferenceField(MagenUser)
    client = mongoengine.ReferenceField(Client)
    expires = mongoengine.DateTimeField()
    scopes = mongoengine.StringField(max_length=255)
    mc_id = mongoengine.StringField(max_length=255)

    class Meta:
        """Meta class for dynamic inheritance"""
        verbose_name = u'Token'
        verbose_name_plural = u'Tokens'


class Service(mongoengine.Document):
    """Represents Service collection in Mongo DB"""
    state = mongoengine.StringField(max_length=255, unique=True, nullable=False)
    client_id = mongoengine.StringField(max_length=255)
    response_type = mongoengine.StringField(max_length=255)
    redirect_uri = mongoengine.StringField(max_length=255)
    nonce = mongoengine.StringField(max_length=255)
    default_scopes = mongoengine.StringField(max_length=255)
    code_challenge = mongoengine.StringField(max_length=255)
    code_challenge_method = mongoengine.StringField(max_length=255)
    username = mongoengine.StringField(max_length=255)
    external_token_info = mongoengine.StringField(max_length=2055)


class ExtIdp(mongoengine.Document):
    """Represents External Idps collection in Mongo DB"""
    name = mongoengine.StringField(max_length=255, unique=True, nullable=False)
    desc = mongoengine.StringField(max_length=255)
    client_id = mongoengine.StringField(max_length=255)
    client_secret = mongoengine.StringField(max_length=255)
    authz_url = mongoengine.StringField(max_length=255)
    token_url = mongoengine.StringField(max_length=255)
    token_info_url = mongoengine.StringField(max_length=255)
    user_info_url = mongoengine.StringField(max_length=255)
    redirect_uri = mongoengine.StringField(max_length=255)
    scopes = mongoengine.StringField(max_length=255)
    code_challenge = mongoengine.StringField(max_length=255)
    code_challenge_method = mongoengine.StringField(max_length=255)


class RSAKey(mongoengine.Document):
    """"Represents External Idps collection in Mongo DB"""

    key = mongoengine.StringField(verbose_name='Key')

    # FIXME:
    # No usages found
    # class Meta:
    #     verbose_name = u'RSA Key'
    #     verbose_name_plural = u'RSA Keys'

    def __str__(self):
        return '{0}'.format(self.kid)

    def __unicode__(self):
        return self.__str__()

    @property
    def kid(self):
        """key id md5 format"""
        return '{0}'.format(md5(self.key.encode('utf-8')).hexdigest() if self.key else '')
