from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, \
    SignatureExpired, BadSignature
from passlib.apps import custom_app_context as pwd_context

import logging
import logging.config
from logging.handlers import RotatingFileHandler

from id.id_service.magenid.idsapp import ids
from id.id_service.magenid.idsapp.idsserver.lib.db.models.models import *
from id.id_service.magenid.idsapp.idsserver.lib.db.dao import *
from id.id_service.magenid.idsapp.idsserver.lib.db.magen_user_dao import *

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"

#logging.config.fileConfig('logging.conf')
logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)

class UserAuthentication():
    userdao=MagenUserDao()

    @staticmethod
    def verify_auth_token(token):
        userdao=MagenUserDao()
        s = Serializer(ids.secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    
        except BadSignature:
            return None    

        return userdao.getUserByUserName(data['username'])

    def generate_auth_token(expiration, username):
        s = Serializer(ids.secret_key, expires_in=expiration)
        return s.dumps({'username': username})

    @classmethod
    def login(cls, email, password):
        logger.debug('email=============  %s',email)
        user = cls.userdao.getUserByUserName(email)
        if user: 
           return user

        return None


   