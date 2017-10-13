from mongoengine import *
import datetime
import mongoengine

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"


class MagenClient(mongoengine.Document):
    """Represents Magen Client collection in Mongo DB"""
    mc_id = mongoengine.StringField(max_length=200, required=True, unique=True)
    user = mongoengine.StringField(max_length=200)
    device_id = mongoengine.StringField(max_length=200)
    ip = mongoengine.StringField(max_length=200)
    mac = mongoengine.StringField(max_length=200)
    revision = mongoengine.StringField(max_length=200)


class MagenUser(mongoengine.Document):
    """Represents Magen User collection in Mongo DB"""
    uuid = mongoengine.StringField(max_length=200, required=True, unique=True)
    username = mongoengine.StringField(max_length=200, required=True, unique=True)
    first_name = mongoengine.StringField(max_length=50)
    last_name = mongoengine.StringField(max_length=50)
    password = mongoengine.StringField(max_length=200)
    email = mongoengine.StringField(max_length=50)
    email_verified = mongoengine.BooleanField()
    last_login = mongoengine.DateTimeField(default=datetime.datetime.now)
    registered_on = mongoengine.DateTimeField(default=datetime.datetime.now)
    role = mongoengine.StringField(max_length=10)
    idp = mongoengine.StringField(max_length=50)
    department = mongoengine.StringField(max_length=200)
    photo = mongoengine.StringField(max_length=550)
    local = mongoengine.StringField(max_length=50)

    position = mongoengine.StringField(max_length=200)
    u_groups = mongoengine.ListField(StringField(max_length=200))
    u_clients = mongoengine.ListField(StringField(max_length=200))
    display_name = mongoengine.StringField(max_length=200)

    # FIXME: no usages found
    # @classmethod
    # def is_authenticated(cls):
    #     return True
    #
    # @classmethod
    # def is_active(cls):
    #     return True
    #
    # @classmethod
    # def is_anonymous(cls):
    #     return False
    #
    # @classmethod
    # def get_id(cls):
    #     return cls.username


class MagenGroup(mongoengine.Document):
    """Represents Magen Group collection in Mongo DB"""
    ug_name = mongoengine.StringField(max_length=200, required=True, unique=True)
    ug_id = mongoengine.IntField()
