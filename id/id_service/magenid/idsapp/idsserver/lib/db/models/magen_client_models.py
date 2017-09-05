from mongoengine import *
import datetime

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"


class MagenClient(Document):
    mc_id = StringField(max_length=200, required=True, unique=True)
    user = StringField(max_length=200)
    device_id = StringField(max_length=200)
    ip = StringField(max_length=200)
    mac = StringField(max_length=200)
    revision = StringField(max_length=200)


class MagenUser(Document):
    uuid = StringField(max_length=200, required=True, unique=True)
    username = StringField(max_length=200, required=True, unique=True)
    first_name = StringField(max_length=50)
    last_name = StringField(max_length=50)
    password = StringField(max_length=200)
    email = StringField(max_length=50)
    email_verified = BooleanField()
    last_login = DateTimeField(default=datetime.datetime.now)
    registered_on = DateTimeField(default=datetime.datetime.now)
    role = StringField(max_length=10)
    idp = StringField(max_length=50)
    department = StringField(max_length=200)
    photo = StringField(max_length=550)
    local = StringField(max_length=50)

    position = StringField(max_length=200)
    u_groups = ListField(StringField(max_length=200))
    u_clients= ListField(StringField(max_length=200))
    display_name = StringField(max_length=200)

    @classmethod
    def is_authenticated(self):
        return True

    @classmethod
    def is_active(self):
        return True

    @classmethod
    def is_anonymous(self):
        return False

    @classmethod
    def get_id(self):
        return self.username

class MagenGroup(Document):
    ug_name = StringField(max_length=200, required=True, unique=True)
    ug_id = IntField()