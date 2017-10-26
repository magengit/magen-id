# coding=utf-8
"""Database Interface for ID service Database"""

import pymongo
from pymongo import MongoClient

from magen_utils_apis.singleton_meta import Singleton
from magen_datastore_apis.dao_interface import IDao
from magen_datastore_apis.utils_db import IUtils


_COLLECTIONS = dict(
    magen_client='magen_clients',
    magen_user='magen_users',
    magen_user_group='magen_u_groups',
    id_client_app='app_clients',
    id_token='id_tokens'
)


class IdDatabase(metaclass=Singleton):
    """
    Wrapper class for Database in order to avoid direct usage
    of concrete DB implementation - this allows easily change DB
    during development
    """
    __instance = None

    def __init__(self):
        super().__init__()
        self.__id_service_db = None

    @classmethod
    def get_iddb_instance(cls):
        """Get Concrete Id DB instance"""
        return cls().id_service_db

    @property
    def id_service_db(self):
        """Property for Concrete ID service Database instance"""
        return self.__id_service_db

    @id_service_db.setter
    def id_service_db(self, value):
        self.__id_service_db = value

    def initialize(self, db_name=None):
        """Initialize concrete Database instance with entities"""
        pass


class MongoId(IdDatabase):
    """Concrete Mongo ID service Database"""

    __instance = None

    def __init__(self):
        super().__init__()
        # MongoClient
        self.mongo_client = None
        # Mongo Database
        self.id_db = None
        # DB interfaces - strategies
        self.magen_client_strategy = IDao
        self.magen_user_strategy = IDao
        self.magen_user_group_strategy = IDao
        self.id_client_app_strategy = IDao
        self.id_token_strategy = IDao
        self.utils_strategy = IUtils
        # DB resources - collections
        self.magen_client = None
        self.magen_user = None
        self.magen_user_group = None
        self.id_client_app = None
        self.id_token = None

    @classmethod
    def get_instance(cls):
        """Providing Singleton"""
        if not cls.__instance:
            cls.__instance = cls()
        return cls.__instance

    def initialize(self, host='localhost', port=27017, db_name='magenid'):
        """
        Initialize MongoID instance with entities
        :param host: ip-address for mongo client, default localhost
        :type host: str
        :param port: port for mongo client, default 27017
        :type port: int
        :param db_name: name for database, default 'magenid'
        :type db_name: str
        """
        self.mongo_client = MongoClient(host, port)
        self.id_db = self.mongo_client.get_database(db_name)
        # collections
        self.magen_client = self.id_db.get_collection(_COLLECTIONS['magen_client'])
        self.magen_client.create_index('mc_id', unique=True)
        self.magen_user = self.id_db.get_collection(_COLLECTIONS['magen_user'])
        self.magen_user.create_index('user_uuid', unique=True)
        self.magen_user.create_index('username', unique=True)
        self.magen_user_group = self.id_db.get_collection(_COLLECTIONS['magen_user_group'])
        self.magen_user_group.create_index('ug_name', unique=True)
        self.id_client_app = self.id_db.get_collection(_COLLECTIONS['id_client_app'])
        self.id_token = self.id_db.get_collection(_COLLECTIONS['id_token'])
        return self.mongo_client
