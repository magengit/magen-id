# coding=utf-8
"""Test Base to establish connection with testing DB"""

import unittest
import mongoengine
import mongoengine.connection as mongo_connection

from magen_utils_apis import domain_resolver
from id.id_service.magenid.idsapp.idsserver.lib.db.id_service_db import IdDatabase, MongoId
from id.id_service.magenid.idsapp.idsserver.lib.db.mongo_magen_client_dao import MongoMagenClient
from id.id_service.magenid.idsapp.idsserver.lib.db.mongo_magen_group_dao import MongoMagenUserGroup
from id.id_service.magenid.idsapp.idsserver.lib.db.mongo_magen_user_dao import MongoMagenUser

DB_NAME = 'test_id_db'


class TestBaseMongoengine(unittest.TestCase):
    """Test Base class for mongo connection using mongoengine lib"""
    test_db = None

    @classmethod
    def setUpClass(cls):
        mongo_ip, mongo_port = domain_resolver.mongo_host_port()
        # FIXME:
        # Other tests are failing, because mongoengine is not disconnected from  default databased
        # which is not test database, but operational. Needs fixing
        # register_connection as default is a hack to avoid test failure
        mongo_connection.register_connection('default', DB_NAME, host=mongo_ip, port=mongo_port)
        cls.test_db = mongoengine.connect(db=DB_NAME, host=mongo_ip, port=mongo_port)

    @classmethod
    def tearDownClass(cls):
        cls.test_db.drop_database(DB_NAME)
        mongo_connection.disconnect(DB_NAME)


class TestBasePyMongo(unittest.TestCase):
    """Test Base class for mongo connection using PyMongo lib"""
    mongo_client = None
    magen_client_collection = None
    magen_user_group_collection = None
    magen_user_collection = None

    @classmethod
    def setUpClass(cls):
        mongo_ip, mongo_port = domain_resolver.mongo_host_port()
        db = IdDatabase()
        db.id_service_db = MongoId.get_instance()
        db.id_service_db.magen_client_strategy = MongoMagenClient.get_instance()
        db.id_service_db.magen_user_group_strategy = MongoMagenUserGroup.get_instance()
        db.id_service_db.magen_user_strategy = MongoMagenUser.get_instance()
        cls.mongo_client = db.id_service_db.initialize(host=mongo_ip, port=mongo_port, db_name=DB_NAME)
        cls.magen_client_collection = db.id_service_db.magen_client_strategy.get_collection()
        cls.magen_user_group_collection = db.id_service_db.magen_user_group_strategy.get_collection()
        cls.magen_user_collection = db.id_service_db.magen_user_strategy.get_collection()

    @classmethod
    def tearDownClass(cls):
        cls.mongo_client.drop_database(DB_NAME)
