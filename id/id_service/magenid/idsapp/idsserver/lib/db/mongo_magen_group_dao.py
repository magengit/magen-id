# coding=utf-8
"""Magen User Group Mongo Dao"""

from magen_mongo_apis.concrete_dao import Dao

from .id_service_db import IdDatabase


class MongoMagenUserGroup(Dao):
    """
    Mongo Magen User Group Dao inherits from Concrete Dao

    PK: ug_name - magen group name (required, unique)
    ug_id       - magen group id (integer)
    """
    uuid_field_name = 'ug_name'

    def get_collection(self):
        """Get Magen User Group mongo collection"""
        mongo_id_db = IdDatabase.get_iddb_instance()
        return mongo_id_db.magen_user_group
