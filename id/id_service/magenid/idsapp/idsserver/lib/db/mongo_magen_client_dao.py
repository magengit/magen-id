# coding=utf-8
"""Magen Client Mongo Dao"""

from magen_mongo_apis.concrete_dao import Dao

from .id_service_db import IdDatabase


class MongoMagenClient(Dao):
    """
    Mongo Magen Client Dao inherits from Concrete Dao

    PK: mc_id   - magen client id (required, unique)
    username    - name associated with Magen User
    device_type - ios/android/pc/darwin/linux
    ip          - ip address of the device
    mac         - mac address of the device
    revision    - revision of Magen Client
    """

    def get_collection(self):
        """Get MagenClient mongo collection"""
        mongo_id_db = IdDatabase.get_iddb_instance()
        return mongo_id_db.magen_client
