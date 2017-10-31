# coding=utf-8
"""Magen User API for Database Manipulations"""

from magen_mongo_apis.concrete_dao import Dao

from .id_service_db import IdDatabase


class MongoMagenUser(Dao):
    """
    Mongo Magen User Dao inherits from Concrete Dao

    PK: uuid        - user id (unique, required)
    username        - user name
    first_name      - user's first name
    last_name       - user's last name
    password        - user's secret
    email           - user's email
    email_verified  - boolean flag (default True)
    last_login      - time of last login  -- FIXME: make sure this is used
    registered_on   - date of registration
    role            - user's role
    idp             - user's identity provider
    photo           - link to user's photo
    position        - user's position
    u_groups        - user's groups (list)
    u_clients       - clients registered under current user
    display_name    - user's nickname
    """
    uuid_field_name = 'user_uuid'

    def get_collection(self):
        """Get Magen User mongo collection"""
        mongo_id_db = IdDatabase.get_iddb_instance()
        return mongo_id_db.magen_user
