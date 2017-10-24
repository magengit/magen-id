# coding=utf-8
"""Test Suit for Magen User API"""

import datetime
import uuid

from id.id_service.magenid.idsapp.idsserver.lib.db.id_service_db import IdDatabase


class MagenUserApi(object):
    """
    Magen User API

    Magen User represents a person who is registered with Magen
    or with trusted Identity Provider
    """

    def __init__(self):
        self.id_db = IdDatabase.get_iddb_instance()
        self.magen_user_strategy = self.id_db.magen_user_strategy

    def insert_user(self, user_data: dict):
        """
        Insert User data into Database

        :param user_data: information about the user
        :type user_data: dict

        :return: response object
        :rtype: MongoReturn object
        """
        now_timestamp = datetime.datetime.now().timestamp()
        utc_now_timestamp = datetime.datetime.utcfromtimestamp(now_timestamp).timestamp()
        user_data['registered_on'] = utc_now_timestamp
        user_data['u_groups'] = user_data['u_groups'] if 'u_groups' in user_data else list()
        # User registration happens before clients registration
        user_data['u_clients'] = list()
        user_data['email_verified'] = True
        if 'user_uuid' not in user_data:
            user_data['user_uuid'] = str(uuid.uuid4())
        mongo_result = self.magen_user_strategy.insert(user_data)
        if not mongo_result.success:
            mongo_result.message = 'Magen User ID (user_uuid) and Username (username) must be unique!' \
                if mongo_result.code == 11000 \
                else mongo_result.message
        return mongo_result

    def delete_user(self, user_uuid: str):
        """
        Delete User from Database

        :param user_uuid: user uuid (unique id)
        :type user_uuid: str

        :return: response object
        :rtype: MongoReturn object
        """
        seed = dict(user_uuid=user_uuid)
        return self.magen_user_strategy.delete(seed)

    def update_user(self, user_uuid: str, new_data: dict, action='set'):
        """
        Update User in Database

        :param user_uuid: Magen user unique id
        :type user_uuid: str
        :param new_data: data for update
        :type new_data: dict
        :param action: Update Opertation for udpate
        :type action: str

        :return: response object
        :rtype: MongoReturn object
        """
        seed = dict(user_uuid=user_uuid)
        action = '$' + action  # MongoDb specifics
        update_dict = {
            action: new_data
        }
        return self.magen_user_strategy.update(seed, update_dict)

    def get_all(self):
        """
        Select all Magen users from Database

        :return: response object
        :rtype: MongoReturn object
        """
        return self.magen_user_strategy.select_all()

    def get_user(self, user_uuid: str):
        """
        Select Magen User by user id

        :param user_uuid: unique user id
        :type user_uuid: str

        :return: response object
        :rtype: MongoReturn object
        """
        seed = dict(user_uuid=user_uuid)
        return self.magen_user_strategy.find_one_filter(seed)

    def get_user_by_name(self, username: str):
        """
        Select Magen User by username

        :param username: username
        :type username: str

        :return: response object
        :rtype: MongoReturn object
        """
        seed = dict(username=username)
        return self.magen_user_strategy.find_one_filter(seed)
