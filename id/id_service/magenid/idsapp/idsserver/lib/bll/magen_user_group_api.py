# coding=utf-8
"""Magen User Group API for Database Manipulations"""

from id.id_service.magenid.idsapp.idsserver.lib.db.id_service_db import IdDatabase


class MagenUserGroupApi(object):
    """
    Magen User Group API

    Magen User Group represents a user group that could be inherited from LDAP
    or organization structure.
    """

    def __init__(self):
        self.id_db = IdDatabase.get_iddb_instance()
        self.magen_user_group_strategy = self.id_db.magen_user_group_strategy

    def get_group_by_name(self, user_group_name: str):
        """
        Select a User Group from Database by given user group name (unique)

        :param user_group_name: unique magen user group name
        :type user_group_name: str

        :return: response object
        :rtype: MongoReturn object
        """
        seed = dict(ug_name=user_group_name)
        return self.magen_user_group_strategy.find_one_filter(seed)

    def delete_group(self, user_group_name: str):
        """

        :param user_group_name:
        :type user_group_name:

        :return: response object
        :rtype: MongoReturn object
        """
        seed_for_deletion = dict(ug_name=user_group_name)
        return self.magen_user_group_strategy.delete(seed=seed_for_deletion)

    def get_all(self):
        """
        Select all User Groups from Database

        :return: response object
        :rtype: MongoReturn object
        """
        return self.magen_user_group_strategy.select_all()

    def insert_group(self, group_data: dict):
        """
        Insert Group data into Database

        :param group_data: information about user group
        :type group_data: dict

        :return: response object
        :rtype: MongoReturn object
        """
        mongo_result = self.magen_user_group_strategy.insert(group_data)
        if not mongo_result.success:
            mongo_result.message = 'Magen User Group name (ug_name) must be unique!' \
                if mongo_result.code == 11000 \
                else mongo_result.message
        return mongo_result

    def update_group(self, group_name: str, data: dict, action='set'):
        """
        Update User Group information and push to Database

        :param group_name:
        :type group_name:
        :param data:
        :type data:
        :param action: Update Operation for update
        :type action: str

        :return: response object
        :rtype: MongoReturn object
        """
        seed = dict(ug_name=group_name)
        action = '$' + action  # MongoDb specifics
        update_dict = {
            action: data
        }
        return self.magen_user_group_strategy.update(seed, update_dict)

    def replace_group(self, ug_name: str, new_data: dict):
        """
        Replace Magen User Group data in Database

        :param ug_name: user group name
        :type ug_name: str
        :param new_data: replacement data
        :type new_data: dict

        :return: response object
        :rtype: MongoReturn
        """
        new_data['ug_name'] = ug_name
        seed = dict(ug_name=ug_name)
        result = self.magen_user_group_strategy.replace(seed, new_data)
        result.documents.pop('_id')
        return result
