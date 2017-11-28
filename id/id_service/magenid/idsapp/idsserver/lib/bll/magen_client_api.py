# coding=utf-8
"""Magen Client API for Database Manipulations"""
# import uuid
import hashlib

from id.id_service.magenid.idsapp.idsserver.lib.db.id_service_db import IdDatabase
from id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_api import MagenUserApi


class MagenClientApi(object):
    """
    Magen Client API

    Magen Client is the most important entity of Magen
    Magen Client represents an identity and policy object
    Magen Client represents a device that Magen works with
    Devices can be: mobile/desktop
    device types: ios/android/linux/pc/mac etc..

    Magen User can have multiple Magen Clients (user devices)
    """

    def __init__(self):
        self.id_db = IdDatabase.get_iddb_instance()
        self.magen_client_strategy = self.id_db.magen_client_strategy
        self.user_api = MagenUserApi()
        # self.magen_user_strategy = self.id_db.magen_user_strategy

    def _add_client_for_user(self, username, mc_id):
        """

        :param username:
        :return:
        """
        user = self.user_api.get_user_by_name(username)
        if not user.success:
            return False
        user_uuid = user.documents['user_uuid']
        user_clients = user.documents['u_clients']
        user_clients.append(mc_id)
        to_update = dict(
            u_clients=user_clients
        )
        res = self.user_api.update_user(user_uuid, to_update)
        return bool(res.success & res.count)

    def _remove_client_from_user(self, username, magen_client_id):
        """

        :param username:
        :param magen_client_id:
        :return:
        """
        user = self.user_api.get_user_by_name(username)
        if not user.success:
            return False
        user_uuid = user.documents['user_uuid']
        user_clients = user.documents['u_clients']
        if magen_client_id not in user_clients:
            # FIXME: Create own set of Exceptions
            raise ValueError('Client is not in List!')
        user_clients.remove(magen_client_id)
        to_update = dict(
            u_clients=user_clients
        )
        res = self.user_api.update_user(user_uuid, to_update)
        return bool(res.success & res.count)

    def delete_client(self, magen_client_id: str):
        """
        Delete Magen Client from Database

        :param magen_client_id: mc_id of a client
        :type magen_client_id: str

        :return: response object
        :rtype: MongoReturn object
        """
        seed = dict(mc_id=magen_client_id)
        client = self.get_client(magen_client_id)
        if not client.success:
            return self.magen_client_strategy.delete(seed=seed)
        username = client.documents['user']
        if not self._remove_client_from_user(username, magen_client_id):
            # FIXME: Create own set of Exceptions
            raise ValueError("User is not found for the Client!")
        return self.magen_client_strategy.delete(seed=seed)

    def insert_client(self, client_dict: dict):
        """
        Insert Magen Client into Database

        :param client_dict: data to be inserted, unique mc_id required
        :type client_dict: dict

        :return: response object
        :rtype: MongoReturn object
        """
        client_dict['mc_id'] = client_dict.get('mc_id', None) or generate_magen_client_id(client_dict)
        if not self._add_client_for_user(client_dict['user'], client_dict['mc_id']):
            # FIXME: Create own set of Exceptions
            raise ValueError('User is not Found for Client!')
        mongo_result = self.magen_client_strategy.insert(client_dict)
        if '_id' in client_dict:
            client_dict.pop('_id')
        if not mongo_result.success:
            mongo_result.message = 'Magen Client ID (mc_id) must be unique!' \
                if mongo_result.code == 11000 \
                else mongo_result.message
        return mongo_result

    def get_client(self, magen_client_id: str):
        """
        Select a single Client by Magen Client ID

        :param magen_client_id: mc_id of a client
        :type magen_client_id: str

        :return: response object
        :rtype: MongoReturn object
        """
        seed = dict(mc_id=magen_client_id)
        return self.magen_client_strategy.find_one_filter(seed)

    def get_by_user_and_device_id(self, username: str, device_type: str):
        """
        Select Client by user and device id

        [Note]: username and device_id fields are not unique for clients collection
        Means that there is a possibility that multiple clients could be returned
        for the same username and device type. Thus, select_by_condition() is used here,
        not find_one_filter(). These functions have different processing of the result

        :param username: username of a user the client belongs to
        :type username: str
        :param device_type: type of client's device: [ios/android/mac/pc/linux]
        :type device_type: str

        :return: response object
        :rtype: MongoReturn object
        """
        projection = dict(user=username, device_id=device_type)
        return self.magen_client_strategy.select_by_condition(projection)

    def get_all(self):
        """
        Select all Clients from Database

        :return: response object
        :rtype: MongoReturn object
        """
        return self.magen_client_strategy.select_all()

    def update_client(self, new_data: dict, mc_id: str, action='set'):
        """
        Update client in Database

        :param new_data: data to be update (includes only fields that will be updated or added to existing document)
        :type new_data: dict
        :param mc_id: magen client id
        :type mc_id: str
        :param action: Update Operator for document update
        :type action: str

        :return: response object
        :rtype: MongoReturn object
        """
        seed = dict(mc_id=mc_id)
        action = '$' + action  # MongoDb specifics
        update_dict = {
            action: new_data
        }
        return self.magen_client_strategy.update(seed, update_dict)


def generate_magen_client_id(client_data: dict):
    """
    This function generates a hash from given client data
    This hash represents mc_id
    :param client_data: all client information
    :type client_data: dict

    :return: calculated hash (sha256)
    :rtype: str
    """
    # client_uuid = uuid.uuid4().hex
    str_data = ''
    for value in client_data.values():
        str_data += value
    # str_data += client_uuid
    return hashlib.sha256(str_data.encode()).hexdigest()
