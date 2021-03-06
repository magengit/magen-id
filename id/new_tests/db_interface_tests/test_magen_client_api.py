# coding=utf-8
"""Test Suit for Magen Client API"""

import typing

from ..db_test_base import TestBasePyMongo
from id.id_service.magenid.idsapp.idsserver.lib.bll.magen_client_api import MagenClientApi
from id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_api import MagenUserApi


MAGEN_CLIENT = dict(
    mc_id='test_mc_id',
    # FIXME: user to username
    user='test_username',
    # FIXME: device_id to device_type
    device_id='test_device_id',
    ip='test_ip',
    mac='test_mac',
    revision='test_revision'
)

MAGEN_USER = dict(
    # user_uuid='test_uuid',
    username='test_username',
    first_name='test_first_name',
    last_name='test_last_name',
    password='test_password',
    email='test_email',
    role='test_role',
    idp='test_idp',
    department='test_department',
    photo='test_photo',
    position='test_position',
    display_name='test_display_name'
)


class TestMagenClientAPI(TestBasePyMongo):
    """Test Suit for Magen Client API"""

    def setUp(self):
        self.mc_api = MagenClientApi()
        self.user_api = MagenUserApi()

    def tearDown(self):
        TestMagenClientAPI.magen_client_collection.remove()
        TestMagenClientAPI.magen_user_collection.remove()

    def test_insert_and_get_client(self):
        """Test Insertion and Selection of a Magen Client into Database"""

        # Select a client on an empty set
        selected = self.mc_api.get_client(MAGEN_CLIENT['mc_id'])
        self.assertFalse(selected.success)
        self.assertIsNone(selected.documents)

        # Inserting client into Database without User existing
        self.assertRaises(ValueError, self.mc_api.insert_client, MAGEN_CLIENT)

        # Insert user into Database
        inserted = self.user_api.insert_user(MAGEN_USER)
        self.assertTrue(inserted.success)

        # Insert client into Database
        inserted = self.mc_api.insert_client(MAGEN_CLIENT)
        self.assertTrue(inserted.success)

        # Verify that document was inserted
        selected = self.mc_api.get_client(MAGEN_CLIENT['mc_id'])
        self.assertTrue(selected.success)
        self.assertEqual(selected.documents, MAGEN_CLIENT)

        # Inserting same client again (mc_id must be unique)
        result = self.mc_api.insert_client(MAGEN_CLIENT)
        self.assertFalse(result.success)  # document was not inserted
        self.assertIn('mc_id', result.message)

    def test_delete_client(self):
        """Test Delete a single Client from Database"""

        # Delete a client on empty set
        result = self.mc_api.delete_client(MAGEN_CLIENT['mc_id'])
        self.assertTrue(result.success)  # idempotent request

        # Inserting client into Database without User existing
        self.assertRaises(ValueError, self.mc_api.insert_client, MAGEN_CLIENT)

        # Insert user into Database
        inserted = self.user_api.insert_user(MAGEN_USER)
        self.assertTrue(inserted.success)

        # Insert client into Database
        inserted = self.mc_api.insert_client(MAGEN_CLIENT)
        self.assertTrue(inserted.success)

        # Delete client
        result = self.mc_api.delete_client(MAGEN_CLIENT['mc_id'])
        self.assertTrue(result.success)  # idempotent request
        # Verify that client was actually deleted
        self.assertIsNone(self.mc_api.get_client(MAGEN_CLIENT['mc_id']).documents)
        # Verify that client was removed from user
        self.assertFalse(self.user_api.get_user(MAGEN_USER['user_uuid']).documents['u_clients'])

    def test_get_by_user_device_id(self):
        """Test Selection of a client by user and device type"""

        # Select on an empty set
        selected = self.mc_api.get_by_user_and_device_id(MAGEN_CLIENT['user'], MAGEN_CLIENT['device_id'])
        self.assertTrue(selected.success)
        self.assertIsInstance(selected.documents, typing.List)
        self.assertFalse(selected.documents)  # empty list returned

        # Insert user into Database
        inserted = self.user_api.insert_user(MAGEN_USER)
        self.assertTrue(inserted.success)

        # Inserting a client into Database
        result = self.mc_api.insert_client(MAGEN_CLIENT)
        self.assertTrue(result.success)

        # Selecting client from Database
        selected = self.mc_api.get_by_user_and_device_id(MAGEN_CLIENT['user'], MAGEN_CLIENT['device_id'])
        self.assertTrue(selected.success)
        self.assertEqual(selected.documents[0], MAGEN_CLIENT)

    def test_get_all(self):
        """Select all clients from Database"""

        # Select on empty set
        selected = self.mc_api.get_all()
        self.assertTrue(selected.success)
        self.assertFalse(selected.documents)

        # Insert user into Database
        inserted = self.user_api.insert_user(MAGEN_USER)
        self.assertTrue(inserted.success)

        new_user = MAGEN_USER.copy()
        new_user['username'] = 'test_another_user'
        new_user.pop('user_uuid')

        # Insert user into Database
        inserted = self.user_api.insert_user(new_user)
        self.assertTrue(inserted.success)

        # Inserting several clients
        result = self.mc_api.insert_client(MAGEN_CLIENT)
        self.assertTrue(result.success)
        another_client = MAGEN_CLIENT.copy()
        another_client.pop('mc_id')  # removing existing mc_id (should be generated automatically on insert())
        another_client['user'] = 'test_another_user'
        result = self.mc_api.insert_client(another_client)
        self.assertTrue(result.success)

        # Select all clients from Database
        selected = self.mc_api.get_all()
        self.assertTrue(selected.success)
        self.assertEqual(len(selected.documents), 2)
        self.assertEqual(selected.documents[0], MAGEN_CLIENT)
        # Verify mc_id was generated
        self.assertIn('mc_id', selected.documents[1])
        # Verify that other keys were inserted
        self.assertEqual(selected.documents[1], another_client)

    def test_update_client(self):
        """Update a client and push to Database"""

        update_dict = dict(
            user='test_another_username',
            revision='test_another_revision'
        )

        # Update non-existing document
        result = self.mc_api.update_client(update_dict, mc_id=MAGEN_CLIENT['mc_id'])
        self.assertTrue(result.success)
        self.assertEqual(result.count, 0)

        # Insert user into Database
        inserted = self.user_api.insert_user(MAGEN_USER)
        self.assertTrue(inserted.success)

        # Inserting client in Database
        result = self.mc_api.insert_client(MAGEN_CLIENT)
        self.assertTrue(result.success)

        # Update existing document
        result = self.mc_api.update_client(update_dict, mc_id=MAGEN_CLIENT['mc_id'])
        self.assertTrue(result.success)
        self.assertEqual(result.count, 1)
        # Verify that data was updated
        selected = self.mc_api.get_client(MAGEN_CLIENT['mc_id'])
        self.assertTrue(selected.success)
        self.assertEqual(selected.documents['user'], update_dict['user'])
        self.assertEqual(selected.documents['revision'], update_dict['revision'])
