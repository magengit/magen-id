# coding=utf-8
"""Test Suit for Magen User API"""

from .db_test_base import TestBasePyMongo
from id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_api import MagenUserApi


MAGEN_USER = dict(
    user_uuid='test_uuid',
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


class TestMagenUserAPI(TestBasePyMongo):
    """Test Suit for Magen User API"""

    def setUp(self):
        self.user_api = MagenUserApi()

    def tearDown(self):
        TestMagenUserAPI.magen_user_collection.remove()

    def test_insert_get_user(self):
        """Test Insert Magen User into Database"""

        # Select a user on an empty set
        selected = self.user_api.get_user(MAGEN_USER['user_uuid'])
        self.assertFalse(selected.success)
        self.assertIsNone(selected.documents)

        # Inserting user into Database
        inserted = self.user_api.insert_user(MAGEN_USER)
        self.assertTrue(inserted.success)

        # Verify that document was inserted
        selected = self.user_api.get_user(MAGEN_USER['user_uuid'])
        self.assertTrue(selected.success)
        self.assertEqual(selected.documents, MAGEN_USER)

        # Inserting same user again (uuid and e-mail should be unique)
        inserted = self.user_api.insert_user(MAGEN_USER)
        self.assertFalse(inserted.success)
        self.assertIn('user_uuid', inserted.message)

    def test_delete_user(self):
        """Test Delete User from Database"""

        # Delete a user on an empty set
        deleted = self.user_api.delete_user(MAGEN_USER['user_uuid'])
        self.assertTrue(deleted.success)  # idempotent request

        # Inserting user into Database
        inserted = self.user_api.insert_user(MAGEN_USER)
        self.assertTrue(inserted.success)

        # Delete user
        deleted = self.user_api.delete_user(MAGEN_USER['user_uuid'])
        self.assertTrue(deleted.success)
        # Verify that user was actually removed
        self.assertIsNone(self.user_api.get_user(MAGEN_USER['user_uuid']).documents)

    def test_get_all(self):
        """Test Select all users from Database"""

        # Select on empty set
        selected = self.user_api.get_all()
        self.assertTrue(selected.success)
        self.assertFalse(selected.documents)

        # Inserting several users
        inserted = self.user_api.insert_user(MAGEN_USER)
        self.assertTrue(inserted.success)
        another_user = MAGEN_USER.copy()
        another_user.pop('user_uuid')
        another_user['username'] = 'test_another_username'
        another_user['first_name'] = 'test_another_f_name'
        inserted = self.user_api.insert_user(another_user)
        self.assertTrue(inserted.success)

        # Select all users from Database
        selected = self.user_api.get_all()
        self.assertTrue(selected.success)
        self.assertEqual(len(selected.documents), 2)
        self.assertEqual(selected.documents[0], MAGEN_USER)
        # Verify that user_uuid was generated
        self.assertIn('user_uuid', selected.documents[1])
        # Verify that other keys were inserted
        self.assertEqual(selected.documents[1], another_user)

    def test_get_user_by_name(self):
        """Test Select user by username"""

        # Select on empty set
        selected = self.user_api.get_user_by_name(MAGEN_USER['username'])
        self.assertFalse(selected.success)
        self.assertIsNone(selected.documents)

        # Insert user
        inserted = self.user_api.insert_user(MAGEN_USER)
        self.assertTrue(inserted.success)

        # Select user by username
        selected = self.user_api.get_user_by_name(MAGEN_USER['username'])
        self.assertTrue(selected.success)
        self.assertEqual(selected.documents, MAGEN_USER)

    def test_update_user(self):
        """Test Update user data and push to Database"""

        update_dict = dict(
            username='test_another_username',
            role='test_new_role',
            department='test_new_department'
        )

        # Update non-existing user
        updated = self.user_api.update_user(MAGEN_USER['user_uuid'], update_dict)
        self.assertTrue(updated.success)
        self.assertEqual(updated.count, 0)

        # Insert user in Database
        inserted = self.user_api.insert_user(MAGEN_USER)
        self.assertTrue(inserted.success)

        # Update existing user
        updated = self.user_api.update_user(MAGEN_USER['user_uuid'], update_dict)
        self.assertTrue(updated.success)
        self.assertEqual(updated.count, 1)
        # Verify that data was updated
        selected = self.user_api.get_user(MAGEN_USER['user_uuid'])
        self.assertTrue(selected.success)
        self.assertEqual(selected.documents['username'], update_dict['username'])
        self.assertEqual(selected.documents['role'], update_dict['role'])
        self.assertEqual(selected.documents['department'], update_dict['department'])
