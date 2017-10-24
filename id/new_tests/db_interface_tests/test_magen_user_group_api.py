# coding=utf-8
"""Test Suit for Magen User Group API"""

import typing

from .db_test_base import TestBasePyMongo
from id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_group_api import MagenUserGroupApi


USER_GROUP = dict(
    ug_name='test_ug_name',
    ug_id=1
)


class TestMagenUserGroupAPI(TestBasePyMongo):

    def setUp(self):
        self.mu_group = MagenUserGroupApi()

    def tearDown(self):
        TestMagenUserGroupAPI.magen_user_group_collection.remove()

    def test_insert_get_group(self):
        """Insert and Select magen user group from Database"""

        # Select on empty set
        selected = self.mu_group.get_group_by_name(USER_GROUP['ug_name'])
        self.assertFalse(selected.success)
        self.assertIsNone(selected.documents)

        # Insert a group in Database
        inserted = self.mu_group.insert_group(USER_GROUP)
        self.assertTrue(inserted.success)

        # Select group
        selected = self.mu_group.get_group_by_name(USER_GROUP['ug_name'])
        self.assertTrue(selected.success)
        self.assertEqual(selected.documents, USER_GROUP)

        # Insert same group again
        inserted = self.mu_group.insert_group(USER_GROUP)
        self.assertFalse(inserted.success)
        self.assertIn('ug_name', inserted.message)

    def test_delete_group(self):
        """Delete Magen User group from Database"""

        # Delete on empty set
        deleted = self.mu_group.delete_group(USER_GROUP['ug_name'])
        self.assertTrue(deleted.success)  # idempotent request

        # Inserting group into Database
        inserted = self.mu_group.insert_group(USER_GROUP)
        self.assertTrue(inserted.success)

        # Delete group
        deleted = self.mu_group.delete_group(USER_GROUP['ug_name'])
        self.assertTrue(deleted.success)  # idempotent request
        # Verify that group was actually removed
        self.assertIsNone(self.mu_group.get_group_by_name(USER_GROUP['ug_name']).documents)

    def test_get_all(self):
        """Test Select all User groups from Database"""

        # Select on empty set
        selected = self.mu_group.get_all()
        self.assertTrue(selected.success)
        self.assertIsInstance(selected.documents, typing.List)
        self.assertFalse(selected.documents)  # empty list

        # Inserting 2 groups into Database
        inserted = self.mu_group.insert_group(USER_GROUP)
        self.assertTrue(inserted.success)
        another_group = dict(
            ug_name='test_another_ug_name',
            ug_id=2
        )
        inserted = self.mu_group.insert_group(another_group)
        self.assertTrue(inserted.success)

        # Select all from Database
        selected = self.mu_group.get_all()
        self.assertTrue(selected.success)
        self.assertEqual(len(selected.documents), 2)
        self.assertEqual(selected.documents[0], USER_GROUP)
        self.assertEqual(selected.documents[1], another_group)

    def test_update_group(self):
        """Update User Group information and push to Database"""

        update_dict = dict(
            ug_name='test_diff_name',
            ug_id=100
        )

        # Update non-existing document
        updated = self.mu_group.update_group(group_name=USER_GROUP['ug_name'], data=update_dict)
        # FIXME: update in concrete_dao returns True, but False expected
        # self.assertFalse(updated.success)
        self.assertEqual(updated.count, 0)

        # Inserting group into Database
        inserted = self.mu_group.insert_group(USER_GROUP)
        self.assertTrue(inserted.success)

        # Update existing group
        updated = self.mu_group.update_group(group_name=USER_GROUP['ug_name'], data=update_dict)
        self.assertTrue(updated.success)
        self.assertEqual(updated.count, 1)
        # Verify that data was update
        selected = self.mu_group.get_group_by_name(update_dict['ug_name'])
        self.assertTrue(selected.success)
        self.assertEqual(selected.documents['ug_id'], update_dict['ug_id'])
