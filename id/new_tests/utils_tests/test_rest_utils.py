# coding=utf-8
"""Test Suit for REST utilities functions"""

import unittest

from id.id_service.magenid.idsapp.idsserver.rest import rest_utils


class TestRestUtils(unittest.TestCase):

    def test_check_payload(self):
        """Test Payload Check"""

        # Check with empty
        success, missing_keys = rest_utils.check_payload({}, [])
        self.assertTrue(success)
        self.assertIsNone(missing_keys)

        test_data = dict(
            key1='value1',
            key2='',  # required fields must be present and can't be empty
            key3=[],
            key5='value5'
        )

        # Check all cases
        success, missing_keys = rest_utils.check_payload(test_data, ['key1', 'key2', 'key3', 'key4'])
        expected_missing_keys = ['key2', 'key3', 'key4']
        self.assertFalse(success)
        self.assertEqual(missing_keys, expected_missing_keys)
