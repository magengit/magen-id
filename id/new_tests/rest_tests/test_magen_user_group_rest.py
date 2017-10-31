# coding=utf-8
"""Test Suit for Magen User Group REST API"""
import json
from flask import Flask
from http import HTTPStatus
from unittest.mock import patch

from magen_rest_apis.rest_client_apis import RestClientApis

from ..db_test_base import TestBasePyMongo
from id.id_service.magenid.idsapp.idsserver.rest.magen_group_rest_api import magen_user_group_bp, MAGEN_U_GROUP_URLS, \
    SERVER_500_ATTR_CAUSE, SERVER_500_GEN_CAUSE

TEST_NAME = "test_group_name"

MAGEN_U_GROUP = """{
    "group": [{
        "ug_name": "engineering",
        "ug_id": 1
    }]
}"""

MAGEN_U_GROUP_BAD_JSON = """{
    "group": [{
        "ug_name": "engineering",
        "ug_id": 1,
    }]
}"""  # extra comma

MAGEN_U_GROUP_BAD_FORMAT = """{
"groups": {
    "group": [{
        "ug_name": "engineering",
        "ug_id": 1
    }]
}}"""

MAGEN_U_GROUP_MISSING = """{
    "group": [{
        "ug_name": "engineering"
    }]
}"""

MAGEN_USER_GROUP_REPLACE = """{
    "group": [{
        "ug_name": "test_group_name",
        "ug_id": "another_id",
        "new_field": "new_field"
    }]
}"""


class TestMagenUserREST(TestBasePyMongo):
    """Test suit for Magen User REST API"""

    def setUp(self):
        id_app = Flask(__name__)
        id_app.config['TESTING'] = True
        id_app.register_blueprint(magen_user_group_bp)
        self.test_id_app = id_app.test_client()

    def tearDown(self):
        TestMagenUserREST.magen_user_group_collection.remove()

    def test_add_group_OK(self):
        """
        Test Add Magen User Group through REST.
        Test covers 2 cases:
            o: creation of a new user group
            o: attempting to create same user group again
        """

        post_resp_obj = self.test_id_app.post(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_U_GROUP
        )

        self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertTrue(post_resp_data['response']['success'])
        self.assertIsNotNone(post_resp_data['response']['group'])

        # POST same group again:
        post_resp_obj = self.test_id_app.post(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_U_GROUP
        )

        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        # Verify that server returned False
        self.assertFalse(post_resp_data['response']['success'])

    def test_add_group_bad_payload(self):
        """
        Test Add Magen User Group through REST with bad payload.
        Test contains 3 cases:
            o: json could not be generated from the request data
            o: bad request data formatting (KeyError, IndexError)
            o: bad request type, missing headers (TypeError)
            o: payload missing keys
        """
        # Bad JSON format: BadRequest
        post_resp_obj = self.test_id_app.post(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_U_GROUP_BAD_JSON
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertFalse(post_resp_data['response']['success'])
        self.assertIsNone(post_resp_data['response']['group'])

        # Payload format violation: KeyError, IndexError
        post_resp_obj = self.test_id_app.post(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_U_GROUP_BAD_FORMAT
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertFalse(post_resp_data['response']['success'])
        self.assertIsNone(post_resp_data['response']['group'])

        # Bad Request data type: TypeError
        post_resp_obj = self.test_id_app.post(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],  # missing JSON headers
            data=MAGEN_U_GROUP
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertFalse(post_resp_data['response']['success'])
        self.assertIsNone(post_resp_data['response']['group'])

        post_resp_obj = self.test_id_app.post(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_U_GROUP_MISSING
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertFalse(post_resp_data['response']['success'])
        self.assertIn('ug_id', post_resp_data['response']['cause'])

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_group_api.MagenUserGroupApi.insert_group')
    def test_add_group_attrerror(self, attr_error_mock):
        """
        Test Add Magen User Group through REST generated 500 error
            o: database connection failed or was not initialized properly (Attribute Error)
        """
        attr_error_mock.side_effect = AttributeError('\n' + __name__ + '.AttributeError\n')
        post_resp_obj = self.test_id_app.post(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_U_GROUP
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertEqual(post_resp_data['response']['cause'], SERVER_500_ATTR_CAUSE)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_group_api.MagenUserGroupApi.insert_group')
    def test_add_group_generror(self, gen_exception_mock):
        """
        Test Add Magen User Group through REST generated 500 error
            o: general Exception wrapped into Response object and returned to the client
        """
        gen_exception_mock.side_effect = Exception('\n' + __name__ + '.GeneralException\n')
        post_resp_obj = self.test_id_app.post(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_U_GROUP
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertEqual(post_resp_data['response']['cause'], SERVER_500_GEN_CAUSE)

    def test_get_user_OK(self):
        """
        Test Get Magen User Group by user_group_name
        Test contains 2 cases:
            o: GET non-existing group (NOT_FOUND http status)
            o: POST a user and GET group by user_group_name (OK http status)
        """
        # Get non-existing group
        get_resp_obj = self.test_id_app.get(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group_name'].format('some_id'),
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.NOT_FOUND)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertFalse(get_resp_data['response']['success'])

        post_resp_obj = self.test_id_app.post(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_U_GROUP
        )
        # Verify the group was created
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        test_group_name = post_resp_data['response']['group']['ug_name']

        get_resp_obj = self.test_id_app.get(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group_name'].format(test_group_name),
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.OK)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertTrue(get_resp_data['response']['success'])
        # Compare inserted and selected group data
        self.assertEqual(post_resp_data['response']['group'], get_resp_data['response']['group'])

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_group_api.MagenUserGroupApi.get_group_by_name')
    def test_get_user_attrerror(self, attr_error_mock):
        """
        Test GET Magen User through REST generated 500 error
            o: database connection failed or was not initialized properly (Attribute Error)
        """
        attr_error_mock.side_effect = AttributeError('\n' + __name__ + '.AttributeError\n')
        get_resp_obj = self.test_id_app.get(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group_name'].format('some_id'),
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertEqual(get_resp_data['response']['cause'], SERVER_500_ATTR_CAUSE)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_group_api.MagenUserGroupApi.get_group_by_name')
    def test_get_user_genrerror(self, gen_exception_mock):
        """
        Test GET Magen User through REST generated 500 error
            o: general Exception wrapped into Response object and returned to the client
        """
        gen_exception_mock.side_effect = Exception('\n' + __name__ + '.GeneralException\n')
        get_resp_obj = self.test_id_app.get(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group_name'].format('some_id'),
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertEqual(get_resp_data['response']['cause'], SERVER_500_GEN_CAUSE)

    def test_get_all_groups_OK(self):
        """
        Test Get ALL Magen User Groups
        """

        # Users not exist
        get_resp_obj = self.test_id_app.get(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['groups'],
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.NOT_FOUND)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertFalse(get_resp_data['response']['success'])
        self.assertIsNone(get_resp_data['response']['groups'])

        # POSTing a group
        post_resp_obj = self.test_id_app.post(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_U_GROUP
        )
        # Verify the user was created
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)

        # Get groups
        get_resp_obj = self.test_id_app.get(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['groups'],
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.OK)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertTrue(get_resp_data['response']['success'])
        self.assertEqual(get_resp_data['response']['cause'], 'OK')
        group_list = get_resp_data['response']['groups']
        self.assertEqual(len(group_list), 1)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_group_api.MagenUserGroupApi.get_all')
    def test_get_groups_attrerror(self, attr_error_mock):
        """
        Test GET Magen Users through REST generated 500 error
            o: database connection failed or was not initialized properly (Attribute Error)
        """
        attr_error_mock.side_effect = AttributeError('\n' + __name__ + '.AttributeError\n')
        get_resp_obj = self.test_id_app.get(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['groups'],
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertEqual(get_resp_data['response']['cause'], SERVER_500_ATTR_CAUSE)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_group_api.MagenUserGroupApi.get_all')
    def test_get_groups_genrerror(self, gen_exception_mock):
        """
        Test GET Magen Users through REST generated 500 error
            o: general Exception wrapped into Response object and returned to the client
        """
        gen_exception_mock.side_effect = Exception('\n' + __name__ + '.GeneralException\n')
        get_resp_obj = self.test_id_app.get(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['groups'],
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertEqual(get_resp_data['response']['cause'], SERVER_500_GEN_CAUSE)

    def test_delete_group_OK(self):
        """
        Test Delete Magen User Group by group name
        Test contains 2 usecases:
            o: delete non-existing group
            o: delete existing group
        """

        # Delete non-existing group
        delete_url = MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group_name'].format('some_name')
        delete_resp_obj = self.test_id_app.delete(delete_url)
        self.assertEqual(delete_resp_obj.status_code, HTTPStatus.OK)
        delete_resp_data = json.loads(delete_resp_obj.data.decode())
        self.assertTrue(delete_resp_data['response']['success'])
        self.assertEqual(delete_resp_data['response']['group']['removed'], 0)

        # POSTing a group
        post_resp_obj = self.test_id_app.post(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_U_GROUP
        )
        # Verify the group was created
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertIsNotNone(post_resp_data['response']['group'])
        test_group_name = post_resp_data['response']['group']['ug_name']

        # Delete group
        delete_url = MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group_name'].format(test_group_name)
        delete_resp_obj = self.test_id_app.delete(delete_url)
        self.assertEqual(delete_resp_obj.status_code, HTTPStatus.OK)
        delete_resp_data = json.loads(delete_resp_obj.data.decode())
        self.assertTrue(delete_resp_data['response']['success'])
        self.assertEqual(delete_resp_data['response']['group']['removed'], 1)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_group_api.MagenUserGroupApi.delete_group')
    def test_delete_group_attrerror(self, attr_error_mock):
        """
        Test DELETE Magen User Group through REST generated 500 error
            o: database connection failed or was not initialized properly (Attribute Error)
        """
        attr_error_mock.side_effect = AttributeError('\n' + __name__ + '.AttributeError\n')
        delete_url = MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group_name'].format('some_name')
        delete_resp_obj = self.test_id_app.delete(delete_url)
        self.assertEqual(delete_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        delete_resp_data = json.loads(delete_resp_obj.data.decode())
        self.assertEqual(delete_resp_data['response']['cause'], SERVER_500_ATTR_CAUSE)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_group_api.MagenUserGroupApi.delete_group')
    def test_delete_group_genrerror(self, gen_exception_mock):
        """
        Test DELETE Magen User Group through REST generated 500 error
            o: general Exception wrapped into Response object and returned to the client
        """
        gen_exception_mock.side_effect = Exception('\n' + __name__ + '.GeneralException\n')
        delete_url = MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group_name'].format('some_id')
        delete_resp_obj = self.test_id_app.delete(delete_url)
        self.assertEqual(delete_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        delete_resp_data = json.loads(delete_resp_obj.data.decode())
        self.assertEqual(delete_resp_data['response']['cause'], SERVER_500_GEN_CAUSE)

    def test_replace_group_OK(self):
        """
        Test Replace Magen User Group through REST.
        Test covers 2 cases:
            o: creation of a new group
            o: replace existing group
        """
        put_resp_obj = self.test_id_app.put(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER_GROUP_REPLACE  # ug_name must be provided
        )

        self.assertEqual(put_resp_obj.status_code, HTTPStatus.OK)
        post_resp_data = json.loads(put_resp_obj.data.decode())
        self.assertTrue(post_resp_data['response']['success'])
        self.assertIsNotNone(post_resp_data['response']['group'])

        magen_group = json.loads(MAGEN_U_GROUP)
        magen_group['group'][0]['ug_name'] = TEST_NAME
        magen_group = json.dumps(magen_group)
        # Replace existing group
        put_resp_obj = self.test_id_app.put(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=magen_group  # ug_name must be provided
        )

        self.assertEqual(put_resp_obj.status_code, HTTPStatus.OK)
        post_resp_data = json.loads(put_resp_obj.data.decode())
        self.assertTrue(post_resp_data['response']['success'])
        self.assertIsNotNone(post_resp_data['response']['group'])
        self.assertEqual(post_resp_data['response']['group']['ug_id'], 1)

    def test_replace_user_bad_payload(self):
        """
        Test Replace Magen User Group through REST with bad payload.
        Test contains 3 cases:
            o: json could not be generated from the request data
            o: bad request data formatting (KeyError, IndexError)
            o: bad request type, missin headers (TypeError)
            o: payload missing keys
        """
        # Bad JSON format: BadRequest
        put_resp_obj = self.test_id_app.put(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_U_GROUP_BAD_JSON
        )
        self.assertEqual(put_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        put_resp_data = json.loads(put_resp_obj.data.decode())
        self.assertFalse(put_resp_data['response']['success'])
        self.assertIsNone(put_resp_data['response']['group'])

        # Payload format violation: KeyError, IndexError
        put_resp_obj = self.test_id_app.put(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_U_GROUP_BAD_FORMAT
        )
        self.assertEqual(put_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        put_resp_data = json.loads(put_resp_obj.data.decode())
        self.assertFalse(put_resp_data['response']['success'])
        self.assertIsNone(put_resp_data['response']['group'])

        # Bad Request data type: TypeError
        put_resp_obj = self.test_id_app.put(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],  # missing JSON headers
            data=MAGEN_U_GROUP
        )
        self.assertEqual(put_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        put_resp_data = json.loads(put_resp_obj.data.decode())
        self.assertFalse(put_resp_data['response']['success'])
        self.assertIsNone(put_resp_data['response']['group'])

        put_resp_obj = self.test_id_app.put(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_U_GROUP_MISSING
        )
        self.assertEqual(put_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        put_resp_data = json.loads(put_resp_obj.data.decode())
        self.assertFalse(put_resp_data['response']['success'])
        self.assertIn('ug_id', put_resp_data['response']['cause'])

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_group_api.MagenUserGroupApi.replace_group')
    def test_replace_group_attrerror(self, attr_error_mock):
        """
        Test Replace (PUT) Magen User Group through REST generated 500 error
            o: database connection failed or was not initialized properly (Attribute Error)
        """
        attr_error_mock.side_effect = AttributeError('\n' + __name__ + '.AttributeError\n')
        replace_resp_obj = self.test_id_app.put(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER_GROUP_REPLACE
        )
        self.assertEqual(replace_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        replace_resp_data = json.loads(replace_resp_obj.data.decode())
        self.assertEqual(replace_resp_data['response']['cause'], SERVER_500_ATTR_CAUSE)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_group_api.MagenUserGroupApi.replace_group')
    def test_replace_users_genrerror(self, gen_exception_mock):
        """
        Test Replace (PUT) Magen User Group through REST generated 500 error
            o: general Exception wrapped into Response object and returned to the client
        """
        gen_exception_mock.side_effect = Exception('\n' + __name__ + '.GeneralException\n')
        replace_resp_obj = self.test_id_app.put(
            MAGEN_U_GROUP_URLS['base_v3'] + MAGEN_U_GROUP_URLS['group'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER_GROUP_REPLACE
        )
        self.assertEqual(replace_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        replace_resp_data = json.loads(replace_resp_obj.data.decode())
        self.assertEqual(replace_resp_data['response']['cause'], SERVER_500_GEN_CAUSE)
