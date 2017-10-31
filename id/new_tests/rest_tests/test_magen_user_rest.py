# coding=utf-8
"""Test Suit for Magen User REST API"""

import json
from flask import Flask
from http import HTTPStatus
from unittest.mock import patch

from magen_rest_apis.rest_client_apis import RestClientApis

from ..db_test_base import TestBasePyMongo
from id.id_service.magenid.idsapp.idsserver.rest.magen_user_rest_api \
    import magen_user_bp, MAGEN_USER_URLS, SERVER_500_GEN_CAUSE, SERVER_500_ATTR_CAUSE


TEST_UUID = 'test_user_uuid'

MAGEN_USER = """{
    "user": [
        {
         "first_name": "Mizan",
         "last_name": "Chowdhury",
         "display_name":"Mizan Chowdhury",
         "password": "pw",
         "department":"R&D",
         "position":"lead",
         "role":"lead",
         "idp": "magen",
         "u_groups": [
            "finance"
         ],
         "u_clients":[],
         "username": "michowdh@cisco.com",
         "email": "michowdh@cisco.com",
         "imgSrc": "user_mizanul_chowdhury.png"
        }
    ]
}"""

MAGEN_USER_BAD_JSON = """{
    "user": [
        {
         "first_name": "Mizan",
         "last_name": "Chowdhury",
         "display_name":"Mizan Chowdhury",
         "password": "pw",
      #   "department":"R&D",
         "position":"lead",
         "role":"lead",
         "idp": "magen",
         "u_groups": [
            "finance"
         ],
         "u_clients":[],
         "username": "michowdh@cisco.com",
         "email": "michowdh@cisco.com",
         "imgSrc": "user_mizanul_chowdhury.png"
        }
    ]
}"""  # hashtag

MAGEN_USER_WRONG_FORMAT = """{
  "users": {
    "user": [
        {
         "uuid":"c9d0388e-76ea-48f7-9df4-62ea95a27649",
         "first_name": "Mizan",
         "last_name": "Chowdhury",
         "display_name":"Mizan Chowdhury",
         "password": "pw",
         "department":"R&D",
         "position":"lead",
         "role":"lead",
         "idp": "magen",
         "u_groups": [
            "finance"
         ],
         "u_clients":[],
         "username": "michowdh@cisco.com",
         "email": "michowdh@cisco.com",
         "imgSrc": "user_mizanul_chowdhury.png"
        }
    ]
  }
}"""

MAGEN_USER_MISSING = """{
    "user": [
        {
         "first_name": "Mizan",
         "display_name":"Mizan Chowdhury",
         "department":"R&D",
         "position":"lead",
         "role":"lead",
         "idp": "magen",
         "u_groups": [
            "finance"
         ],
         "u_clients":[],
         "username": "michowdh@cisco.com",
         "email": "michowdh@cisco.com",
         "imgSrc": "user_mizanul_chowdhury.png"
        }
    ]
}"""

MAGEN_USER_REPLACE = """{
    "user": [
        {
         "user_uuid": "test_user_uuid",
         "first_name": "John",
         "last_name": "Doe",
         "display_name":"Einstein",
         "password": "pw",
         "department":"R&D",
         "position":"intern",
         "role":"intern",
         "idp": "magen",
         "u_groups": [
            "engineering"
         ],
         "u_clients":[],
         "username": "jdoe@cisco.com",
         "email": "jdoe@cisco.com"
        }
    ]
}"""


class TestMagenUserREST(TestBasePyMongo):
    """Test suit for Magen User REST API"""

    def setUp(self):
        id_app = Flask(__name__)
        id_app.config['TESTING'] = True
        id_app.register_blueprint(magen_user_bp)
        self.test_id_app = id_app.test_client()

    def tearDown(self):
        TestMagenUserREST.magen_user_collection.remove()

    def test_add_user_OK(self):
        """
        Test Add Magen User through REST.
        Test covers 2 cases:
            o: creation of a new user
            o: attempting to create same user again
        """

        post_resp_obj = self.test_id_app.post(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER
        )

        self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertTrue(post_resp_data['response']['success'])
        self.assertIsNotNone(post_resp_data['response']['user'])
        # Verify that user_uuid was assigned and returned
        self.assertIn('user_uuid', post_resp_data['response']['user'])

        # POST same user again:
        post_resp_obj = self.test_id_app.post(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER
        )

        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        # Verify that server returned False
        self.assertFalse(post_resp_data['response']['success'])

    def test_add_user_bad_payload(self):
        """
        Test Add Magen User through REST with bad payload.
        Test contains 3 cases:
            o: json could not be generated from the request data
            o: bad request data formatting (KeyError, IndexError)
            o: bad request type, missin headers (TypeError)
            o: payload missing keys
        """
        # Bad JSON format: BadRequest
        post_resp_obj = self.test_id_app.post(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER_BAD_JSON
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertFalse(post_resp_data['response']['success'])
        self.assertIsNone(post_resp_data['response']['user'])

        # Payload format violation: KeyError, IndexError
        post_resp_obj = self.test_id_app.post(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER_WRONG_FORMAT
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertFalse(post_resp_data['response']['success'])
        self.assertIsNone(post_resp_data['response']['user'])

        # Bad Request data type: TypeError
        post_resp_obj = self.test_id_app.post(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],  # missing JSON headers
            data=MAGEN_USER
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertFalse(post_resp_data['response']['success'])
        self.assertIsNone(post_resp_data['response']['user'])

        post_resp_obj = self.test_id_app.post(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER_MISSING
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertFalse(post_resp_data['response']['success'])
        self.assertIn('password', post_resp_data['response']['cause'])
        self.assertIn('last_name', post_resp_data['response']['cause'])

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_api.MagenUserApi.insert_user')
    def test_add_user_attrerror(self, attr_error_mock):
        """
        Test Add Magen User through REST generated 500 error
            o: database connection failed or was not initialized properly (Attribute Error)
        """
        attr_error_mock.side_effect = AttributeError('\n' + __name__ + '.AttributeError\n')
        post_resp_obj = self.test_id_app.post(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertEqual(post_resp_data['response']['cause'], SERVER_500_ATTR_CAUSE)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_api.MagenUserApi.insert_user')
    def test_add_user_generror(self, gen_exception_mock):
        """
        Test Add Magen User through REST generated 500 error
            o: general Exception wrapped into Response object and returned to the client
        """
        gen_exception_mock.side_effect = Exception('\n' + __name__ + '.GeneralException\n')
        post_resp_obj = self.test_id_app.post(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertEqual(post_resp_data['response']['cause'], SERVER_500_GEN_CAUSE)

    def test_get_user_OK(self):
        """
        Test Get Magen User by user_uuid
        Test contains 2 cases:
            o: GET non-existing user (NOT_FOUND http status)
            o: POST a user and GET user by user_uuid (OK http status)
        """
        # Get non-existing user
        get_resp_obj = self.test_id_app.get(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user_uuid'].format('some_id'),
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.NOT_FOUND)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertFalse(get_resp_data['response']['success'])

        post_resp_obj = self.test_id_app.post(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER
        )
        # Verify the user was created
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        test_user_uuid = post_resp_data['response']['user']['user_uuid']

        get_resp_obj = self.test_id_app.get(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user_uuid'].format(test_user_uuid),
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.OK)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertTrue(get_resp_data['response']['success'])
        # Compare inserted and selected user data
        self.assertEqual(post_resp_data['response']['user'], get_resp_data['response']['user'])

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_api.MagenUserApi.get_user')
    def test_get_user_attrerror(self, attr_error_mock):
        """
        Test GET Magen User through REST generated 500 error
            o: database connection failed or was not initialized properly (Attribute Error)
        """
        attr_error_mock.side_effect = AttributeError('\n' + __name__ + '.AttributeError\n')
        get_resp_obj = self.test_id_app.get(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user_uuid'].format('some_id'),
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertEqual(get_resp_data['response']['cause'], SERVER_500_ATTR_CAUSE)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_api.MagenUserApi.get_user')
    def test_get_user_genrerror(self, gen_exception_mock):
        """
        Test GET Magen User through REST generated 500 error
            o: general Exception wrapped into Response object and returned to the client
        """
        gen_exception_mock.side_effect = Exception('\n' + __name__ + '.GeneralException\n')
        get_resp_obj = self.test_id_app.get(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user_uuid'].format('some_id'),
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertEqual(get_resp_data['response']['cause'], SERVER_500_GEN_CAUSE)

    def test_get_all_users_OK(self):
        """
        Test Get ALL Magen Users
        """

        # Users not exist
        get_resp_obj = self.test_id_app.get(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['users'],
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.NOT_FOUND)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertFalse(get_resp_data['response']['success'])
        self.assertIsNone(get_resp_data['response']['users'])

        # POSTing a user
        post_resp_obj = self.test_id_app.post(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER
        )
        # Verify the user was created
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)

        # Get users
        get_resp_obj = self.test_id_app.get(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['users'],
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.OK)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertTrue(get_resp_data['response']['success'])
        self.assertEqual(get_resp_data['response']['cause'], 'OK')
        user_list = get_resp_data['response']['users']
        self.assertEqual(len(user_list), 1)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_api.MagenUserApi.get_all')
    def test_get_users_attrerror(self, attr_error_mock):
        """
        Test GET Magen Users through REST generated 500 error
            o: database connection failed or was not initialized properly (Attribute Error)
        """
        attr_error_mock.side_effect = AttributeError('\n' + __name__ + '.AttributeError\n')
        get_resp_obj = self.test_id_app.get(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['users'],
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertEqual(get_resp_data['response']['cause'], SERVER_500_ATTR_CAUSE)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_api.MagenUserApi.get_all')
    def test_get_users_genrerror(self, gen_exception_mock):
        """
        Test GET Magen Users through REST generated 500 error
            o: general Exception wrapped into Response object and returned to the client
        """
        gen_exception_mock.side_effect = Exception('\n' + __name__ + '.GeneralException\n')
        get_resp_obj = self.test_id_app.get(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['users'],
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertEqual(get_resp_data['response']['cause'], SERVER_500_GEN_CAUSE)

    def test_delete_user_OK(self):
        """
        Test Delete Magen User by user_uuid
        Test contains 2 usecases:
            o: delete non-existing user
            o: delete existing user
        """

        # Delete non-existing user
        delete_url = MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user_uuid'].format('some_id')
        delete_resp_obj = self.test_id_app.delete(delete_url)
        self.assertEqual(delete_resp_obj.status_code, HTTPStatus.OK)
        delete_resp_data = json.loads(delete_resp_obj.data.decode())
        self.assertTrue(delete_resp_data['response']['success'])
        self.assertEqual(delete_resp_data['response']['user']['removed'], 0)

        # POSTing a user
        post_resp_obj = self.test_id_app.post(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER
        )
        # Verify the user was created
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertIsNotNone(post_resp_data['response']['user'])
        test_user_uuid = post_resp_data['response']['user']['user_uuid']

        # Delete user
        delete_url = MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user_uuid'].format(test_user_uuid)
        delete_resp_obj = self.test_id_app.delete(delete_url)
        self.assertEqual(delete_resp_obj.status_code, HTTPStatus.OK)
        delete_resp_data = json.loads(delete_resp_obj.data.decode())
        self.assertTrue(delete_resp_data['response']['success'])
        self.assertEqual(delete_resp_data['response']['user']['removed'], 1)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_api.MagenUserApi.delete_user')
    def test_delete_user_attrerror(self, attr_error_mock):
        """
        Test DELETE Magen Users through REST generated 500 error
            o: database connection failed or was not initialized properly (Attribute Error)
        """
        attr_error_mock.side_effect = AttributeError('\n' + __name__ + '.AttributeError\n')
        delete_url = MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user_uuid'].format('some_id')
        delete_resp_obj = self.test_id_app.delete(delete_url)
        self.assertEqual(delete_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        delete_resp_data = json.loads(delete_resp_obj.data.decode())
        self.assertEqual(delete_resp_data['response']['cause'], SERVER_500_ATTR_CAUSE)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_api.MagenUserApi.delete_user')
    def test_delete_user_genrerror(self, gen_exception_mock):
        """
        Test DELETE Magen Users through REST generated 500 error
            o: general Exception wrapped into Response object and returned to the client
        """
        gen_exception_mock.side_effect = Exception('\n' + __name__ + '.GeneralException\n')
        delete_url = MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user_uuid'].format('some_id')
        delete_resp_obj = self.test_id_app.delete(delete_url)
        self.assertEqual(delete_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        delete_resp_data = json.loads(delete_resp_obj.data.decode())
        self.assertEqual(delete_resp_data['response']['cause'], SERVER_500_GEN_CAUSE)

    def test_replace_user_OK(self):
        """
        Test Replace Magen User through REST.
        Test covers 2 cases:
            o: creation of a new user
            o: replace existing user
        """
        put_resp_obj = self.test_id_app.put(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER_REPLACE  # user_uuid must be provided
        )

        self.assertEqual(put_resp_obj.status_code, HTTPStatus.OK)
        post_resp_data = json.loads(put_resp_obj.data.decode())
        self.assertTrue(post_resp_data['response']['success'])
        self.assertIsNotNone(post_resp_data['response']['user'])

        magen_user = json.loads(MAGEN_USER)
        magen_user['user'][0]['user_uuid'] = TEST_UUID
        magen_user = json.dumps(magen_user)
        # Replace existing user
        put_resp_obj = self.test_id_app.put(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=magen_user  # user_uuid must be provided
        )

        self.assertEqual(put_resp_obj.status_code, HTTPStatus.OK)
        post_resp_data = json.loads(put_resp_obj.data.decode())
        self.assertTrue(post_resp_data['response']['success'])
        self.assertIsNotNone(post_resp_data['response']['user'])
        self.assertEqual(post_resp_data['response']['user']['username'], 'michowdh@cisco.com')

    def test_replace_user_bad_payload(self):
        """
        Test Replace Magen User through REST with bad payload.
        Test contains 3 cases:
            o: json could not be generated from the request data
            o: bad request data formatting (KeyError, IndexError)
            o: bad request type, missin headers (TypeError)
            o: payload missing keys
        """
        # Bad JSON format: BadRequest
        put_resp_obj = self.test_id_app.put(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER_BAD_JSON
        )
        self.assertEqual(put_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        put_resp_data = json.loads(put_resp_obj.data.decode())
        self.assertFalse(put_resp_data['response']['success'])
        self.assertIsNone(put_resp_data['response']['user'])

        # Payload format violation: KeyError, IndexError
        put_resp_obj = self.test_id_app.put(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER_WRONG_FORMAT
        )
        self.assertEqual(put_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        put_resp_data = json.loads(put_resp_obj.data.decode())
        self.assertFalse(put_resp_data['response']['success'])
        self.assertIsNone(put_resp_data['response']['user'])

        # Bad Request data type: TypeError
        put_resp_obj = self.test_id_app.put(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],  # missing JSON headers
            data=MAGEN_USER
        )
        self.assertEqual(put_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        put_resp_data = json.loads(put_resp_obj.data.decode())
        self.assertFalse(put_resp_data['response']['success'])
        self.assertIsNone(put_resp_data['response']['user'])

        put_resp_obj = self.test_id_app.put(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER_MISSING
        )
        self.assertEqual(put_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        put_resp_data = json.loads(put_resp_obj.data.decode())
        self.assertFalse(put_resp_data['response']['success'])
        self.assertIn('user_uuid', put_resp_data['response']['cause'])
        self.assertIn('password', put_resp_data['response']['cause'])
        self.assertIn('last_name', put_resp_data['response']['cause'])

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_api.MagenUserApi.replace_user')
    def test_replace_users_attrerror(self, attr_error_mock):
        """
        Test Replace (PUT) Magen Users through REST generated 500 error
            o: database connection failed or was not initialized properly (Attribute Error)
        """
        attr_error_mock.side_effect = AttributeError('\n' + __name__ + '.AttributeError\n')
        replace_resp_obj = self.test_id_app.put(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER_REPLACE
        )
        self.assertEqual(replace_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        replace_resp_data = json.loads(replace_resp_obj.data.decode())
        self.assertEqual(replace_resp_data['response']['cause'], SERVER_500_ATTR_CAUSE)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_api.MagenUserApi.replace_user')
    def test_replace_users_genrerror(self, gen_exception_mock):
        """
        Test Replace (PUT) Magen Users through REST generated 500 error
            o: general Exception wrapped into Response object and returned to the client
        """
        gen_exception_mock.side_effect = Exception('\n' + __name__ + '.GeneralException\n')
        replace_resp_obj = self.test_id_app.put(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER_REPLACE
        )
        self.assertEqual(replace_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        replace_resp_data = json.loads(replace_resp_obj.data.decode())
        self.assertEqual(replace_resp_data['response']['cause'], SERVER_500_GEN_CAUSE)
