# coding=utf-8
"""Test Suit for Magen Client REST API"""

import json
from flask import Flask
from http import HTTPStatus
from unittest.mock import patch

from magen_rest_apis.rest_client_apis import RestClientApis

from ..db_test_base import TestBasePyMongo
from id.id_service.magenid.idsapp.idsserver.rest.magen_client_rest_api \
    import magen_client_bp, MAGEN_CLIENTS_URLS, SERVER_500_GEN_CAUSE, SERVER_500_ATTR_CAUSE
from id.id_service.magenid.idsapp.idsserver.rest.magen_user_rest_api import magen_user_bp, MAGEN_USER_URLS
from .test_magen_user_rest import MAGEN_USER


TEST_MC_ID = 'test_mc_id'

MAGEN_CLIENT = """{
    "client": [
        {
        "user": "michowdh@cisco.com",
        "revision": "1",
        "device_id": "ipad",
        "mc_id": "",
        "ip": "192.168.1.209",
        "mac": "AA.96.9F.4E.3B.00"
        }
    ]
  }
"""

MAGEN_CLIENT_BAD_JSON = """{
    "client": [
        {
        "user": "rod@taxco.com",
        "revision": "1",
        "device_id": "ipad",
    #    "mc_id": "",
        "ip": "192.168.1.209",
        "mac": "AA.96.9F.4E.3B.00"
        }
    ]
  }
"""  # hashtag

MAGEN_CLIENT_BAD_FORMAT = """{
    "clients": {
    "client": [
        {
        "user": "michowdh@cisco.com",
        "revision": "1",
        "device_id": "ipad",
        "mc_id": "",
        "ip": "192.168.1.209",
        "mac": "AA.96.9F.4E.3B.00"
        }
    ]
  }
}
"""

MAGEN_CLIENT_MISSING = """{
    "client": [
        {
        "revision": "1",
        "device_id": "ipad",
        "mc_id": "",
        "ip": "192.168.1.209",
        "mac": "AA.96.9F.4E.3B.00"
        }
    ]
  }
"""  # user is missing


class TestMagenClientREST(TestBasePyMongo):
    """Test suit for Magen Client REST API"""

    def setUp(self):
        id_app = Flask(__name__)
        id_app.config['TESTING'] = True
        id_app.register_blueprint(magen_client_bp)
        id_app.register_blueprint(magen_user_bp)
        self.test_id_app = id_app.test_client()

    def tearDown(self):
        # Database clean up
        TestMagenClientREST.magen_client_collection.remove()
        TestMagenClientREST.magen_user_collection.remove()

    def _create_user(self):
        """Create Magen User"""
        post_resp_obj = self.test_id_app.post(
            MAGEN_USER_URLS['base_v3'] + MAGEN_USER_URLS['user'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_USER
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)

    def test_add_client_OK(self):
        """
        Test Add Magen Client through REST.
        Test covers 3 cases:
            o: attempt to create a new client with no existing user in place
            o: creation of a new client
            o: attempting to create same client again
        """
        # Create Client with not existing user
        post_resp_obj = self.test_id_app.post(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['client'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_CLIENT
        )

        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertFalse(post_resp_data['response']['success'])
        self.assertIn('michowdh@cisco.com', post_resp_data['response']['cause'])
        self.assertIsNone(post_resp_data['response']['client'])

        self._create_user()

        # Create a new Client for existing user
        post_resp_obj = self.test_id_app.post(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['client'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_CLIENT
        )

        self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertTrue(post_resp_data['response']['success'])
        self.assertIsNotNone(post_resp_data['response']['client'])
        # Verify that mc_id was assigned and returned
        self.assertIn('mc_id', post_resp_data['response']['client'])
        # Verify that mc_id value is not None
        self.assertIsNotNone(post_resp_data['response']['client']['mc_id'])
        # Verify that mc_id is not Empty
        self.assertTrue(post_resp_data['response']['client']['mc_id'])

        # Attempt to create client with same data
        post_resp_obj = self.test_id_app.post(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['client'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_CLIENT
        )

        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        # Verify that server returned False
        self.assertFalse(post_resp_data['response']['success'])

    def test_add_client_bad_payload(self):
        """
        Test Add Magen Client through REST with bad payload.
        Test contains 3 cases:
            o: json could not be generated from the request data
            o: bad request data formatting (KeyError, IndexError)
            o: bad request type, missing headers (TypeError)
            o: payload missing keys
        """
        # Bad JSON format: BadRequest
        post_resp_obj = self.test_id_app.post(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['client'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_CLIENT_BAD_JSON
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertFalse(post_resp_data['response']['success'])
        self.assertIsNone(post_resp_data['response']['client'])

        # Payload format violation: KeyError, IndexError
        post_resp_obj = self.test_id_app.post(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['client'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_CLIENT_BAD_FORMAT
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertFalse(post_resp_data['response']['success'])
        self.assertIsNone(post_resp_data['response']['client'])

        # Bad Request data type: TypeError
        post_resp_obj = self.test_id_app.post(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['client'],  # missing JSON headers
            data=MAGEN_CLIENT
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertFalse(post_resp_data['response']['success'])
        self.assertIsNone(post_resp_data['response']['client'])

        post_resp_obj = self.test_id_app.post(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['client'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_CLIENT_MISSING
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertFalse(post_resp_data['response']['success'])
        self.assertIn('user', post_resp_data['response']['cause'])

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_client_api.MagenClientApi.insert_client')
    def test_add_client_attrerror(self, attr_error_mock):
        """
        Test Add Magen Client through REST generated 500 error
            o: database connection failed or was not initialized properly (Attribute Error)
        """
        # Create user for client
        self._create_user()

        attr_error_mock.side_effect = AttributeError('\n' + __name__ + '.AttributeError\n')
        post_resp_obj = self.test_id_app.post(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['client'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_CLIENT
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertEqual(post_resp_data['response']['cause'], SERVER_500_ATTR_CAUSE)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_client_api.MagenClientApi.insert_client')
    def test_add_client_generror(self, gen_exception_mock):
        """
        Test Add Magen Client through REST generated 500 error
            o: general Exception wrapped into Response object and returned to the client
        """
        # Create user for client
        self._create_user()

        gen_exception_mock.side_effect = Exception('\n' + __name__ + '.GeneralException\n')
        post_resp_obj = self.test_id_app.post(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['client'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_CLIENT
        )
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        self.assertEqual(post_resp_data['response']['cause'], SERVER_500_GEN_CAUSE)

    def test_get_client_OK(self):
        """
        Test Get Magen Client by mc_id (magen client id)
        Test contains 2 cases:
            o: GET non-existing client (NOT_FOUND http status)
            o: POST a client and GET client by mc_id (OK http status)
        """
        # Get non-existing client
        get_resp_obj = self.test_id_app.get(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['mc_id'].format('some_id'),
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.NOT_FOUND)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertFalse(get_resp_data['response']['success'])

        # Create a user
        self._create_user()

        # POSTing a client
        post_resp_obj = self.test_id_app.post(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['client'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_CLIENT
        )
        # Verify the client was created
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        test_mc_id = post_resp_data['response']['client']['mc_id']

        get_resp_obj = self.test_id_app.get(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['mc_id'].format(test_mc_id),
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.OK)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertTrue(get_resp_data['response']['success'])
        # Compare inserted and selected user data
        self.assertEqual(post_resp_data['response']['client'], get_resp_data['response']['client'])

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_client_api.MagenClientApi.get_client')
    def test_get_client_attrerror(self, attr_error_mock):
        """
        Test GET Magen Client through REST generated 500 error
            o: database connection failed or was not initialized properly (Attribute Error)
        """
        attr_error_mock.side_effect = AttributeError('\n' + __name__ + '.AttributeError\n')
        get_resp_obj = self.test_id_app.get(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['mc_id'].format('some_id'),
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertEqual(get_resp_data['response']['cause'], SERVER_500_ATTR_CAUSE)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_client_api.MagenClientApi.get_client')
    def test_get_client_genrerror(self, gen_exception_mock):
        """
        Test GET Magen Client through REST generated 500 error
            o: general Exception wrapped into Response object and returned to the client
        """
        gen_exception_mock.side_effect = Exception('\n' + __name__ + '.GeneralException\n')
        get_resp_obj = self.test_id_app.get(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['mc_id'].format('some_id'),
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertEqual(get_resp_data['response']['cause'], SERVER_500_GEN_CAUSE)

    def test_get_all_clients_OK(self):
        """
        Test Get ALL Magen Clients
        """

        # Clients not exist
        get_resp_obj = self.test_id_app.get(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['clients'],
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.NOT_FOUND)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertFalse(get_resp_data['response']['success'])
        self.assertIsNone(get_resp_data['response']['clients'])

        # Create a user
        self._create_user()

        # POSTing a client
        post_resp_obj = self.test_id_app.post(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['client'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_CLIENT
        )
        # Verify the client was created
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)

        # GET clients
        get_resp_obj = self.test_id_app.get(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['clients'],
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.OK)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertTrue(get_resp_data['response']['success'])
        self.assertEqual(get_resp_data['response']['cause'], 'OK')
        client_list = get_resp_data['response']['clients']
        self.assertEqual(len(client_list), 1)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_client_api.MagenClientApi.get_all')
    def test_get_clients_attrerror(self, attr_error_mock):
        """
        Test GET Magen Clients through REST generated 500 error
            o: database connection failed or was not initialized properly (Attribute Error)
        """
        attr_error_mock.side_effect = AttributeError('\n' + __name__ + '.AttributeError\n')
        get_resp_obj = self.test_id_app.get(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['clients'],
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertEqual(get_resp_data['response']['cause'], SERVER_500_ATTR_CAUSE)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_client_api.MagenClientApi.get_all')
    def test_get_clients_genrerror(self, gen_exception_mock):
        """
        Test GET Magen Clients through REST generated 500 error
            o: general Exception wrapped into Response object and returned to the client
        """
        gen_exception_mock.side_effect = Exception('\n' + __name__ + '.GeneralException\n')
        get_resp_obj = self.test_id_app.get(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['clients'],
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        get_resp_data = json.loads(get_resp_obj.data.decode())
        self.assertEqual(get_resp_data['response']['cause'], SERVER_500_GEN_CAUSE)

    def test_delete_client_OK(self):
        """
        Test Delete Magen Client by mc_id (magen client id)
        Test contains 2 cases:
            o: Delete non-existing client (OK http status, different cause)
            o: POST a client and Delete client by mc_id (OK http status)
        """
        # Get non-existing client
        delete_resp_obj = self.test_id_app.delete(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['mc_id'].format('some_id'),
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(delete_resp_obj.status_code, HTTPStatus.OK)
        delete_resp_data = json.loads(delete_resp_obj.data.decode())
        self.assertTrue(delete_resp_data['response']['success'])
        self.assertIn('not exist', delete_resp_data['response']['cause'])

        # Create a user
        self._create_user()

        # POSTing a client
        post_resp_obj = self.test_id_app.post(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['client'],
            headers=RestClientApis.put_json_headers,
            data=MAGEN_CLIENT
        )
        # Verify the client was created
        self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)
        post_resp_data = json.loads(post_resp_obj.data.decode())
        test_mc_id = post_resp_data['response']['client']['mc_id']

        delete_resp_obj = self.test_id_app.delete(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['mc_id'].format(test_mc_id),
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(delete_resp_obj.status_code, HTTPStatus.OK)
        delete_resp_data = json.loads(delete_resp_obj.data.decode())
        self.assertTrue(delete_resp_data['response']['success'])
        self.assertEqual(delete_resp_data['response']['client']['removed'], 1)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_client_api.MagenClientApi.delete_client')
    def test_delete_client_attrerror(self, attr_error_mock):
        """
        Test DELETE Magen Clients through REST generated 500 error
            o: database connection failed or was not initialized properly (Attribute Error)
        """
        attr_error_mock.side_effect = AttributeError('\n' + __name__ + '.AttributeError\n')
        delete_resp_obj = self.test_id_app.delete(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['mc_id'].format(TEST_MC_ID),
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(delete_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        delete_resp_data = json.loads(delete_resp_obj.data.decode())
        self.assertEqual(delete_resp_data['response']['cause'], SERVER_500_ATTR_CAUSE)

    @patch('id.id_service.magenid.idsapp.idsserver.lib.bll.magen_client_api.MagenClientApi.delete_client')
    def test_delete_client_genrerror(self, gen_exception_mock):
        """
        Test DELETE Magen Clients through REST generated 500 error
            o: general Exception wrapped into Response object and returned to the client
        """
        gen_exception_mock.side_effect = Exception('\n' + __name__ + '.GeneralException\n')
        delete_resp_obj = self.test_id_app.delete(
            MAGEN_CLIENTS_URLS['base_v3'] + MAGEN_CLIENTS_URLS['mc_id'].format(TEST_MC_ID),
            headers=RestClientApis.get_json_headers
        )
        self.assertEqual(delete_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        delete_resp_data = json.loads(delete_resp_obj.data.decode())
        self.assertEqual(delete_resp_data['response']['cause'], SERVER_500_GEN_CAUSE)
