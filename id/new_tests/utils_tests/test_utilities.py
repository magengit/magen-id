# coding=utf-8
"""Test Suit  for Utilities functions"""

import unittest
import typing
import datetime
import socket

from mock import Mock
from freezegun import freeze_time

from id.id_service.magenid.idsapp.idsserver.utils.utilities \
    import get_user_dic, get_magen_client_dic, get_magen_group_dic, get_oauth_client_dic, \
    get_the_encoded_url, get_schema_from_url, get_port_from_url, \
    get_expire_time, create_id_token, get_json_response, get_magen_client_id, get_guid, \
    mac_for_ip


def get_ip():
    """Get IP address of a host machine"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        ip_address = s.getsockname()[0]
    except:
        ip_address = '127.0.0.1'
    finally:
        s.close()
    return ip_address


class TestUtilities(unittest.TestCase):
    """Test Suit for Utility Functions"""

    def test_get_user_dic_default(self):
        """Test Building User Dict from Default parameters"""
        t_username = 'test_username'
        t_email = 'test_email'
        user_dict_default = get_user_dic(t_username, t_email)
        self.assertEqual(len(user_dict_default), 16)
        self.assertIsNotNone(user_dict_default['uuid'])
        # check passed values assigned
        self.assertEqual(user_dict_default['username'], t_username)
        self.assertEqual(user_dict_default['email'], t_email)
        # default value assigned
        self.assertEqual(user_dict_default['idp'], 'magen')
        self.assertEqual(user_dict_default['role'], 'standard')
        # opt values are None
        self.assertIsNone(user_dict_default['first_name'])
        self.assertIsNone(user_dict_default['last_name'])
        self.assertIsNone(user_dict_default['department'])
        self.assertIsNone(user_dict_default['position'])
        self.assertIsNone(user_dict_default['display_name'])
        self.assertIsNone(user_dict_default['photo'])
        self.assertIsNone(user_dict_default['local'])
        self.assertIsNone(user_dict_default['password'])
        # assert default boolean
        self.assertTrue(user_dict_default['email_verified'])
        # default value for list type is empty list
        self.assertIsInstance(user_dict_default['u_groups'], typing.List)
        self.assertIsInstance(user_dict_default['u_clients'], typing.List)
        self.assertFalse(user_dict_default['u_groups'])
        self.assertFalse(user_dict_default['u_clients'])

    def test_get_user_dic(self):
        """Test Building User Dict from given values"""
        user_dict = get_user_dic(
            username='test_username',
            email='test_email',
            first_name='test_f_name',
            last_name='test_l_name',
            password='test_pass',
            department='test_department',
            u_clients=['client1_id', 'client2_id'],
            u_groups=['group1_id', 'group2_id'],
            position='test_position',
            role='test_role',
            display_name='test_d_name',
            email_verified=False,
            photo='test_photo',
            local='test_local'
        )

        self.assertEqual(len(user_dict), 16)
        # verify default
        self.assertEqual(user_dict['idp'], 'magen')
        # verify assigned values
        self.assertEqual(user_dict['username'], 'test_username')
        self.assertEqual(user_dict['email'], 'test_email')
        self.assertEqual(user_dict['first_name'], 'test_f_name')
        self.assertEqual(user_dict['last_name'], 'test_l_name')
        self.assertEqual(user_dict['password'], 'test_pass')
        self.assertEqual(user_dict['department'], 'test_department')
        self.assertEqual(user_dict['position'], 'test_position')
        self.assertEqual(user_dict['role'], 'test_role')
        self.assertEqual(user_dict['display_name'], 'test_d_name')
        self.assertEqual(user_dict['photo'], 'test_photo')
        self.assertEqual(user_dict['local'], 'test_local')

        # verify lists
        self.assertIsInstance(user_dict['u_groups'], typing.List)
        self.assertIsInstance(user_dict['u_clients'], typing.List)
        self.assertEqual(len(user_dict['u_groups']), 2)
        self.assertEqual(len(user_dict['u_clients']), 2)

        # verify boolean
        self.assertFalse(user_dict['email_verified'])

    def test_get_magen_client_dict_default(self):
        """Test Building Magen Client Dict from default parameters"""
        test_username = 'test_username'
        test_device_id = 'test_device_id'
        magen_client_dict_default = get_magen_client_dic(test_username, test_device_id)

        self.assertEqual(len(magen_client_dict_default), 6)
        # verify assigned values
        self.assertIsNotNone(magen_client_dict_default['mc_id'])
        self.assertEqual(magen_client_dict_default['user'], test_username)
        self.assertEqual(magen_client_dict_default['device_id'], test_device_id)
        # verify opt values are None
        self.assertIsNone(magen_client_dict_default['ip'])
        self.assertIsNone(magen_client_dict_default['mac'])
        self.assertIsNone(magen_client_dict_default['revision'])

    def test_get_magen_client_dict(self):
        """Test Building Magen Client Dict from given values"""
        magen_client_dict = get_magen_client_dic(
            user='test_username',
            device_id='test_device_id',
            mc_id='test_mc_id',
            ip='test_ip',
            mac='test_mac',
            revision='test_revision'
        )

        self.assertEqual(len(magen_client_dict), 6)
        # verify assigned values
        self.assertEqual(magen_client_dict['mc_id'], 'test_mc_id')
        self.assertEquals(magen_client_dict['user'], 'test_username')
        self.assertEqual(magen_client_dict['device_id'], 'test_device_id')
        self.assertEqual(magen_client_dict['ip'], 'test_ip')
        self.assertEqual(magen_client_dict['mac'], 'test_mac')
        self.assertEqual(magen_client_dict['revision'], 'test_revision')

    def test_get_magen_group_dict(self):
        """Test Building Magen Group Dict from given value"""
        group_dict = get_magen_group_dic('test_groupname', 'test_group_id')

        self.assertEqual(len(group_dict), 2)
        self.assertEqual(group_dict['ug_name'], 'test_groupname')
        self.assertEqual(group_dict['ug_id'], 'test_group_id')

    def test_get_oauth_client_dict_default(self):
        """Test Building Magen Group Dict from default parameters"""
        test_client_name = 'test_client_name'
        oauth_client_dict_default = get_oauth_client_dic(test_client_name)

        self.assertEqual(len(oauth_client_dict_default), 7)
        # verify assigned values
        self.assertEqual(oauth_client_dict_default['client_name'], test_client_name)
        # verify default
        self.assertEqual(oauth_client_dict_default['jwt_alg'], 'RS256')
        self.assertEqual(oauth_client_dict_default['response_type'], 'code')
        # verify opt None values
        self.assertIsNone(oauth_client_dict_default['redirect_uris'])
        self.assertIsNone(oauth_client_dict_default['client_id'])
        self.assertIsNone(oauth_client_dict_default['client_secret'])
        # verify lists
        self.assertIsInstance(oauth_client_dict_default['default_scopes'], typing.List)

    def test_get_oauth_client_dict(self):
        """Test Building Magen Group Dict from default parameters"""
        oauth_client_dict = get_oauth_client_dic(
            client_name='test_client_name',
            redirect_uris='test_redirect_uris',
            default_scopes=['test_scope1', 'test_scope2'],
            jwt_alg='test_jwt_alg',
            client_id='test_client_id',
            client_secret='test_client_secret'
        )

        self.assertEqual(len(oauth_client_dict), 7)
        # verify assigned values
        self.assertEqual(oauth_client_dict['client_name'], 'test_client_name')
        self.assertEqual(oauth_client_dict['redirect_uris'], 'test_redirect_uris')
        self.assertEqual(oauth_client_dict['jwt_alg'], 'test_jwt_alg')
        self.assertEqual(oauth_client_dict['client_id'], 'test_client_id')
        self.assertEqual(oauth_client_dict['client_secret'], 'test_client_secret')
        # verify lists
        self.assertIsInstance(oauth_client_dict['default_scopes'], typing.List)
        self.assertEqual(len(oauth_client_dict['default_scopes']), 2)

    def test_get_the_encoded_url(self):
        """Test get _the_ encoded URL"""
        not_valid_url = 'test_not_valid_url'
        self.assertEqual(get_the_encoded_url(not_valid_url), not_valid_url)
        valid_url = 'http://localhost:8080/test_url'
        self.assertEqual(get_the_encoded_url(valid_url), valid_url)
        valid_decoded_url = 'http://localhost:8080/test url/'
        # verify that returned url is not encoded
        self.assertEqual(get_the_encoded_url(valid_decoded_url), valid_decoded_url)

    def test_get_schema_from_url(self):
        """Test get schema from URL"""
        not_valid_url = 'test_not_valid_url'
        self.assertEqual(get_schema_from_url(not_valid_url), '')
        valid_http_url = 'http://localhost:8080/test_url'
        self.assertEqual(get_schema_from_url(valid_http_url), 'http')
        valid_https_url = 'https://localhost:5050/test_url'
        self.assertEqual(get_schema_from_url(valid_https_url), 'https')
        not_valid_scheme_url = 'some_scheme://localhost:8090/test_url'
        self.assertEqual(get_schema_from_url(not_valid_scheme_url), '')
        unknown_scheme_url = 'ttt://localhost:8080/test_url'
        self.assertEqual(get_schema_from_url(unknown_scheme_url), 'ttt')

    def test_get_port_from_url(self):
        """Test Port from URL"""
        not_valid_url = 'test_not_valid_url'
        self.assertIsNone(get_port_from_url(not_valid_url))
        valid_url = 'http://localhost:8080/test_url'
        # port returned as integer, not a string
        self.assertIsInstance(get_port_from_url(valid_url), int)
        self.assertEqual(get_port_from_url(valid_url), 8080)
        valid_url_no_port = 'http://localhost/test_url'
        self.assertIsNone(get_port_from_url(valid_url_no_port))

    def test_get_expire_time(self):
        """Test Generation expiration time from now"""
        cur_time_value = datetime.datetime(2017, 10, 18, 17, 5, 11, 717155)
        default_seconds = 100
        with freeze_time(cur_time_value):
            result = get_expire_time()
        self.assertEqual(str(result - datetime.timedelta(seconds=default_seconds)), str(cur_time_value))

        custom_seconds = 25000
        with freeze_time(cur_time_value):
            result = get_expire_time(custom_seconds)
        self.assertEqual(str(result - datetime.timedelta(seconds=custom_seconds)), str(cur_time_value))

    def test_create_id_token(self):
        # September 10th
        test_time = datetime.datetime.utcfromtimestamp(datetime.datetime(2017, 9, 10, 17, 5, 11, 717155).timestamp())
        # October 18th
        frozen_now = datetime.datetime.utcfromtimestamp(datetime.datetime(2017, 10, 18, 19, 43, 42, 352778).timestamp())
        # expire in 3 days
        expire_datetime = datetime.datetime.utcfromtimestamp(datetime.datetime(2017, 10, 21, 19, 43, 42, 352778).timestamp())
        user_mock = Mock(username='test_username', last_login=test_time)

        expected_iat_time_seconds = int(frozen_now.timestamp())
        expected_exp_time_seconds = int(expire_datetime.timestamp())
        expected_auth_time_seconds = int(test_time.timestamp())

        with freeze_time(frozen_now):
            id_token_dict = create_id_token(
                user=user_mock,
                aud='test_aud',
                nonce='test_nonce',
                expire=3*60*60*24,  # 3 days
                issuer='test_issuer'
            )

        self.assertEqual(id_token_dict['iss'], 'test_issuer')
        self.assertEqual(id_token_dict['sub'], 'test_username')
        self.assertEqual(id_token_dict['aud'], 'test_aud')
        self.assertEqual(id_token_dict['exp'], expected_exp_time_seconds)
        self.assertEqual(id_token_dict['iat'], expected_iat_time_seconds)
        self.assertEqual(id_token_dict['auth_time'], expected_auth_time_seconds)

    def test_get_json_response(self):
        """Test create json response from str"""
        resp_object = get_json_response('test')
        print(resp_object.data)
        self.assertEqual(resp_object.status_code, 200)
        self.assertEqual(resp_object.mimetype, 'application/json')
        self.assertEqual(resp_object.cache_control.max_age, 300)
        self.assertEqual(resp_object.data, b'test')  # data as binary string

        d = dict(
            username='test_username',
            additional_data='test_data'
        )
        resp_object = get_json_response(str(d))
        self.assertEqual(resp_object.status_code, 200)
        self.assertEqual(resp_object.mimetype, 'application/json')
        self.assertEqual(resp_object.cache_control.max_age, 300)
        self.assertEqual(resp_object.data, str(d).encode())  # data as binary string

    def test_get_magen_client_id(self):
        """Test Generation of magen_client id"""
        expected_id = '1f53ad66e4cc49387f157aa7849c48d659f4931a58e8dff8ec3849ed29e974f7'
        actual_id = get_magen_client_id('test_user', 'test_device_id')
        self.assertEqual(expected_id, actual_id)

    def test_get_guid(self):
        """Test Generation of Group User id"""
        expected_id = 'e7d87b738825c33824cf3fd32b7314161fc8c425129163ff5e7260fc7288da36'
        actual_id = get_guid('test_data')
        self.assertEqual(expected_id, actual_id)

    def test_mac_for_ip(self):
        """Test Mac for IP"""
        mac_address = mac_for_ip(get_ip())
        mac_address_list = mac_address.split(':')
        # verify mac address format
        self.assertEqual(len(mac_address_list), 6)
