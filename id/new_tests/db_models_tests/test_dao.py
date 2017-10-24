# coding=utf-8
"""Test Suit for Dao module"""

import unittest
import datetime
import mongoengine
import mongoengine.connection as mongo_connection
from magen_utils_apis import domain_resolver
#
# from .test_models import mongo_object_to_dict

# # Package imports from local PIP
# from magen_rest_apis.magen_app import MagenApp
# # If this is being run from workspace (as main module),
# # import dev/magen_env.py to add workspace package directories.
# src_ver = MagenApp.app_source_version(__name__)
# if src_ver:
#     # noinspection PyUnresolvedReferences
#     import dev.magen_env

from id.id_service.magenid.idsapp.idsserver.lib.db.models.models import Domain, Client, Code, Grant, Token
from id.id_service.magenid.idsapp.idsserver.lib.db.models.magen_client_models import MagenUser
from id.id_service.magenid.idsapp.idsserver.lib.db import dao

TEST_USERNAME = 'test_username'
TEST_CLIENT_ID = 'test_client_id'

TEST_TOKEN = dict(
    access_token='test_access_token',
    refresh_token='test_refresh_token',
    id_token='test_id_token',
    encoded_token='test_encoded_token',
    scopes='test_scopes',  # supposed to be list but not regulated yet
    mc_id='test_mc_id'
)

TEST_CODE = dict(
    code='test_code',
    nonce='test_nonce',
    is_authentication=True,
    code_challenge='test_code_challenge',
    code_challenge_method='test_code_challenge_method',
    scopes='test_scopes'
)

TEST_USER = dict(
    uuid='test_uuid',
    username=TEST_USERNAME,
    first_name='test_first_name',
    last_name='test_last_name',
    password='test_password',
    email='test_email',
    email_verified=True,
    role='test_role',
    idp='test_idp',
    department='test_department',
    photo='test_photo',
    local='test_local',
    position='test_position',
    u_groups=['test_group1', 'test_group2'],
    display_name='test_display_name'
)

TEST_CLIENT = dict(
    client_id=TEST_CLIENT_ID,
    client_name='test_client_name',
    client_secret='test_client_secret',
    response_type='test_response_type',
    redirect_uris='test_redirect_uri',
    default_scopes=['test_scope1', 'test_scope2'],
    jwt_alg='test_jwt_alg',
    registration_client_uri='test_registration_client_uri',
    grant_types='test_grant_types',
    application_type='test_app_type',
    contacts='test_contacts',
    logo_uri='test_logo_uri',
    client_uri='test_client_uri',
    policy_uri='test_policy_uri',
    tos_uri='test_tos_uri',
    jwks_uri='test_jwks_uri',
    jwks='test_jwks',
    sector_identifier_uri='test_identifier_uri',
    subject_type='test_subject_type',
    id_token_signed_response_alg='test_id_token_signed_response_alg',
    id_token_encrypted_response_alg='test_id_token_encrypted_response_alg',
    id_token_encrypted_response_enc='test_id_token_encrypted_response_enc',
    userinfo_signed_response_alg='test_userinfo_signed_response_alg',
    userinfo_encrypted_response_alg='test_userinfo_encrypted_response_alg',
    userinfo_encrypted_response_enc='test_userinfo_encrypted_response_enc',
    request_object_signing_alg='test_request_object_signing_alg',
    request_object_encryption_alg='test_request_object_encryption_alg',
    request_object_encryption_enc='test_request_object_encryption_enc',
    token_endpoint_auth_method='test_token_endpoint_auth_method',
    token_endpoint_auth_signing_alg='test_token_endpoint_auth_signing_alg',
    default_max_age=300,
    require_auth_time=True,
    default_acr_values='test_default_acr_values',
    initiate_login_uri='test_initiate_login_uri',
    request_uris='test_request_uris',
    device_id='test_device_id',
    mac='test_mac',
    ip='test_ip',
    revision='test_revision',
    dns_name='test_dns_name',
    client_description='test_client_description',
    reuse_refresh_token=False,
    dynamically_registered=False,
    allow_introspection=False,
    id_token_validity_seconds=False,
    clear_access_tokens_on_refresh=False
    # default fields
)


def _insert_test_user(user_data):
    """Insert User into DataBase"""
    test_user = MagenUser(**user_data)
    test_user.save()
    return test_user


def _insert_test_client(client_data):
    """Insert Client into Database"""
    test_client = Client(**client_data)
    # FIXME: models must support validation as True
    test_client.save(validate=False)
    return test_client


def _insert_test_code(code_data):
    """Insert Code into Database"""
    test_code = Code(**code_data)
    test_code.save()
    return test_code


def _insert_test_grant(grant_data):
    """Insert Grant into Database"""
    test_code = Grant(**grant_data)
    test_code.save()
    return test_code


def _insert_test_token(token_data):
    """Insert Token into Database"""
    test_token = Token(**token_data)
    test_token.save()
    return test_token


class TestBase(unittest.TestCase):
    """Test suit Test Base class for mongo connection"""
    test_db = None

    @classmethod
    def setUpClass(cls):
        mongo_ip, mongo_port = domain_resolver.mongo_host_port()
        # FIXME:
        # Other tests are failing, because mongoengine is not disconnected from  default databased
        # which is not test database, but operational. Needs fixing
        # register_connection as default is a hack to avoid test failure
        mongo_connection.register_connection('default', 'test_id_db', host=mongo_ip, port=mongo_port)
        cls.test_db = mongoengine.connect(db='test_id_db', host=mongo_ip, port=mongo_port)

    @classmethod
    def tearDownClass(cls):
        cls.test_db.drop_database('test_id_db')
        mongo_connection.disconnect('test_id_db')


class TestDomainDao(TestBase):
    """Test suit for DomainDao class"""

    def setUp(self):
        self.domains_dao = dao.DomainDao()

    def tearDown(self):
        Domain.objects.delete()
        self.assertFalse(Domain.objects.all())

    def test_get_all_domains(self):
        """Test select all domains"""
        # Selecting Domains on Empty set
        Domain.objects.delete()
        self.assertFalse(self.domains_dao.getAllDomains())

        domain = Domain(name='test_name', idp='test_idp', allow=True)
        domain.save()
        result_domains = self.domains_dao.getAllDomains()
        self.assertEqual(len(result_domains), 1)
        result_domain = result_domains[0]
        self.assertEqual(result_domain.name, 'test_name')
        self.assertEqual(result_domain.idp, 'test_idp')
        self.assertEqual(result_domain.allow, True)

    def test_get_domain_by_name(self):
        """Test select domain by name"""
        test_name = 'test_name'
        test_name2 = 'test_name2'
        domain = Domain(name=test_name, idp='test_idp', allow=True)
        domain.save()
        domain2 = Domain(name=test_name2, idp='test_idp', allow=False)
        domain2.save()

        result_domain = self.domains_dao.getDomainByDomainName(test_name)
        self.assertIsNotNone(result_domain)
        self.assertEqual(result_domain.name, test_name)
        self.assertEqual(result_domain.idp, 'test_idp')
        self.assertEqual(result_domain.allow, True)

        # try to get domain by non-existing name
        result_domain = self.domains_dao.getDomainByDomainName('non_existing_name')
        self.assertIsNone(result_domain)

    def test_save_domain(self):
        """Test Insert Domain"""
        saved_domain = self.domains_dao.saveDomain('test_name', 'test_idp', True)
        self.assertIsNotNone(saved_domain)
        selected_domain = Domain.objects.get(name='test_name')
        # verify that domain was saved
        self.assertEqual(selected_domain, saved_domain)


class TestClientDao(TestBase):
    """Test suit for ClientDao class"""

    def setUp(self):
        self.clients_dao = dao.ClientDao()

    def tearDown(self):
        Client.objects.delete()
        self.assertFalse(Client.objects.all())
        MagenUser.objects.delete()
        self.assertFalse(MagenUser.objects.all())

    def test_get_all_clients(self):
        """Test Select All Clients"""
        # Selecting Clients on Empty set
        self.assertFalse(self.clients_dao.getAllClients())

        client = _insert_test_client(TEST_CLIENT)

        result_clients = self.clients_dao.getAllClients()
        self.assertEqual(len(result_clients), 1)
        result_client = result_clients[0]
        self.assertEqual(client, result_client)  # comparing model objects directly

    def test_get_all_clients_by_username(self):
        """Test Select clients by username"""
        # Creating few clients with same username
        test_client = TEST_CLIENT.copy()
        test_client2 = TEST_CLIENT.copy()
        test_client2['client_id'] = 'test_client2_id'
        test_client2['client_secret'] = 'test_client2_secret'
        test_client3 = TEST_CLIENT.copy()
        test_client3['client_id'] = 'test_client3_id'
        test_client3['client_secret'] = 'test_client3_secret'

        # creating 1 client with different username
        test_client_diff_ursername = TEST_CLIENT.copy()
        # test_client_diff_ursername['username'] = 'test_diff_username'
        test_client_diff_ursername['client_id'] = 'test_diff_username_client_id',
        test_client_diff_ursername['client_secret'] = 'test_diff_username_client_secret'

        user = _insert_test_user(TEST_USER)
        test_another_user = TEST_USER.copy()
        test_another_user['uuid'] = 'another_uuid'
        test_another_user['username'] = 'another_username'
        another_user = _insert_test_user(test_another_user)

        # adding same user to clients data
        test_client['user'] = user
        test_client2['user'] = user
        test_client3['user'] = user

        # inserting clients with same user
        _insert_test_client(test_client)
        _insert_test_client(test_client2)
        _insert_test_client(test_client3)

        # add client with different user
        # FIXME: gradually support no user for client with diff user
        # FIXME: deny client creation
        test_client_diff_ursername['user'] = another_user
        _insert_test_client(test_client_diff_ursername)

        result_clients = self.clients_dao.getAllClientsByUserName(TEST_USERNAME)
        self.assertEqual(len(result_clients), 3)

        # verify each selected client has expected username
        for client in result_clients:
            self.assertEqual(client.user.username, TEST_USERNAME)

    def test_client_by_id(self):
        """Test Select Client by id"""
        # inserting user in DB
        test_user = _insert_test_user(TEST_USER)

        # creating clients data
        test_client = TEST_CLIENT.copy()
        test_client['user'] = test_user
        test_client2 = TEST_CLIENT.copy()
        test_client2['client_id'] = 'test_client2_id'
        test_client2['user'] = test_user

        _insert_test_client(test_client)
        _insert_test_client(test_client2)

        result_client = self.clients_dao.getClientByClientId(client_id=TEST_CLIENT_ID)
        self.assertIsNotNone(result_client)
        # verify that selected client has expected client_id
        self.assertEqual(result_client['client_id'], TEST_CLIENT_ID)

    def test_get_register_client_dynamically(self):
        """Test for a simple save of a client"""
        # inserting user into DB
        test_user = _insert_test_user(TEST_USER)

        client = self.clients_dao.getRegisterClientDynamically(user=test_user, content=TEST_CLIENT, expire=35000)

        selected_clients = Client.objects.all()
        self.assertEqual(len(selected_clients), 1)
        selected_client = selected_clients[0]
        self.assertEqual(client, selected_client)

    def test_save_client(self):
        """Test Save Client"""
        # inserting user into DB
        test_user = _insert_test_user(TEST_USER)

        result_client = self.clients_dao.saveClient(user=test_user, dic=TEST_CLIENT)

        selected_clients = Client.objects.all()
        self.assertEqual(len(selected_clients), 1)
        selected_client = selected_clients[0]
        self.assertEqual(selected_client, result_client)

        # Test inserting same data again:

        result_client = self.clients_dao.saveClient(user=test_user, dic=TEST_CLIENT)
        # print(mongo_object_to_dict(result_client))
        selected_clients = Client.objects.all()
        self.assertEqual(len(selected_clients), 1)
        selected_client = selected_clients[0]
        # FIXME: saveClient() when trying to insert same data creates a client model object
        # FIXME: and returns it, not the one that is actually in database
        self.assertNotEqual(selected_client, result_client)

    @unittest.expectedFailure
    def test_update_client(self):
        """Test Update Client"""
        # inserting user into DB
        test_user = _insert_test_user(TEST_USER)

        # creating client data
        test_client = TEST_CLIENT.copy()
        test_client['user'] = test_user

        # inserting client into DB
        client = _insert_test_client(test_client)

        selected_clients_before_update = Client.objects.all()
        self.assertEqual(len(selected_clients_before_update), 1)

        test_client['name'] = 'test_different_name'
        test_client['response_type'] = 'test_different_response_type'

        # FIXME: return client is old, not updated
        res_client = self.clients_dao.updateClient(
            client_id=test_client['client_id'],
            name=test_client['name'],
            response_type=test_client['response_type'],
            redirect_uris=test_client['redirect_uris'],
            default_scopes=test_client['default_scopes'],
            jwt_alg=test_client['jwt_alg']
        )

        selected_clients_after_update = Client.objects.all()
        self.assertEqual(len(selected_clients_after_update), 1)
        selected_client = selected_clients_after_update[0]
        self.assertEqual(selected_client.client_name, 'test_different_name')
        self.assertEqual(selected_client.response_type, 'test_different_response_type')
        self.assertEqual(selected_client.default_scopes, client.default_scopes)




class TestCodeDao(TestBase):
    """Test Suit for CodeDao class"""

    def setUp(self):
        self.codes_dao = dao.CodeDao()

    def tearDown(self):
        Code.objects.delete()
        self.assertFalse(Code.objects.all())
        MagenUser.objects.delete()
        self.assertFalse(MagenUser.objects.all())
        Client.objects.delete()
        self.assertFalse(Client.objects.all())

    def test_get_all_codes(self):
        """Test Selection of All codes from DB"""
        # Selecting Codes on Empty set
        self.assertFalse(self.codes_dao.getAllCodes())

        test_user = _insert_test_user(TEST_USER)
        test_client_data = TEST_CLIENT.copy()
        test_client_data['user'] = test_user
        test_client = _insert_test_client(test_client_data)
        # October 18th 2017
        expire_time = datetime.datetime.utcfromtimestamp(
            datetime.datetime(2017, 10, 18, 19, 43, 42, 352000).timestamp())

        test_code_data = TEST_CODE.copy()
        test_code_data['user'] = test_user
        test_code_data['client'] = test_client
        test_code_data['expires'] = expire_time

        # insert code into DB
        _insert_test_code(test_code_data)

        selected_codes = self.codes_dao.getAllCodes()
        self.assertEqual(len(selected_codes), 1)
        selected_code = selected_codes[0]
        self.assertEqual(selected_code.code, 'test_code')
        self.assertEqual(selected_code.nonce, 'test_nonce')
        self.assertEqual(selected_code.is_authentication, True)
        self.assertEqual(selected_code.code_challenge, 'test_code_challenge')
        self.assertEqual(selected_code.code_challenge_method, 'test_code_challenge_method')
        self.assertEqual(selected_code.user, test_user)
        self.assertEqual(selected_code.client, test_client)
        self.assertEqual(selected_code.expires, expire_time)
        self.assertEqual(selected_code.scopes, 'test_scopes')

    @unittest.expectedFailure
    def test_get_code_by_code(self):
        """Test Selection of code by PK"""
        test_user = _insert_test_user(TEST_USER)
        test_client_data = TEST_CLIENT.copy()
        test_client_data['user'] = test_user
        test_client = _insert_test_client(test_client_data)
        # October 18th 2017
        expire_time = datetime.datetime.utcfromtimestamp(
            datetime.datetime(2017, 10, 18, 19, 43, 42, 352000).timestamp())

        test_code_data = TEST_CODE.copy()
        test_code_data['user'] = test_user
        test_code_data['client'] = test_client
        test_code_data['expires'] = expire_time

        # insert code into DB
        _insert_test_code(test_code_data)

        test_code_data['code'] = 'test_another_code'
        test_code_data['nonce'] = 'test_another_nonce'

        # insert another code into DB
        _insert_test_code(test_code_data)

        # Select code by code
        selected_code = self.codes_dao.getCodeByCode(code='test_code')
        self.assertIsNotNone(selected_code)
        self.assertEqual(selected_code.code, 'test_code')
        self.assertEqual(selected_code.nonce, 'test_nonce')

        # FIXME: This causes Failure
        non_existing_code = self.codes_dao.getCodeByCode(code='test_code_not_exist')
        self.assertIsNone(non_existing_code)

    def test_delete_code(self):
        """Test Deletion a code from DB"""
        test_user = _insert_test_user(TEST_USER)
        test_client_data = TEST_CLIENT.copy()
        test_client_data['user'] = test_user
        test_client = _insert_test_client(test_client_data)
        # October 18th 2017
        expire_time = datetime.datetime.utcfromtimestamp(
            datetime.datetime(2017, 10, 18, 19, 43, 42, 352000).timestamp())

        test_code_data = TEST_CODE.copy()
        test_code_data['user'] = test_user
        test_code_data['client'] = test_client
        test_code_data['expires'] = expire_time

        # insert code into DB
        test_code = _insert_test_code(test_code_data)

        # verify that code is in DB
        selected_codes = Code.objects.all()
        self.assertEqual(len(selected_codes), 1)

        # removing inserted code
        self.codes_dao.deleteCode(test_code)
        # verify that code is not longer in DB
        self.assertFalse(Code.objects.all())

        # removing of non-existing code has no effect
        self.codes_dao.deleteCode(test_code)
        # verify that Code collection is still empty
        self.assertFalse(Code.objects.all())


class TestGrantDao(TestBase):
    """Test suit for GrantDao class"""

    def setUp(self):
        self.grants_dao = dao.GrantDao()

    def tearDown(self):
        Grant.objects.delete()
        self.assertFalse(Grant.objects.all())
        Code.objects.delete()
        self.assertFalse(Code.objects.all())
        MagenUser.objects.delete()
        self.assertFalse(MagenUser.objects.all())
        Client.objects.delete()
        self.assertFalse(Client.objects.all())

    def test_get_all_grants(self):
        """Test Selection of All grants"""
        # Selecting Grants on Empty set
        self.assertFalse(self.grants_dao.getAllGrants())

        # Inserting user and client
        test_user = _insert_test_user(TEST_USER)
        test_client_data = TEST_CLIENT.copy()
        test_client_data.update(user=test_user)
        test_client = _insert_test_client(test_client_data)
        # Inserting code
        # October 18th 2017
        expire_time = datetime.datetime.utcfromtimestamp(
            datetime.datetime(2017, 10, 18, 19, 43, 42, 352000).timestamp())
        test_code_data = TEST_CODE.copy()
        test_code_data['user'] = test_user
        test_code_data['client'] = test_client
        test_code_data['expires'] = expire_time
        test_code = _insert_test_code(test_code_data)

        # Inserting Grant
        test_grant_data = dict(
            code=test_code,
            redirect_uri='test_redirect_uri',
            user=test_user,
            client=test_client,
            expires=expire_time,
            scopes='test_scopes'  # should be a list, but not regulated yet
        )
        _insert_test_grant(test_grant_data)

        # Select from DB
        selected_grants = self.grants_dao.getAllGrants()
        self.assertEqual(len(selected_grants), 1)
        selected_grant = selected_grants[0]
        self.assertEqual(selected_grant.code, test_code)
        self.assertEqual(selected_grant.user, test_user)
        self.assertEqual(selected_grant.client, test_client)
        self.assertEqual(selected_grant.expires, expire_time)
        self.assertEqual(selected_grant.scopes, 'test_scopes')

    @unittest.expectedFailure
    def test_get_grant_by_client_and_code(self):
        """Test Selection of Grant by client_id and code fields"""
        # Inserting user and client
        test_user = _insert_test_user(TEST_USER)
        test_client_data = TEST_CLIENT.copy()
        test_client_data.update(user=test_user)
        test_client = _insert_test_client(test_client_data)
        # Inserting code
        # October 18th 2017
        expire_time = datetime.datetime.utcfromtimestamp(
            datetime.datetime(2017, 10, 18, 19, 43, 42, 352000).timestamp())
        test_code_data = TEST_CODE.copy()
        test_code_data['user'] = test_user
        test_code_data['client'] = test_client
        test_code_data['expires'] = expire_time
        test_code = _insert_test_code(test_code_data)

        # Inserting Grant
        test_grant_data = dict(
            code=test_code,
            redirect_uri='test_redirect_uri',
            user=test_user,
            client=test_client,
            expires=expire_time,
            scopes='test_scopes'  # should be a list, but not regulated yet
        )
        _insert_test_grant(test_grant_data)

        # Select from DB
        selected_grant = self.grants_dao.getGrantByClientIdAndCode(client_id=test_client.client_id, code=test_code)
        self.assertIsNotNone(selected_grant)
        self.assertEqual(selected_grant.code, test_code)
        self.assertEqual(selected_grant.client, test_client)
        self.assertEqual(selected_grant.user, test_user)

        # FIXME: This causes Failure
        # Select not-existing Grant from DB
        not_existing_grant = self.grants_dao.getGrantByClientIdAndCode(client_id='some_id', code=test_code)
        self.assertIsNone(not_existing_grant)


class TestTokenDao(TestBase):
    """Test Suit TokenDao class"""

    def setUp(self):
        self.tokens_dao = dao.TokenDao()

    def tearDown(self):
        Token.objects.delete()
        self.assertFalse(Token.objects.all())
        MagenUser.objects.delete()
        self.assertFalse(MagenUser.objects.all())
        Client.objects.delete()
        self.assertFalse(Client.objects.all())

    def test_get_all_tokens(self):
        """Test Selection of tokens from DB"""
        # Selecting Tokens on Empty set
        self.assertFalse(Token.objects.all())

        # inserting user and client
        test_user = _insert_test_user(TEST_USER)
        test_client_data = TEST_CLIENT.copy()
        test_client_data.update(user=test_user)
        test_client = _insert_test_client(test_client_data)

        test_token_data = TEST_TOKEN.copy()
        test_token_data.update(user=test_user)
        test_token_data.update(client=test_client)  # user is in client too
        test_token = _insert_test_token(test_token_data)

        selected_tokens = self.tokens_dao.getAllTokens()
        self.assertEqual(len(selected_tokens), 1)
        selected_token = selected_tokens[0]
        self.assertEqual(selected_token, test_token)

    def test_save_token(self):
        """Test Insert Token in DB"""
        # Inserting client and user
        test_user = _insert_test_user(TEST_USER)
        test_client_data = TEST_CLIENT.copy()
        test_client_data.update(user=test_user)
        test_client = _insert_test_client(test_client_data)

        self.tokens_dao.saveToken(
            user=test_user,
            client=test_client,
            access_token='test_access_token',
            refresh_token='test_refresh_token',
            _id_token='test_id_token',
            encoded_token='test_encoded_token',
            _scopes='test_scopes',
            expire=36000,
            magen_client_id='test_mc_id'
        )

        test_tokens = Token.objects.all()
        self.assertEqual(len(test_tokens), 1)
        test_token = test_tokens[0]
        self.assertEqual(test_token.user, test_user)
        self.assertEqual(test_token.client, test_client)
        self.assertEqual(test_token.refresh_token, 'test_refresh_token')

        # Inserting same document again
        self.tokens_dao.saveToken(
            user=test_user,
            client=test_client,
            access_token='test_access_token',
            refresh_token='test_refresh_token',
            _id_token='test_id_token',
            encoded_token='test_encoded_token',
            _scopes='test_scopes',
            expire=36000,
            magen_client_id='test_mc_id'
        )

        test_tokens = Token.objects.all()
        self.assertEqual(len(test_tokens), 1)
        test_token = test_tokens[0]
        self.assertEqual(test_token.user, test_user)
        self.assertEqual(test_token.client, test_client)
        self.assertEqual(test_token.refresh_token, 'test_refresh_token')
