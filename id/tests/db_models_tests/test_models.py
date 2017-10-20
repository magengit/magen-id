# coding=utf-8
"""Test for Magen ID DB Models"""

import unittest
import mongoengine
# from mongoengine.connection import register_connection, disconnect
import mongoengine.connection as mongo_connection

from magen_utils_apis import domain_resolver
from id.id_service.magenid.idsapp.idsserver.lib.db.models.magen_client_models import MagenClient, MagenUser, MagenGroup
from id.id_service.magenid.idsapp.idsserver.lib.db.models.models import Role, Domain, Client, Code, Grant, Token, Service, ExtIdp, RSAKey


def mongo_object_to_dict(mongo_object):
    """Get dictionary from mongo object"""
    data_dict = dict()
    for item in mongo_object._data:
        data_dict[item] = mongo_object._data[item]
    del data_dict['id']
    return data_dict


class TestClientModels(unittest.TestCase):
    """
    Test Suit for mongo client models using mongoengine
    Before running make sure have mongo_db running on the host
    """
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

    def tearDown(self):
        MagenClient.objects.delete()
        MagenUser.objects.delete()
        MagenGroup.objects.delete()
        self.assertFalse(MagenClient.objects.all())
        self.assertFalse(MagenUser.objects.all())
        self.assertFalse(MagenGroup.objects.all())

    @classmethod
    def tearDownClass(cls):
        cls.test_db.drop_database('test_id_db')
        mongo_connection.disconnect('test_id_db')

    def test_empty_set(self):
        """Magen Client, User, Group select on empty set"""
        clients = MagenClient.objects.all()
        users = MagenUser.objects.all()
        groups = MagenGroup.objects.all()
        self.assertEqual(len(clients), 0)
        self.assertEqual(len(users), 0)
        self.assertEqual(len(groups), 0)

    def test_magen_client(self):
        """Saving and retrieving correct client"""
        client = MagenClient()
        client.mc_id = 'test_mc_id'
        client.user = 'test_user'
        client.device_id = 'test_device_id'
        client.ip = 'test_ip'
        client.mac = 'test_mac'
        client.revision = 'test_revision'

        # throws exception if requirements for values are not satisfied (from Document class)
        client.save(validate=True)
        clients = MagenClient.objects.all()
        self.assertEqual(len(clients), 1)
        client_dict = mongo_object_to_dict(clients[0])
        for key in client_dict:
            self.assertIn('test', client_dict[key])

    def test_magen_client_fail(self):
        """Validation Failed for client document"""
        client = MagenClient()
        # mc_id is missing
        # string longer then 200 chars
        client.user = 'test_user test_user test_user test_user test_user test_user ' \
                      'test_user test_user test_user test_user test_user test_user ' \
                      'test_user test_user test_user test_user test_user test_user ' \
                      'test_user test_user test_user test_user '
        client.device_id = 'test_device_id'
        client.ip = 'test_ip'
        client.mac = 'test_mac'
        client.revision = 'test_revision'

        with self.assertRaises(mongoengine.errors.ValidationError) as err:
            client.save(validate=True)
        self.assertIn('mc_id', err.exception.errors)
        self.assertIn('user', err.exception.errors)

    def test_magen_user(self):
        """Saving and retrieving correct user"""
        user = MagenUser()
        user.uuid = 'test_uuid'
        user.username = 'test_username'
        user.first_name = 'test_first_name'
        user.last_name = 'test_first_name'
        user.password = 'test_password'
        user.email = 'test_email'
        user.email_verified = True
        # accepting default parameters for last_login and registered_on
        user.role = 'test_role'
        user.idp = 'test_idp'
        user.department = 'test_departament'
        user.photo = 'test_photo'  # link to avatar
        user.local = 'test_local'
        user.position = 'test_position'
        user.u_groups = ['test_group1', 'test_group2']
        user.u_clients = list()
        user.display_name = 'test_display_name'

        user.save(validate=True)
        users = MagenUser.objects.all()
        self.assertEqual(len(users), 1)
        user_dict = mongo_object_to_dict(users[0])
        except_keys = ['email_verified', 'last_login', 'registered_on', 'u_groups', 'u_clients']
        for key in user_dict:
            if key not in except_keys:
                self.assertIn('test', user_dict[key])

        self.assertEqual(len(user_dict['u_groups']), 2)

    def test_magen_user_fail(self):
        """Validation Failed for user document"""
        user = MagenUser()
        # uuid is missing
        user.username = 'test_username'
        user.first_name = 'test_first_name'
        user.last_name = 'test_first_name'
        user.password = 'test_password'
        user.email = 'test_email'
        user.email_verified = True
        # accepting default parameters for last_login and registered_on
        user.role = 'test_role test_role test_role test_role'  # longer then 10 chars
        user.idp = 'test_idp'
        user.department = 'test_departament'
        user.photo = 'test_photo'  # link to avatar
        user.local = 'test_local'
        user.position = 'test_position'
        user.u_groups = ['test_group1', 'test_group2']
        user.u_clients = list()
        user.display_name = 'test_display_name'

        with self.assertRaises(mongoengine.errors.ValidationError) as err:
            user.save(validate=True)
        self.assertIn('uuid', err.exception.errors)
        self.assertIn('role', err.exception.errors)

    def test_magen_group(self):
        """"Saving and retrieving correct group"""
        group = MagenGroup()
        group.ug_name = 'test_ug_name'
        group.ug_id = 1351

        group.save(validate=True)
        groups = MagenGroup.objects.all()
        self.assertEqual(len(groups), 1)
        group_dict = mongo_object_to_dict(groups[0])
        self.assertIn('test', group_dict['ug_name'])
        self.assertEquals(group.ug_id, group_dict['ug_id'])

    def test_magen_group_fail(self):
        """Validation Failed for group document"""
        group = MagenGroup()
        # mc_id is missing
        group.ug_id = 1351

        with self.assertRaises(mongoengine.errors.ValidationError) as err:
            group.save(validate=True)
        self.assertIn('ug_name', err.exception.errors)


class TestIDModels(unittest.TestCase):
    """
    Test Suit for mongo models using mongoengine
    Before running make sure have mongo_db running on the host
    """

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
        Role.objects.delete()
        Domain.objects.delete()
        Client.objects.delete()
        Code.objects.delete()
        Grant.objects.delete()
        Token.objects.delete()
        Service.objects.delete()
        ExtIdp.objects.delete()
        RSAKey.objects.delete()

    def tearDown(self):
        Role.objects.delete()
        Domain.objects.delete()
        Client.objects.delete()
        Code.objects.delete()
        Grant.objects.delete()
        Token.objects.delete()
        Service.objects.delete()
        ExtIdp.objects.delete()
        RSAKey.objects.delete()
        self.assertFalse(Role.objects.all())
        self.assertFalse(Domain.objects.all())
        self.assertFalse(Client.objects.all())
        self.assertFalse(Code.objects.all())
        self.assertFalse(Grant.objects.all())
        self.assertFalse(Token.objects.all())
        self.assertFalse(Service.objects.all())
        self.assertFalse(ExtIdp.objects.all())
        self.assertFalse(RSAKey.objects.all())

    @classmethod
    def tearDownClass(cls):
        cls.test_db.drop_database('test_id_db')
        mongo_connection.disconnect('test_id_db')

    def test_empty(self):
        domains = Domain.objects.all()
        clients = Client.objects.all()
        codes = Code.objects.all()
        grants = Grant.objects.all()
        tokens = Token.objects.all()
        services = Service.objects.all()
        ext_idps = ExtIdp.objects.all()
        rsa_keys = RSAKey.objects.all()
        self.assertEqual(len(domains), 0)
        self.assertEqual(len(clients), 0)
        self.assertEqual(len(codes), 0)
        self.assertEqual(len(grants), 0)
        self.assertEqual(len(tokens), 0)
        self.assertEqual(len(services), 0)
        self.assertEqual(len(ext_idps), 0)
        self.assertEqual(len(rsa_keys), 0)

    def test_role(self):
        """Saving and retrieving correct role"""
        role = Role()
        role.role = 'test_role'

        # throws exception if requirements for values are not satisfied (from Document class)
        role.save(validate=True)
        roles = Role.objects.all()
        self.assertEqual(len(roles), 1)
        role_dict = mongo_object_to_dict(roles[0])
        for key in role_dict:
            self.assertIn('test', role_dict[key])

    def test_domain(self):
        """Saving and retrieving correct domain"""
        domain = Domain()
        domain.name = 'test_name'
        domain.idp = 'test_idp'
        domain.allow = True

        # throws exception if requirements for values are not satisfied (from Document class)
        domain.save(validate=True)
        domains = Domain.objects.all()
        self.assertEqual(len(domains), 1)
        domain_dict = mongo_object_to_dict(domains[0])
        self.assertIn('test', domain_dict['name'])
        self.assertIn('test', domain_dict['idp'])

    def test_client(self):
        """Saving and retrieving correct client"""
        client = Client()
        client.client_id = 'test_id'
        client.client_name = 'test_name'
        client.client_secret = 'test_client_secret'
        client.response_type = 'test_response_type'
        client.redirect_uris = 'test_redirect_uris'
        client.default_scopes = 'test_default_scopes'
        # etc ... all fields

        # throws exception if requirements for values are not satisfied (from Document class)
        client.save(validate=True)
        clients = Client.objects.all()
        self.assertEqual(len(clients), 1)
        client_dict = mongo_object_to_dict(clients[0])
        self.assertIn('test', client_dict['client_id'])
        self.assertIn('test', client_dict['client_name'])
        # not assigned field got created
        self.assertIn('subject_type', client_dict)
        self.assertIn('mac', client_dict)

        self.assertEqual(client.client_type, 'public')

    def test_code(self):
        """Saving and retrieving correct code"""
        code = Code()
        code.code = 'test_code'
        code.nonce = 'test_nonce'
        code.is_authentication = True
        code.code_challenge = 'test_code_challenge'
        code.code_challenge_method = 'test_code_challenge_method'
        code.scopes = 'test_scopes'

        # throws exception if requirements for values are not satisfied (from Document class)
        code.save(validate=True)
        codes = Code.objects.all()
        self.assertEqual(len(codes), 1)
        code_dict = mongo_object_to_dict(codes[0])
        self.assertIn('test', code_dict['code'])
        self.assertIn('test', code_dict['nonce'])
        self.assertIn('test', code_dict['code_challenge'])
        # not assigned field got created
        self.assertIn('user', code_dict)
        self.assertIn('client', code_dict)

        self.assertFalse(code.has_expired())

    def test_grant(self):
        """Saving and retrieving correct grant"""
        grant = Grant()
        grant.redirect_uri = 'test_redirect_uri'
        grant.scopes = 'test_scopes'

        # throws exception if requirements for values are not satisfied (from Document class)
        grant.save(validate=True)
        grants = Grant.objects.all()
        self.assertEqual(len(grants), 1)
        grant_dict = mongo_object_to_dict(grants[0])
        self.assertIn('test', grant_dict['redirect_uri'])
        self.assertIn('test', grant_dict['scopes'])
        # not assigned field got created
        self.assertIn('user', grant_dict)
        self.assertIn('client', grant_dict)

    def test_token(self):
        """Saving and retrieving correct token"""
        token = Token()
        token.access_token = 'test_access_token'
        token.refresh_token = 'test_refresh_token'
        token.id_token = 'test_id_token'
        token.encoded_token = 'test_encoded_token'
        token.scopes = 'test_scopes'
        token.mc_id = 'test_mc_id'

        # throws exception if requirements for values are not satisfied (from Document class)
        token.save(validate=True)
        tokens = Token.objects.all()
        self.assertEqual(len(tokens), 1)
        token_dict = mongo_object_to_dict(tokens[0])
        self.assertIn('test', token_dict['access_token'])
        self.assertIn('test', token_dict['refresh_token'])
        self.assertIn('test', token_dict['id_token'])
        self.assertIn('test', token_dict['encoded_token'])
        self.assertIn('test', token_dict['scopes'])
        self.assertIn('test', token_dict['mc_id'])
        # not assigned field got created
        self.assertIn('user', token_dict)
        self.assertIn('client', token_dict)
        self.assertIn('expires', token_dict)

    def test_service(self):
        """Saving and retrieving correct service"""
        service = Service()
        service.state = 'test_state'
        service.client_id = 'test_client_id'
        service.response_type = 'test_response_type'
        service.redirect_uri = 'test_redirect_uri'
        service.nonce = 'test_nonce'
        service.default_scopes = 'test_default_scopes'
        service.code_challenge = 'test_code_challenge'
        service.code_challenge_method = 'test_code_challenge_method'
        service.username = 'test_username'
        service.external_token_info = 'test_external_token_info'

        # throws exception if requirements for values are not satisfied (from Document class)
        service.save(validate=True)
        services = Service.objects.all()
        self.assertEqual(len(services), 1)
        service_dict = mongo_object_to_dict(services[0])
        for key in service_dict:
            self.assertIn('test', service_dict[key])

    def test_ext_idp(self):
        """Saving and retrieving correct ext_idp"""
        ext_idp = ExtIdp()
        ext_idp.name = 'test_name'
        ext_idp.desc = 'test_desc'
        ext_idp.client_id = 'test_client_id'
        ext_idp.client_secret = 'test_client_secret'
        ext_idp.authz_url = 'test_authz_url'
        ext_idp.token_url = 'test_token_url'
        ext_idp.token_info_url = 'test_token_info_url'
        ext_idp.user_info_url = 'tests_user_info_url'
        ext_idp.redirect_uri = 'test_redirect_uri'
        ext_idp.scopes = 'test_scopes'
        ext_idp.code_challenge = 'test_code_challenge'
        ext_idp.code_challenge_method = 'test_code_challenge_method'

        # throws exception if requirements for values are not satisfied (from Document class)
        ext_idp.save(validate=True)
        ext_idps = ExtIdp.objects.all()
        self.assertEqual(len(ext_idps), 1)
        ext_idp_dict = mongo_object_to_dict(ext_idps[0])
        for key in ext_idp_dict:
            self.assertIn('test', ext_idp_dict[key])

    def test_rsa_key(self):
        """Saving and retrieving correct rsa_key"""
        rsa_key = RSAKey()
        rsa_key.key = 'test_key'
        self.assertIsInstance(rsa_key.kid, str)
