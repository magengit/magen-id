#! /usr/bin/python3.5

from flask import Flask
import mongoengine as db
import unittest
import sys
import requests
from mongoengine import connect

from id.id_service.magenid.idsapp.idsserver.lib.db.magen_user_dao import *
from magen_rest_apis.rest_client_apis import RestClientApis
from id.id_service.magenid.idsapp.idsserver.lib.db.magen_user_dao import *
from id.id_service.magenid.idsapp.idsserver.utils.utilities import *
from magen_utils_apis.domain_resolver import mongo_host_port

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)

__author__ = "Mizanul Chowdhury"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__license__ = "New-style BSD"
__version__ = "0.1"
__email__ = "michowdh@cisco.com"


d = '''{
    "users": {
        "user": [
            {
                "username": "michowdh@cisco.com",
                "email": "michowdh@cisco.com",
                "department": "dept",
                "first_name":"",
                "last_name":"",
                "role":"",
                "idp":"",
                "email":"michowdh@cisco.com",
                "password":"",
                "position": "user.position",
                "uuid": "986765645546234fdsfwerwerererererer",
                 "u_groups": ["engineer"],
                "u_clients": ["rtrtyrtr676ytyuty67576tyuytyrty5r675"],
                "display_name": "Mizanul Chowdhury"
            }
        ]
    }
}'''

d2 = '''{
    "users": {
        "user": [
            {
                "username": "mizanul3",
                "email": "michowdh@cisco.com",
                "department": "dept3",
                "first_name":"",
                "last_name":"",
                "role":"",
                "idp":"",
                "email":"michowdh@cisco.com",
                "password":"",
                "position": "user.position3",
                "uuid": "32434234234fdsfwerwerewrwqeqwwew",
                 "u_groups": ["development"],
                "u_clients": ["656756rt56r676ytyuty67576tyuytyrty5r675"],
                "display_name": "user.display_name"
            }
        ]
    }
}'''

up_d = '''{
    "users": {
        "user": [
            {
                "username": "mizanul",
                "email": "michowdh@cisco.com",
                "department": "dept2",
                "first_name":"",
                "last_name":"",
                "role":"",
                "idp":"",
                "email":"michowdh@cisco.com",
                "password":"",
                "position": "user.position2",
                "uuid": "986765645546234fdsfwerwerererererer",
                "u_groups": ["engineer","development"],
                "u_clients": ["rtrtyrtr676ytyuty67576tyuytyrty5r675","567ughgdr6ytught76687yiugj6t"],
                "display_name": "Mizanul Chowdhury"
            }
        ]
    }
}'''

headers = {'content-type': 'application/json', 'Accept': 'application/json'}

class MagenIdUserRestTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        mongo_server_ip, mongo_port = mongo_host_port()
        connect(db="magenid", port=mongo_port,host=mongo_server_ip)
        self.server_url = 'http://localhost:5030/'
        self.user_rest_base_url = self.server_url + 'magen/id/v2/users/user/'
        self.db = MagenUserDao()

    def tearDown(self):
        self.db.delete_all()


    def test_delete_user(self):
        r = RestClientApis.http_post_and_check_success(self.user_rest_base_url,d)
        resp_obj = r.json_body
        logger.debug(resp_obj)
        r = RestClientApis.http_delete_and_check_success(self.user_rest_base_url + resp_obj["response"]["uuid"] + "/")

        resp_obj = r.json_body
        self.assertTrue(resp_obj["response"]["success"])
    
    def test_insert_user(self):
        r = RestClientApis.http_post_and_check_success(self.user_rest_base_url,d)
        resp_obj = r.json_body
        self.assertTrue(resp_obj["response"]["success"])

    def test_update_user(self):
        r = RestClientApis.http_post_and_check_success(self.user_rest_base_url,d)

        r = RestClientApis.http_put_and_check_success(self.user_rest_base_url,up_d)
        resp_obj = r.json_body
        self.assertTrue(resp_obj["response"]["success"])


    def test_get_user(self):
        r = RestClientApis.http_post_and_check_success(self.user_rest_base_url,d)
        resp_obj = r.json_body
        r = RestClientApis.http_get_and_check_success(self.user_rest_base_url + resp_obj["response"]["uuid"] + "/")
        resp_obj = r.json_body
        self.assertTrue(resp_obj["response"]["success"])


    def test_get_all_user(self):
        r = RestClientApis.http_post_and_check_success(self.user_rest_base_url,d)
        resp_obj = r.json_body
        r = RestClientApis.http_post_and_check_success(self.user_rest_base_url,d2)
        resp_obj = r.json_body

        r = RestClientApis.http_get_and_check_success(self.server_url +"magen/id/v2/users/")
        resp_obj = r.json_body
        self.assertTrue(resp_obj["response"]["success"])
    


if __name__ == '__main__':
    unittest.main()





