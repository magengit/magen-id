#! /usr/bin/python3.5

from flask import Flask
import unittest
import sys
import requests
from mongoengine import connect

from id.id_service.magenid.idsapp.idsserver.lib.db.magen_group_dao import *
from magen_rest_apis.rest_client_apis import RestClientApis
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
    "groups": {
        "group": [
            {
                "ug_name": "engineering",
                "ug_id": 1
            }
        ]
    }
}'''

d2 = '''{
    "groups": {
        "group": [
            {
                "ug_name": "marketing",
                "ug_id": 2
            }
        ]
    }
}'''

up_d = '''{
    "groups": {
        "group": [
            {
                "ug_name": "engineering",
                "ug_id": 3
            }
        ]
    }
}'''
headers = {'content-type': 'application/json', 'Accept': 'application/json'}


class MagenIdGroupRestTestCase(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        mongo_server_ip, mongo_port = mongo_host_port()
        connect(db="magenid", port=mongo_port,host=mongo_server_ip)
        self.server_url = 'http://localhost:5030/'
        self.group_rest_base_url =self.server_url+'magen/id/v2/groups/group/'
        self.magenGroupDao = MagenGroupDao()
        ret = self.magenGroupDao.delete_all()

    def tearDown(self):
        print("")
        self.magenGroupDao.delete_all()

    def test_delete_group(self):
        logger.debug(self.group_rest_base_url)
        r=RestClientApis.http_post_and_check_success(self.group_rest_base_url, d)
        logger.debug(r)
        resp_obj = r.json_body
        logger.debug(self.group_rest_base_url + resp_obj["response"]["ug_name"] + "/")

        r2 = RestClientApis.http_delete_and_check_success(self.group_rest_base_url + resp_obj["response"]["ug_name"] + "/")
        resp_obj2 = r2.json_body
        logger.debug(resp_obj2)
        self.assertTrue(resp_obj2["response"]["success"])

    def test_insert_group(self):
        r=RestClientApis.http_post_and_check_success(self.group_rest_base_url, d)
        resp_obj = r.json_body
        self.assertTrue(resp_obj["response"]["success"])

    def test_get_all_group(self):
        r=RestClientApis.http_post_and_check_success(self.group_rest_base_url, d)
        resp_obj = r.json_body
        r = RestClientApis.http_post_and_check_success(self.group_rest_base_url, d2)
        resp_obj = r.json_body

        r = RestClientApis.http_get_and_check_success(self.server_url + "magen/id/v2/groups/")
        resp_obj = r.json_body
        self.assertTrue(resp_obj["response"]["success"])


    def test_get_group(self):
        r=RestClientApis.http_post_and_check_success(self.group_rest_base_url, d)
        resp_obj = r.json_body
        r = RestClientApis.http_get_and_check_success(self.group_rest_base_url + resp_obj["response"]["ug_name"])
        resp_obj = r.json_body
        self.assertTrue(resp_obj["response"]["success"])


    def test_update_group(self):
        r=RestClientApis.http_post_and_check_success(self.group_rest_base_url, d)
        resp_obj = r.json_body

        r = RestClientApis.http_put_and_check_success(self.group_rest_base_url,up_d)
        resp_obj = r.json_body
        self.assertTrue(resp_obj["response"]["success"])



if __name__ == '__main__':
    unittest.main()




