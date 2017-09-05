from flask import Flask
import unittest
import sys
import requests


from id.id_service.magenid.idsapp.idsserver.lib.db.magen_client_dao import *
from id.id_service.magenid.idsapp.idsserver.lib.db.magen_user_dao import *
from magen_rest_apis.rest_client_apis import RestClientApis
from id.id_service.magenid.idsapp.idsserver.utils.utilities import *
from magen_utils_apis.domain_resolver import mongo_host_port

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)

__author__ = "Praveen Hasti, Mizanul Chowdhury"
__copyright__ = "Copyright(c) 2017, Cisco Systems, Inc."
__license__ = "New-style BSD"
__version__ = "0.1"
__email__ = "phasti@cisco.com, michowdhury@cisco.com"

d = '''{
    "clients": {
        "client": [
            {
                "user": "michowdh@cisco.com",
                "revision": "1",
                "device_id": "ipad",
                "mc_id": "",
                "ip": "192.168.1.210",
                "mac": "AA.96.9F.4E.3B.00"
            }
        ]
    }
}'''

d_1 = '''{
    "clients": {
        "client": [
            {
                "user": "michowdh@cisco.com",
                "revision": "2",
                "device_id": "iphone",
                "mc_id": "",
                "ip": "192.168.1.211",
                "mac": "AA.96.9F.4E.3B.01"
            }
        ]
    }
}'''


inv_d = '''{
    "clients": {
        "client": [
            {
                "user": "michowdh@cisco.com",
                "revision": "1",
                "device_id": "ipad",
                "mc_id": "",
                "ip": "192.168.1.210",
                "mac": "AA.96.9F.4E.3B.00"
            }
        ]
    }
}'''

up_inv_d = '''{
    "clients": {
        "client": [
            {
                "user": "michowdh@cisco.com",
                "revision": "1",
                "device_id": "",
                "mc_id": "06a2fdf6-4bb2-4d09-praveen1114444-d8d921232333",
                "ip": "192.168.1.199",
                "mac": "AA.96.9F.4E.3B.00"
            }
        ]
    }
}'''

notify = '''{
        "client":
            {
                "user": "michowdh@cisco.com",
                "revision": "1",
                "device_id": "",
                "mc_id": "06a2fdf6-4bb2-4d09-praveen1114444-d8d921232333",
                "ip": "192.168.1.199",
                "mac": "AA.96.9F.4E.3B.00"
            }

}'''


empty_device_user = '''{
        "client":
            {
                "user": "",
                "revision": "1",
                "device_id": "",
                "mc_id": "06a2fdf6-4bb2-4d09-praveen1114444-d8d921232333",
                "ip": "192.168.1.199",
                "mac": "AA.96.9F.4E.3B.00"
            }

}'''

headers = {'content-type': 'application/json', 'Accept': 'application/json'}

class MagenIdGroupRestTestCase(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        mongo_server_ip, mongo_port = mongo_host_port()
        print("=======MONGO PORT AND HOST=============",mongo_server_ip, mongo_port)
        connect(db="magenid", port=mongo_port,host=mongo_server_ip)
        self.server_url = 'http://localhost:5030/'
        self.client_rest_base_url =self.server_url+'magen/id/v2/clients/client/'
        print(self.client_rest_base_url)
        self.db = MagenClientDao()
        self.magenUserDao = MagenUserDao()
        dic = createUserDictionary("michowdh@cisco.com")
        user = self.magenUserDao.insert(dic)

    def tearDown(self):
        print("")
        self.db.delete_all()
        self.magenUserDao.delete_all()


    def test_insert_client(self):
        r=RestClientApis.http_post_and_check_success(self.client_rest_base_url, d)
        resp_obj = r.json_body
        self.assertTrue(resp_obj["response"]["success"])

    def test_neg_insert_client(self):
        r = RestClientApis.http_post_and_check_success(self.client_rest_base_url,inv_d)
        resp_obj = r.json_body
        logger.debug(resp_obj)
        #self.assertFalse(resp_obj["response"]["success"])

    def test_delete_client(self):
        r=RestClientApis.http_post_and_check_success(self.client_rest_base_url, d)
        resp_obj = r.json_body


        resp_obj = RestClientApis.http_delete_and_check_success(self.client_rest_base_url + resp_obj["response"]["mc_id"] + "/")
        resp_obj = r.json_body
        self.assertTrue(resp_obj["response"]["success"])

    def test_neg_delete_client(self):
        r = RestClientApis.http_delete_and_check_success(self.client_rest_base_url + "7676yutyut66" + "/")
        resp_obj = r.json_body
        logger.debug(resp_obj)
        self.assertFalse(resp_obj["response"]["success"])


    def test_get_all_clients(self):
        r=RestClientApis.http_post_and_check_success(self.client_rest_base_url, d)
        resp_obj = r.json_body
        r = RestClientApis.http_post_and_check_success(self.client_rest_base_url, d_1)
        resp_obj = r.json_body

        r = RestClientApis.http_get_and_check_success(self.server_url + "magen/id/v2/clients/")
        resp_obj_final = r.json_body
        self.assertTrue(len(resp_obj_final["response"]["clients"]["client"])==2)

    def test_get_client(self):
        r=RestClientApis.http_post_and_check_success(self.client_rest_base_url, d)
        resp_obj = r.json_body
        resp_obj = RestClientApis.http_get_and_check_success(self.client_rest_base_url + resp_obj["response"]["mc_id"])
        resp_json = r.json_body
        self.assertTrue(resp_json["response"]["success"])

    def test_neg_get_client(self):
        r = RestClientApis.http_get_and_check_success(self.client_rest_base_url + "67uyuy676y78" + "/")
        resp_obj = r.json_body
        self.assertFalse(resp_obj["response"]["success"])


    def test_update_client(self):
        r=RestClientApis.http_post_and_check_success(self.client_rest_base_url, d)
        resp_obj = r.json_body
        up_d = '''{
            "clients": {
                "client": [
                    {
                        "user": "michowdh@cisco.com",
                        "revision": "1",
                        "device_id": "ipad",
                        "mc_id": "''' + resp_obj["response"]["mc_id"] + ''''",
                        "ip": "192.168.1.234",
                        "mac": "AA.96.9F.4E.3B.00"
                    }
                ]
            }
        }'''

        resp_obj = RestClientApis.http_put_and_check_success(self.client_rest_base_url,up_d)
        resp_obj = r.json_body
        self.assertTrue(resp_obj["response"]["success"])


    def test_neg_update_client(self):
        r=RestClientApis.http_post_and_check_success(self.client_rest_base_url, d)
        resp_obj = r.json_body


        up_d = '''{
            "clients": {
                "client": [
                    {
                        "user": "michowdh@cisco.com",
                        "revision": "1",
                        "device_id": "ipad",
                        "mc_id": "''' + resp_obj["response"]["mc_id"] + ''''",
                        "ip": "192.168.1.234",
                        "mac": "AA.96.9F.4E.3B.00"
                    }
                ]
            }
        }'''

        r = RestClientApis.http_put_and_check_success(self.client_rest_base_url,up_inv_d)
        resp_obj = r.json_body
        logger.debug(resp_obj)
        #self.assertFalse(resp_obj["response"]["success"])

    def test_user_empty(self):
        r=RestClientApis.http_post_and_check_success(self.client_rest_base_url, empty_device_user)
        resp_obj = r.json_body
        #self.assertTrue(resp_obj["response"]["success"])  

if __name__ == '__main__':
    unittest.main()
