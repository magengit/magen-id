import logging
from id.id_service.magenid.idsapp.idsserver.lib.db.magen_client_dao import *
from id.id_service.magenid.idsapp.idsserver.lib.bll.user_api import UserApi
from magen_rest_apis.rest_client_apis import RestClientApis
from id.id_service.magenid.idsapp import ids
from magen_rest_apis.server_urls import ServerUrls

#
# Copyright (c) 2016 Cisco Systems, Inc. and others.  All rights reserved.
#

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "2.0"

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)


class ClientApi(object):
    @staticmethod
    def delete_client(mc_id):
        db = MagenClientDao()
        ret=db.delete_by_mc_id(mc_id)
        if ret:
           return True, "client has been deleted succesfully",None
        else:
           return False, "Client delete operation is failed.",None


    @staticmethod
    def insert_client(client_dict):
        db = MagenClientDao()
        client =db.insert(client_dict)
        logger.debug("====OOOOOOO client ==== %s  ", client.user)
        if client:
           return True, "client has been addedd succesfully",client
        else:
           return False, "client add operation is failed",None

    @staticmethod
    def get_client(mc_id):
        db = MagenClientDao()
        ret_obj= db.get_by_mc_id(mc_id)
        if ret_obj:
           return True, "Client found succesfully",ret_obj
        else:
           return False, "Client not found",None

    @staticmethod
    def get_by_user_and_device_id(user,device_id):
        db = MagenClientDao()
        ret_obj= db.get_by_user_and_device_id(user,device_id)
        if ret_obj:
           return True, "Client found succesfully",ret_obj
        else:
           return False, "Client not found",None

    @staticmethod
    def get_all():
        db = MagenClientDao()
        ret_obj= db.get_all()
        if ret_obj:
           return True, "Clients found succesfully", ret_obj
        else:
           return False, "Clients not found", None

    @staticmethod
    def update_client(client_dic):
        db = MagenClientDao()
        return db.update(client_dic)

    @staticmethod
    def new_client_process(client_dict):
            if(client_dict["mc_id"]==""):
               magen_client_id = get_magen_client_id(str(client_dict["user"]),str(client_dict["device_id"]))
               client_dict["mc_id"]=magen_client_id

            success, message, client = ClientApi.insert_client(client_dict)
            if not success:
                return False, "Failed to insert clients", None
            return True, "Magen Client Id", client.mc_id

    @staticmethod
    def Notify(mode, mc_id):
        server_urls_instance = ServerUrls.get_instance()
        polilcy_url=server_urls_instance.policy_session_url
        if polilcy_url=="":
            return True, "Notified to Mocke Policy Service - Created New", None

        #return True, "Notified Policy Service", None
        success, message,client = ClientApi.get_client(str(mc_id))

        ugroups = []
        json_req_obj =None
        if client:
            logger.debug("client.user   %s", client.user)
            success, message, user = UserApi.get_user_by_name(client.user)
            if success:
               logger.debug("user %s is found ",user.username)

               ugroups=user.u_groups


               logger.debug(polilcy_url)
               if mode == "create":
                 try:
                    _dic = {
                         "user": client.user,
                         "revision": client.revision,
                         "device_id": client.device_id,
                         "mc_id": client.mc_id,
                         "ip": client.ip,
                         "mac": client.mac,
                         "u_groups": ugroups
                      }
                    json_req_obj = {"client": _dic}
                    req_obj=json.dumps(json_req_obj)
                    logger.debug("Send request to Policy Service to [ add ] policy session for this client %s", client.mc_id)
                    resp_obj = RestClientApis.http_post_and_check_success(polilcy_url, req_obj)
                    response_object = resp_obj.json_body
                    logger.debug(response_object)
                    logger.debug("[ Received ] response from Policy Service %s", response_object)
                    if response_object["response"]=="OK":
                        return True, "Notified Policy Service - Created New", None
                    elif response_object["response"] == "Already exists":
                        return True, "Notified Policy Service - Already exists", None
                    else:
                        return False, "Failed to notify Policy Service", None
                 except Exception as e:
                   logging.exception(e)
                   return False, "Failed to notify Policy Service", None

               else:
                 logger.debug("Send request to Policy Service to [ delete ] policy session for this client %s", client.mc_id)
                 resp_obj = RestClientApis.http_delete_and_check_success(polilcy_url + client.mc_id + "/")
                 response_object = resp_obj.json_body
                 logger.debug(response_object)

                 if response_object["response"]=="Success":
                     return True, "Notified Policy Service", None
                 else:
                     return False, "Failed to notify Policy Service", None

        else:
            return False, "Failed to notify Policy Service-no client", None