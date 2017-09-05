from http import HTTPStatus

from datadog.api.exceptions import ApiNotInitialized
from id.id_service.magenid.idsapp.idsserver.lib.bll.client_api import ClientApi
from id.id_service.magenid.idsapp.idsserver.lib.bll.user_api import UserApi
from id.id_service.magenid.idsapp.idsserver.views.home import *
from magen_rest_apis.rest_server_apis import RestServerApis
from magen_logger.logger_config import LogDefaults

from id.id_service.magenid.idsapp.idsserver.utils.dd_events import DDIdentityEventsWrapper

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"


#
# Clients APIs
#

# magen_id_client_rest_api(2015-12-07)
#         get /magen/id/v2/clients/
#         get /magen/id/v2/clients/client/{mc_id}/
#         post /magen/id/v2/clients/client/
#         put /magen/id/v2/clients/client/{mc_id}/
#         delete /magen/id/v2/clients/client/{mc_id}/

@ids.route('/magen/id/v2/clients/client/', methods=["POST"])
def add_magen_client():
    client_list = []
    event_title = "Magen Client Creation Request"
    client_action = 'create'
    logger = logging.getLogger(LogDefaults.default_log_name)

    id_events = DDIdentityEventsWrapper(app_name='identity', magen_logger=logger)

    success = False
    response = None
    try:
        client_dict = request.json["clients"]["client"][0]
        logger.debug("remote ip address: %s ", request.remote_addr)
        logger.debug("remote mac address: %s ", mac_for_ip(request.remote_addr))
        if client_dict["user"] == "":
            result = dict(
                success=False,
                clients=[],
                cause="Please provide user name"
            )
            try:
                id_events.send_event(
                    event_name=event_title,
                    event_data=DDIdentityEventsWrapper.construct_event(client_dict, **result, action=client_action),
                    alert='warning'
                )
            except ApiNotInitialized:
                pass
            return RestServerApis.respond(HTTPStatus.BAD_REQUEST, event_title, {
                    "success": False, "cause": "Please provide user name"})

        if client_dict["device_id"] == "":
            result = dict(
                success=False,
                clients=[],
                cause="Please provide device_id"
            )
            try:
                id_events.send_event(
                    event_name=event_title,
                    event_data=DDIdentityEventsWrapper.construct_event(client_dict, **result, action=client_action),
                    alert='warning'
                )
            except ApiNotInitialized:
                pass

            return RestServerApis.respond(HTTPStatus.BAD_REQUEST, event_title, {
                    "success": False, "cause": "Please provide device_id"})

        
        new_success, new_message, mc_id = ClientApi.new_client_process(client_dict)
        logger.debug("testing insert======")
        if new_success:
            logger.debug(request.url)
            
            n_success, n_message, n_response = ClientApi.Notify("create", mc_id)

            
            if n_success:

                kwargs_dict = dict(
                    success=new_success,
                    cause=new_message,
                    mc_id=mc_id
                )
                try:
                    id_events.send_event(
                        event_name=event_title,
                        event_data=DDIdentityEventsWrapper.construct_event(
                            client_dict,
                            **kwargs_dict,
                            action=client_action),
                        alert='success'
                    )
                except ApiNotInitialized:
                    pass

                http_response = RestServerApis.respond(HTTPStatus.CREATED, event_title, {
                    "success": new_success, "cause": "Created and Notified Policy Service", "mc_id": mc_id})
                http_response.headers['location'] = str(request.url + mc_id + '/')
                return http_response
            else:
                kwargs_dict = dict(
                    success=new_success,
                    cause=new_message,
                    mc_id=mc_id
                )
                try:
                    id_events.send_event(
                        event_name=event_title,
                        event_data=DDIdentityEventsWrapper.construct_event(
                            client_dict,
                            **kwargs_dict,
                            action=client_action),
                        alert='warning'
                    )
                except ApiNotInitialized:
                    pass

                http_response = RestServerApis.respond(HTTPStatus.CREATED, event_title, {
                    "success": new_success, "cause": "Created but Notified Policy Service failed", "mc_id": mc_id})
                http_response.headers['location'] = str(request.url + mc_id + '/')
                return http_response    

        else:
            raise ValueError

    except KeyError:
        kwargs_dict = dict(
            success=success,
            cause=HTTPStatus.BAD_REQUEST.phrase,
            mc_id=None
        )
        try:
            id_events.send_event(
                event_name=event_title,
                event_data=DDIdentityEventsWrapper.construct_event(
                    kwargs_dict,
                    action=client_action),
                alert='warning'
            )
        except ApiNotInitialized:
            pass
        return RestServerApis.respond(HTTPStatus.BAD_REQUEST,
                                      event_title,
                                      {"success": False, "cause": HTTPStatus.BAD_REQUEST.phrase,
                                       "mc_id": None})
    except ValueError:
        kwargs_dict = dict(
            success=success,
            cause=response,
            mc_id=None
        )
        try:
            id_events.send_event(
                event_name=event_title,
                event_data=DDIdentityEventsWrapper.construct_event(
                    kwargs_dict,
                    action=client_action),
                alert='warning'
            )
        except ApiNotInitialized:
            pass
        return RestServerApis.respond(HTTPStatus.BAD_REQUEST,
                                      event_title,
                                      {"success": success, "cause": response, "mc_id": None})


@ids.route('/magen/id/v2/clients/client/<mc_id>/', methods=["GET"])
def get_magen_client(mc_id):
    success, message, client = ClientApi.get_client(str(mc_id))
    client_list = []
    
    event_title="Get a Magen Client Request"
    if success:
        success_user, message_user, user = UserApi.get_user_by_name(client.user)
        if success_user:  
            cilent_dic = {"user": client.user,
                      "revision": client.revision,
                      "device_id": client.device_id,
                      "mc_id": client.mc_id,
                      "ip": client.ip,
                      "mac": client.mac,
                      "u_groups": user.u_groups}
            client_list.append(cilent_dic)
            response_obj = {"clients": {"client": client_list}}
            return RestServerApis.respond(HTTPStatus.OK, event_title, response_obj)
        else:
            return RestServerApis.respond(
              HTTPStatus.NOT_FOUND, event_title, {
                "success": success, "cause": message})    
    else:
        return RestServerApis.respond(
            HTTPStatus.NOT_FOUND, event_title, {
                "success": success, "cause": message})


@ids.route('/magen/id/v2/clients/', methods=["GET"])
def get_magen_clients():
    event_title="Get All Magen Client Request"
    success, message, clients = ClientApi.get_all()

    client_list = []
    if success:
        for c in clients:
            success_user, message_user, user = UserApi.get_user_by_name(c.user)
            if success_user:
                cilent_dic = {"user": c.user,
                          "revision": c.revision,
                          "device_id": c.device_id,
                          "mc_id": c.mc_id,
                          "ip": c.ip,
                          "mac": c.mac,
                          "u_groups": user.u_groups}
                client_list.append(cilent_dic)
        response_obj = {"clients": {"client": client_list}}
        return RestServerApis.respond(HTTPStatus.OK, event_title, response_obj)
    else:
        return RestServerApis.respond(
            HTTPStatus.NOT_FOUND, event_title, {
                "success": success, "cause": message})


@ids.route('/magen/id/v2/clients/client/', methods=["PUT"])
def update_magen_client():
    event_title="Update Magen Client Request"
    try:
        client_dict = request.json["clients"]["client"][0]
        c_success, c_message, client = ClientApi.get_client(str(client_dict["mc_id"]))
        if c_success:
                n_success, n_message, n_response = ClientApi.Notify("create", client_dict["mc_id"])
        
                logger.debug(client_dict["mc_id"])
                del_success, del_message, del_response = ClientApi.delete_client(client_dict["mc_id"])
                if del_success:
                    new_success, new_message, mc_id = ClientApi.new_client_process(client_dict)
                    if new_success:
                        if n_success:
                          http_response = RestServerApis.respond(HTTPStatus.CREATED, event_title, {
                            "success": new_success, "cause": "Updated and Policy Service Notify Succeeded", "mc_id": mc_id})
                          http_response.headers['location'] = request.url + mc_id + '/'
                        else:
                          http_response = RestServerApis.respond(HTTPStatus.CREATED, event_title, {
                            "success": new_success, "cause": "Updated but Policy Service Notify Failed", "mc_id": mc_id})
                          http_response.headers['location'] = request.url + mc_id + '/'
                        return http_response
                    else:
                        return RestServerApis.respond(
                            HTTPStatus.NOT_FOUND, event_title, {
                                "success": new_success, "cause": new_message})
                else:
                    return RestServerApis.respond(
                        HTTPStatus.NOT_FOUND, event_title, {
                            "success": del_success, "cause": del_message})

        else:
            return RestServerApis.respond(
                HTTPStatus.NOT_FOUND, event_title, {
                    "success": c_success, "cause": c_message})

    except ValueError as e:
        result = {
            "success": False,
            "client": None,
            "cause": e.args[0]}
        return RestServerApis.respond(HTTPStatus.BAD_REQUEST, event_title,result)


@ids.route('/magen/id/v2/clients/client/<mc_id>/', methods=["DELETE"])
def delete_magen_client(mc_id):
    event_title="Delete Magen Client Request"
    try:
      del_success, del_message, del_response = ClientApi.delete_client(mc_id)
      if del_success:
        n_success, n_message, n_response = ClientApi.Notify("delete", mc_id)  
        if n_success: 
            msg = "Clients deleted and notified Policy Service."
        else:
            msg = "Clients deleted but notified Policy Service failed."   
               
        return RestServerApis.respond(
                HTTPStatus.OK, event_title, {
                    "success": del_success, "cause": msg})   
      else:
        return RestServerApis.respond(
                HTTPStatus.NOT_FOUND, event_title, {
                    "success": del_success, "cause": del_message})

    except ValueError as e:
        result = {
            "success": False,
            "cause": e.args[0]}
        return RestServerApis.respond(HTTPStatus.BAD_REQUEST, event_title,
                                      result)


