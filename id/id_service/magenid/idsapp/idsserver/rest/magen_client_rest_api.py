import functools
from http import HTTPStatus

from flask import Blueprint, jsonify
from werkzeug.exceptions import BadRequest

from datadog.api.exceptions import ApiNotInitialized
from id.id_service.magenid.idsapp.idsserver.lib.bll.client_api import ClientApi
from id.id_service.magenid.idsapp.idsserver.lib.bll.user_api import UserApi
from id.id_service.magenid.idsapp.idsserver.views.home import *
from magen_rest_apis.rest_server_apis import RestServerApis
from magen_logger.logger_config import LogDefaults

from id.id_service.magenid.idsapp.idsserver.utils.dd_events import DDIdentityEventsWrapper
from id.id_service.magenid.idsapp.idsserver.rest import rest_utils
from id.id_service.magenid.idsapp.idsserver.lib.bll.magen_client_api import MagenClientApi
from id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_api import verify_user

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"


MAGEN_CLIENTS_URLS = dict(
    base_v2='/magen/id/v2/clients',
    base_v3='/magen/id/v3/clients',
    clients='/',
    client='/client/',
    mc_id='/client/{}/'
)


magen_client_bp = Blueprint("magen_client_bp", __name__, url_prefix=MAGEN_CLIENTS_URLS['base_v3'])

SERVER_500_GEN_CAUSE = 'Server could not process this request'
SERVER_500_ATTR_CAUSE = 'DB Connection Failed'

#
# Clients APIs
#

# magen_id_client_rest_api(2015-12-07)
#         get /magen/id/v2/clients/
#         get /magen/id/v2/clients/client/{mc_id}/
#         post /magen/id/v2/clients/client/
#         put /magen/id/v2/clients/client/{mc_id}/
#         delete /magen/id/v2/clients/client/{mc_id}/


@magen_client_bp.route(MAGEN_CLIENTS_URLS['client'], methods=['POST'])
def add_magen_client_v3():
    """
    POST REST request for creating a Magen Client
    For each Magen Client Magen User must exist in the system
    Mandatory fields: `user`, `device_id`

    Same Client can't be created twice

    :return: Response from server
    :rtype: JSON
    """
    # Events Handler
    id_events = DDIdentityEventsWrapper(app_name='identity', magen_logger=logger)
    request_title = 'Magen Client Creation Request'
    partial_respond = functools.partial(RestServerApis.respond, title=request_title)
    partial_send_event = functools.partial(id_events.send_event, event_name=request_title)
    partial_construct_event = functools.partial(DDIdentityEventsWrapper.construct_event, action='create')
    # Magen Client API
    magen_client = MagenClientApi()
    required_keys = ['user', 'device_id']
    response = dict(
        success=False,
        client=None
    )
    try:
        # Parse request data
        client_dict = request.json['client'][0]
        # Verify provided data
        status, missing_keys = rest_utils.check_payload(client_dict, required_keys)
    except BadRequest as err:
        # JSON violation
        logger.error(err)
        response['cause'] = 'Bad Payload Data: {}'.format(err.description)
        partial_send_event(event_data=partial_construct_event(response),
                           alert='warning')
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=response)
    except (KeyError, IndexError) as err:
        # Payload format violation
        logger.error(err)
        response['cause'] = 'Bad Payload Data: {} is expected'.format(str(err))
        partial_send_event(event_data=partial_construct_event(response),
                           alert='warning')
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=response)
    except TypeError as err:
        # Payload type violation
        logger.error(err)
        response['cause'] = 'Bad Payload type: JSON expected'
        partial_send_event(event_data=partial_construct_event(response),
                           alert='warning')
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=response)
    if not status:
        response['cause'] = 'Bad Payload: {} is/are missing'.format(str(missing_keys))
        partial_send_event(event_data=partial_construct_event(response),
                           alert='warning')
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=response)
    try:
        # Verify that provided user exists
        if not verify_user(client_dict['user']):
            response['cause'] = 'Bad Payload: User {} does not exist'.format(client_dict['user'])
            partial_send_event(event_data=partial_construct_event(response),
                               alert='warning')
            return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=response)
        # Here goes Policy Notification (Policy Session creation request invoked)
        result = magen_client.insert_client(client_dict)
        success = result.success & result.count
        response['success'] = bool(success)
        response['client'] = client_dict
        if success:
            response['cause'] = HTTPStatus.CREATED.phrase
            partial_send_event(event_data=partial_construct_event(
                client_dict, success=success, cause=response['cause']), alert='success')
            return partial_respond(http_status=HTTPStatus.CREATED, response=response)
        if result.code == 11000:
            # Attempt to insert same data
            response['cause'] = result.message
            partial_send_event(event_data=partial_construct_event(
                client_dict, success=success, cause=response['cause']), alert='success')
            return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=response)
    except AttributeError as err:
        logger.error(err)
        response['cause'] = SERVER_500_ATTR_CAUSE
        response['success'] = False
        partial_send_event(event_data=partial_construct_event(
            client_dict, success=False, cause=response['cause']), alert='error')
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=response)
    except Exception as err:
        logger.error(err)
        response['cause'] = SERVER_500_GEN_CAUSE
        response['success'] = False
        partial_send_event(event_data=partial_construct_event(
            client_dict, success=False, cause=response['cause']), alert='error')
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=response)


@magen_client_bp.route(MAGEN_CLIENTS_URLS['mc_id'].format('<magen_client_id>'))
def get_magen_client_v3(magen_client_id):
    """
    GET REST request for Magen Client by magen client id

    :param magen_client_id: mc_id
    :type magen_client_id: str

    :return: Response from server
    :rtype: JSON
    """
    partial_respond = functools.partial(RestServerApis.respond, title='Get a Magen Client Request')
    magen_client = MagenClientApi()
    try:
        result = magen_client.get_client(magen_client_id)
        success = bool(result.success & result.count)
    except AttributeError as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_ATTR_CAUSE, client=None))
    except Exception as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_GEN_CAUSE, client=None))
    if success:
        res = result.to_dict()
        return partial_respond(response=dict(success=success, cause=HTTPStatus.OK.phrase, client=res['json']))
    return partial_respond(http_status=HTTPStatus.NOT_FOUND,
                           response=dict(success=success, cause='Magen Client is not found', client=None))


@magen_client_bp.route(MAGEN_CLIENTS_URLS['clients'])
def get_magen_clients():
    """
    GET REST request for All Magen Clients in the system

    :return: Response from server
    :rtype: JSON
    """
    partial_respond = functools.partial(RestServerApis.respond, title='Get All Magen Client Request')
    magen_client = MagenClientApi()
    try:
        result = magen_client.get_all()
        success = bool(result.success & result.count)
    except AttributeError as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_ATTR_CAUSE, clients=None))
    except Exception as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_GEN_CAUSE, clients=None))
    if success:
        res = result.to_dict()
        return partial_respond(response=dict(success=success, cause=HTTPStatus.OK.phrase, clients=res['json']))
    return partial_respond(http_status=HTTPStatus.NOT_FOUND,
                           response=dict(success=success, cause='No Magen Clients found', clients=None))


@magen_client_bp.route(MAGEN_CLIENTS_URLS['mc_id'].format('<magen_client_id>'), methods=['DELETE'])
def delete_magen_client_v3(magen_client_id):
    """

    :param magen_client_id:
    :return:
    """
    partial_respond = functools.partial(RestServerApis.respond, title='Delete a Magen Client Request')
    magen_client = MagenClientApi()
    try:
        # TODO: make sure client gets removed from user entry
        result = magen_client.delete_client(magen_client_id)
    except AttributeError as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_ATTR_CAUSE, client=None))
    except Exception as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_GEN_CAUSE, client=None))
    if not result.count:
        return partial_respond(response=dict(success=result.success, cause='Document does not exist',
                                             client=dict(removed=int(result.count))))
    return partial_respond(response=dict(success=result.success, cause=result.message,
                                         client=dict(removed=int(result.count))))


@ids.route('/magen/id/v2/clients/client/', methods=["POST"])
def add_magen_client():

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


