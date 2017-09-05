import logging
import uuid

from flask import request
from http import HTTPStatus
from magen_rest_apis.rest_server_apis import RestServerApis
from magen_rest_apis.rest_client_apis import RestClientApis

from id.id_service.magenid.idsapp.idsserver.lib.bll.user_api import UserApi
from magen_logger.logger_config import LogDefaults

from id.id_service.magenid.idsapp.idsserver.views.home import *

logger = logging.getLogger(LogDefaults.default_log_name)

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "2.0"
__status__ = "alpha"

# magen_id_user(2015-12-05)
#

#         get /magen/id/v2.0/users/user/{user_uuid}/
#         put /magen/id/v2.0/users/user/
#         delete /magen/id/v2.0/users/user/{user_uuid}/
#         post  /magen/id/v2.0/users/user/
#         get /magen/id/v2.0/users/


@ids.route('/magen/id/v2/users/user/', methods=["POST"])
def add_magen_user():
    event_title="Magen User creation Request"
    user_dict = request.json["users"]["user"][0]
    #print(user_dict["username"])
    if user_dict["uuid"]=="":
        user_dict['uuid'] = str(uuid.uuid4())
    success, message, user = UserApi.add_user(user_dict)

    if success:
        result = dict(
            success=success,
            uuid=user.uuid,
            cause=message
        )
        http_response = RestServerApis.respond(HTTPStatus.OK, event_title, result)
        http_response.headers['location'] = request.url + user.uuid + "/"
        return http_response
    else:
        result = dict(
            success=success,
            uuid=None,
            cause=message
        )
        return RestServerApis.respond(HTTPStatus.INTERNAL_SERVER_ERROR, "User Creation", result)


@ids.route('/magen/id/v2/users/user/<user_uuid>/', methods=["GET"])
def get_magen_user(user_uuid):
    event_title="Get a Magen User Request"
    success, message, user = UserApi.get_user(user_uuid)
    user_list = []
    if success:
        user_dict={
                    
                  "department": user.department,
                  "position": user.position,
                  "uuid": user.uuid,
                  "u_groups": user.u_groups,
                  "u_clients": user.u_clients,
                  "display_name":user.display_name,
                  "userId": user.uuid,
                  "idp": user.idp,
                  "username": user.username,
                  "email": user.email,
                  "firstName": user.first_name,
                  "lastName": user.first_name,
                  "password": user.password,
                  "userGroup": user.department,
                  "type": user.role,
                  "roles": [user.role],
                  "lastLogin": user.last_login,
                  "imgSrc": user.photo
                }

        user_list.append(user_dict)
        response_obj = {"user": user_list}
        result = dict(
            success=True,
            users=user_list,
            cause="User found"
        )
        http_status = HTTPStatus.OK
    else:
        result = dict(
            success=False,
            user=None,
            cause="No users found"
        )
        http_status = HTTPStatus.NOT_FOUND
    return RestServerApis.respond(http_status, event_title, result)

# get all users or specific user
@ids.route('/magen/id/v2/users/', methods=["GET"])
def get_magen_users():
    event_title="Get All Magen Users Request"
    success, message, users = UserApi.get_all()

    if success:
        user_list = []
        if users:
            for user in users:
              user_dict={
                  "department": user.department,
                  "position": user.position,
                  "uuid": user.uuid,
                  "u_groups": user.u_groups,
                  "u_clients": user.u_clients,
                  "display_name":user.display_name,
                  "userId": user.uuid,
                  "idp": user.idp,
                  "username": user.username,
                  "email": user.email,
                  "firstName": user.first_name,
                  "lastName": user.first_name,
                  "password": user.password,
                  "userGroup": user.department,
                  "type": user.role,
                  "roles": [user.role],
                  "lastLogin": user.last_login,
                  "imgSrc": user.photo

                }
              user_list.append(user_dict)
        response_obj = {"user": user_list}
        result = dict(
            success=True,
            users=response_obj,
            cause="Users found"
        )
        http_status = HTTPStatus.OK
    else:
        result = dict(
            success=False,
            user=None,
            cause="No users found"
        )
        http_status = HTTPStatus.NOT_FOUND
    return RestServerApis.respond(http_status, event_title, result)



@ids.route('/magen/id/v2/users/user/', methods=["PUT"])
def update_magen_user():
    event_title="Update Magen User Request"
    try:
      user_dict = request.json["users"]["user"][0]
      g_success, g_message, user = UserApi.get_user(str(user_dict["uuid"]))
      if g_success:
         d_success, d_message, d_response = UserApi.delete_user(user.uuid)
         if d_success:
            a_success, a_message, user = UserApi.add_user(user_dict)
            if a_success:
                      http_response = RestServerApis.respond(HTTPStatus.CREATED, event_title, {
                          "success": a_success, "cause": HTTPStatus.CREATED.phrase, "uuid": user.uuid})
                      http_response.headers['location'] = request.url + user.uuid + '/'
                      return http_response
            else:
                      raise ValueError
      else:
          return RestServerApis.respond(
              HTTPStatus.NOT_FOUND, event_title, {
                  "success": False, "cause": "User not found"})

    except ValueError as e:
      result = {
          "success": False,
          "user": None,
          "cause": e.args[0]}
      return RestServerApis.respond(HTTPStatus.BAD_REQUEST, event_title,
                                    result)



@ids.route('/magen/id/v2/users/user/<user_uuid>/', methods=["DELETE"])
def delete_magen_user(user_uuid):
    event_title="Delete a Magen User Request"
    try:
        success,message,response = UserApi.delete_user(user_uuid)
        if not success:
          result = dict(
            success=success,
            client=response,
            cause=message
          )
          msg = "%s Problems while deleting Magen User"
        else:
          result = dict(
            success=success,
            client=response,
            cause=message
          )
          msg = "Deleted Magen User"
          return RestServerApis.respond(HTTPStatus.OK, event_title, result)
    except ValueError as e:
        result = {
            "success": False,
            "user": None,
            "cause": e.args[0]}
        return RestServerApis.respond(HTTPStatus.BAD_REQUEST, event_title,
                                      result)