import logging
from http import HTTPStatus

from flask import request

from id.id_service.magenid.idsapp.idsserver.lib.bll.group_api import GroupApi
from magen_logger.logger_config import LogDefaults
from magen_rest_apis.rest_server_apis import RestServerApis


from id.id_service.magenid.idsapp.idsserver.views.home import *

logger = logging.getLogger(LogDefaults.default_log_name)

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"


#         get /magen/id/v2.0/groups/group/{ug_name}/
#         put /magen/id/v2.0/groups/group/
#         delete /magen/id/v2.0/groups/group/{ug_name}/
#         post  /magen/id/v2.0/groups/group/
#         get /magen/id/v2.0/groups/


@ids.route('/magen/id/v2/groups/group/', methods=["POST"])
def add_magen_group():
    event_title="Magen Group creation Request"
    group_dict = request.json["groups"]["group"][0]

    success, message, group = GroupApi.add_group(group_dict)

    if success:
        result = dict(
            success=success,
            ug_name=group.ug_name,
            cause=message
        )
        http_response = RestServerApis.respond(HTTPStatus.OK, event_title, result)
        http_response.headers['location'] = request.url + group.ug_name + "/"
        return http_response
    else:
        result = dict(
            success=success,
            ug_name=None,
            cause=message
        )
        return RestServerApis.respond(HTTPStatus.INTERNAL_SERVER_ERROR, event_title, result)


@ids.route('/magen/id/v2/groups/group/<ug_name>/', methods=["GET"])
def get_magen_group(ug_name):
    event_title="Get a Magen Group Request"
    success, message, group = GroupApi.get_group_by_group_name(ug_name)
    group_list = []
    if success:
        group_dict={
            "group": [
                {
                    "ug_name": group.ug_name,
                    "ug_id": group.ug_id
                }
            ]
        }
        group_list.append(group_dict)
        response_obj = {"group": group_list}
        result = dict(
            success=True,
            groups=group_list,
            cause=None
        )
        http_status = HTTPStatus.OK
    else:
        result = dict(
            success=False,
            group=None,
            cause="No groups found"
        )
        http_status = HTTPStatus.NOT_FOUND
    return RestServerApis.respond(http_status, event_title, result)

# get all groups or specific group
@ids.route('/magen/id/v2/groups/', methods=["GET"])
def get_magen_groups():
    event_title="Get All Magen Groups Request"
    success, message, groups = GroupApi.get_all()
    print("=====groups=====",groups)
    if success:
        group_list = []
        if groups:
            for group in groups:
              group_dict={
                    "ug_name": group.ug_name,
                    "ug_id": group.ug_id
              }
              group_list.append(group_dict)
        response_obj = {"group": group_list}
        result = dict(
            success=True,
            groups=response_obj,
            cause=None
        )
        http_status = HTTPStatus.OK
    else:
        result = dict(
            success=False,
            group=None,
            cause="No groups found"
        )
        http_status = HTTPStatus.NOT_FOUND
    return RestServerApis.respond(http_status, event_title, result)



@ids.route('/magen/id/v2/groups/group/', methods=["PUT"])
def update_magen_group():
    event_title="Update Magen Group Request"
    try:
      group_dict = request.json["groups"]["group"][0]

      success, message, group = GroupApi.get_group_by_group_name(group_dict["ug_name"])

      if success:
         d_success, d_message,d_response = GroupApi.delete_group(group.ug_name)
         if d_success:
            u_success, u_message, u_group = GroupApi.add_group(group_dict)
            if u_success:
                      http_response = RestServerApis.respond(HTTPStatus.CREATED, event_title, {
                          "success": u_success, "cause": HTTPStatus.CREATED.phrase, "ug_name": u_group.ug_name})
                      http_response.headers['location'] = request.url + u_group.ug_name + '/'
                      return http_response
            else:
                      raise ValueError
      else:
          return RestServerApis.respond(
              HTTPStatus.NOT_FOUND, event_title, {
                  "success": False, "cause": "Problem in updating Group"})

    except ValueError as e:
      result = {
          "success": False,
          "group": None,
          "cause": "Problem in updating Group"}
      return RestServerApis.respond(HTTPStatus.BAD_REQUEST, event_title,
                                    result)



@ids.route('/magen/id/v2/groups/group/<ug_name>/', methods=["DELETE"])
def delete_magen_group(ug_name):
    event_title="Delete Magen Group Request"
    try:
        success,message,response = GroupApi.delete_group(ug_name)
        return RestServerApis.respond(HTTPStatus.OK, event_title, {
                  "success": success, "cause": message})
    except ValueError as e:
        result = {
            "success": False,
            "user": None,
            "cause": e.args[0]}
        return RestServerApis.respond(HTTPStatus.BAD_REQUEST, event_title,
                                      result)