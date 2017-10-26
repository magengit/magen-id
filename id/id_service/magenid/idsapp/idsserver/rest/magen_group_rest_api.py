import logging
import functools
from flask import Blueprint
from http import HTTPStatus

from flask import request
from werkzeug.exceptions import BadRequest

from id.id_service.magenid.idsapp.idsserver.lib.bll.group_api import GroupApi
from id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_group_api import MagenUserGroupApi
from magen_logger.logger_config import LogDefaults
from magen_rest_apis.rest_server_apis import RestServerApis

from id.id_service.magenid.idsapp.idsserver.rest import rest_utils
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

MAGEN_U_GROUP_URLS = dict(
    base_v2='/magen/id/v2/groups',
    base_v3='/magen/id/v3/groups',
    groups='/',
    group='/group/',
    group_name='/group/{}/'
)

magen_user_group_bp = Blueprint('magen_user_group_bp', __name__, url_prefix=MAGEN_U_GROUP_URLS['base_v3'])

SERVER_500_GEN_CAUSE = 'Server could not process this request'
SERVER_500_ATTR_CAUSE = 'DB Connection Failed'


@magen_user_group_bp.route(MAGEN_U_GROUP_URLS['group'], methods=['POST'])
def add_magen_group_v3():
    """
    Add a single Magen User Group through REST (POST)
    This request will create a new user.
    Fields: `ug_name` and `ug_id` are required in payload
    `ug_name` value must be unique

    URL: http://{host:port}/magen/id/v3/groups/group/

    Payload Example:
    {"group": [{
        "ug_name": "engineering",
        "ug_id": 1
    }]
    }

    Response Example:
    {"response": {
        "cause": "Created",
        "group": {
            "ug_id": 1,
            "ug_name": "engineering"
        },
        "success": true
    },
    "status": 201,
    "title": "Magen Group creation Request"
    }

    :return: Response from server
    :rtype: JSON
    """
    partial_respond = functools.partial(RestServerApis.respond, title='Magen Group creation Request')
    magen_user_group = MagenUserGroupApi()
    required_keys = ['ug_name', 'ug_id']
    try:
        group_dict = request.json['group'][0]
        status, missing_keys = rest_utils.check_payload(group_dict, required_keys)
    except BadRequest as err:
        # JSON violation
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
            success=False, cause='Bad Payload Data: {}'.format(err.description), group=None))
    except (KeyError, IndexError) as err:
        # Payload format violation
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
            success=False, cause='Bad Payload Data: {} is expected'.format(str(err)), group=None))
    except TypeError as err:
        # Payload type violation
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
            success=False, cause='Bad Payload type: JSON expected', group=None))
    if not status:
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
            success=status, cause='Bad Payload: {} is/are missing'.format(str(missing_keys)), group=group_dict))
    try:
        result = magen_user_group.insert_group(group_dict)
        success = result.success & result.count
        if success:
            return partial_respond(http_status=HTTPStatus.CREATED, response=dict(
                success=bool(success), cause=HTTPStatus.CREATED.phrase, group=group_dict))
        if result.code == 11000:
            # Attempt to insert same data
            return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
                success=success, cause=result.message, group=group_dict))
    except AttributeError as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_ATTR_CAUSE, group=group_dict))
    except Exception as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_GEN_CAUSE, group=group_dict))


@magen_user_group_bp.route(MAGEN_U_GROUP_URLS['group_name'].format('<user_group_name>'))
def get_magen_user_group_v3(user_group_name):
    """
    Get Magen User Group info by user group name through REST (GET)

    URL: http://{host:port}/magen/id/v3/groups/group/<user_group_name>/

    Response Example:
    {"response": {
        "cause": "OK",
        "group": {
            "ug_id": 1,
            "ug_name": "engineering"
        },
        "success": true
    },
    "status": 200,
    "title": "Get a Magen Group Request"
    }

    :param user_group_name: user group name
    :type user_group_name: str

    :return: Response from server
    :rtype: JSON
    """
    partial_respond = functools.partial(RestServerApis.respond, title='Get a Magen Group Request')
    magen_user_group = MagenUserGroupApi()
    try:
        result = magen_user_group.get_group_by_name(user_group_name)
        success = bool(result.success & result.count)
    except AttributeError as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_ATTR_CAUSE, group=None))
    except Exception as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_GEN_CAUSE, group=None))
    if success:
        res = result.to_dict()
        return partial_respond(response=dict(success=success, cause=HTTPStatus.OK.phrase, group=res['json']))
    return partial_respond(http_status=HTTPStatus.NOT_FOUND,
                           response=dict(success=success, cause='Magen User Group is not found', group=None))


@magen_user_group_bp.route(MAGEN_U_GROUP_URLS['groups'])
def get_all_magen_user_goups():
    """
    Get All Magen User Group through REST (GET)

    URL: http://{host:port}/magen/id/v3/groups/

    Response Example:
    {"response": {
        "cause": "OK",
        "groups": [
            {
                "ug_id": 1,
                "ug_name": "engineering"
            }
        ],
        "success": true
    },
    "status": 200,
    "title": "Get All Magen Groups Request"
}

    :return: Response from server
    :rtype: JSON
    """
    partial_respond = functools.partial(RestServerApis.respond, title='Get All Magen Groups Request')
    magen_user_group = MagenUserGroupApi()
    try:
        result = magen_user_group.get_all()
        success = bool(result.success & result.count)
    except AttributeError as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_ATTR_CAUSE, groups=None))
    except Exception as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_GEN_CAUSE, groups=None))
    if success:
        res = result.to_dict()
        return partial_respond(response=dict(success=success, cause=HTTPStatus.OK.phrase, groups=res['json']))
    return partial_respond(http_status=HTTPStatus.NOT_FOUND,
                           response=dict(success=success, cause='No Magen User Groups found', groups=None))


@magen_user_group_bp.route(MAGEN_U_GROUP_URLS['group_name'].format('<user_group_name>'), methods=['DELETE'])
def delete_magen_user_group_v3(user_group_name):
    """
    Delete Magen User Group by user_group_name

    URL: http://{host:port}/magen/id/v3/groups/group/<user_group_name>/

    Response Example:
    {"response": {
        "cause": "Document deleted",
        "group": {
            "removed": 1
        },
        "success": true
    },
    "status": 200,
    "title": "Delete Magen Group Request"
    }

    :param user_group_name: name of the group
    :type user_group_name: str

    return: Response from server
    :rtype: JSON
    """
    partial_respond = functools.partial(RestServerApis.respond, title='Delete Magen Group Request')
    magen_user_group = MagenUserGroupApi()
    try:
        result = magen_user_group.delete_group(user_group_name)
    except AttributeError as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_ATTR_CAUSE, group=None))
    except Exception as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_GEN_CAUSE, user=None))
    if not result.count:
        return partial_respond(response=dict(success=result.success, cause='Document does not exist',
                                             group=dict(removed=int(result.count))))
    return partial_respond(response=dict(success=result.success, cause=result.message,
                                         group=dict(removed=int(result.count))))


@magen_user_group_bp.route(MAGEN_U_GROUP_URLS['group'], methods=['PUT'])
def replace_magen_user_group():
    """
    Replace or Create Magen User Group.
    Fields: `ug_name` and `ug_id` are required in payload
    `ug_name` must be unique

    Payload Example:
    {"group": [{
        "ug_name": "engineering",
        "ug_id": 1
    }]
    }

    Response Example:
    {"response": {
        "cause": "OK",
        "group": {
            "ug_id": 1,
            "ug_name": "engineering"
        },
        "success": true
    },
    "status": 200,
    "title": "Update Magen Group Request"
    }

    return: Response from server
    :rtype: JSON
    """
    partial_respond = functools.partial(RestServerApis.respond, title='Update Magen Group Request')
    magen_user_group = MagenUserGroupApi()
    required_keys = ['ug_name', 'ug_id']
    try:
        group_dict = request.json['group'][0]
        status, missing_keys = rest_utils.check_payload(group_dict, required_keys)
    except BadRequest as err:
        # JSON violation
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
            success=False, cause='Bad Payload Data: {}'.format(err.description), group=None))
    except (KeyError, IndexError) as err:
        # Payload format violation
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
            success=False, cause='Bad Payload Data: {} is expected'.format(str(err)), group=None))
    except TypeError as err:
        # Payload type violation
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
            success=False, cause='Bad Payload type: JSON expected', group=None))
    if not status:
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
            success=status, cause='Bad Payload: {} is/are missing'.format(str(missing_keys)), group=group_dict))
    try:
        result = magen_user_group.replace_group(group_dict['ug_name'], group_dict)
        if result.success:
            return partial_respond(http_status=HTTPStatus.OK, response=dict(
                success=bool(result.success), cause=HTTPStatus.OK.phrase, group=group_dict))
        else:
            return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
                success=False, cause=SERVER_500_GEN_CAUSE, group=group_dict))
    except AttributeError as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_ATTR_CAUSE, group=group_dict))
    except Exception as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_GEN_CAUSE, group=group_dict))


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