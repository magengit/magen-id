import logging
import uuid
import functools

from flask import request, Blueprint
from werkzeug.exceptions import BadRequest
from http import HTTPStatus
from magen_rest_apis.rest_server_apis import RestServerApis

from id.id_service.magenid.idsapp.idsserver.lib.bll.magen_user_api import MagenUserApi
from id.id_service.magenid.idsapp.idsserver.lib.bll.user_api import UserApi
from magen_logger.logger_config import LogDefaults

from id.id_service.magenid.idsapp.idsserver.rest import rest_utils
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

MAGEN_USER_URLS = dict(
    base_v2='/magen/id/v2/users',
    base_v3='/magen/id/v3/users',
    users='/',
    user='/user/',
    user_uuid='/user/{}/'
)

magen_user_bp = Blueprint('magen_user_bp', __name__, url_prefix=MAGEN_USER_URLS['base_v3'])


SERVER_500_GEN_CAUSE = 'Server could not process this request'
SERVER_500_ATTR_CAUSE = 'DB Connection Failed'


@magen_user_bp.route(MAGEN_USER_URLS['user'], methods=['POST'])
def add_magen_user_v3():
    """
    POST REST request for registering Magen User.
    This request allows to create a new user.
    Error will be generated if attempting to register user with same `username` or `user_uuid` again

    URL: http://{host:port}/magen/id/v3/users/user/

    Payload Example:

    {"user": [{
         "first_name": "Mizan",
         "last_name": "Chowdhury",
         "display_name":"Mizan Chowdhury",
         "password": "pw",
         "department":"R&D",
         "position":"lead",
         "role":"lead",
         "idp": "magen",
         "u_groups": [
            "finance"
         ],
         "u_clients":[],
         "username": "michowdh@cisco.com",
         "email": "michowdh@cisco.com",
         "imgSrc": "user_mizanul_chowdhury.png"
        }]
    }

    Response Example:
    {"response": {
        "cause": "Created",
        "success": true,
        "user": {
            "department": "R&D",
            "display_name": "Mizan Chowdhury",
            "email": "michowdh@cisco.com",
            "email_verified": true,
            "first_name": "Mizan",
            "idp": "magen",
            "photo": "user_mizanul_chowdhury.png",
            "last_name": "Chowdhury",
            "password": "pw",
            "position": "lead",
            "registered_on": 1509017843,
            "role": "lead",
            "u_clients": [],
            "u_groups": [
                "finance"
            ],
            "user_uuid": "816bed5a-bdcc-400f-97ee-c6b2698d8156",
            "username": "michowdh@cisco.com"
        }
    },
    "status": 201,
    "title": "Magen User creation Request"
    }

    [Note]: `username`, `first_name`, `last_name`, `password`, `email` - are required fields for request to be processed
    `user_uuid` will be generated and assigned if not provided.
    `username` and `user_uuid` must contain unique values

    :return: Response from server
    :rtype: JSON
    """
    partial_respond = functools.partial(RestServerApis.respond, title='Magen User creation Request')
    magen_user = MagenUserApi()
    required_keys = ['username', 'first_name', 'last_name', 'password', 'email']
    try:
        user_dict = request.json['user'][0]
        status, missing_keys = rest_utils.check_payload(user_dict, required_keys)
    except BadRequest as err:
        # JSON violation
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
            success=False, cause='Bad Payload Data: {}'.format(err.description), user=None))
    except (KeyError, IndexError) as err:
        # Payload format violation
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
            success=False, cause='Bad Payload Data: {} is expected'.format(str(err)), user=None))
    except TypeError as err:
        # Payload type violation
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
            success=False, cause='Bad Payload type: JSON expected', user=None))
    if not status:
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
            success=status, cause='Bad Payload: {} is/are missing'.format(str(missing_keys)), user=user_dict))
    try:
        result = magen_user.insert_user(user_dict)
        success = result.success & result.count
        if success:
            return partial_respond(http_status=HTTPStatus.CREATED, response=dict(
                success=bool(success), cause=HTTPStatus.CREATED.phrase, user=user_dict))
        if result.code == 11000:
            # Attempt to insert same data
            return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
                success=bool(success), cause=result.message, user=user_dict))
    except AttributeError as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_ATTR_CAUSE, user=user_dict))
    except Exception as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_GEN_CAUSE, user=user_dict))


@magen_user_bp.route(MAGEN_USER_URLS['user_uuid'].format('<user_uuid>'))
def get_magen_user_v3(user_uuid):
    """
    Get Magen User by user_uuid

    URL: http://{host:port}/magen/id/v3/users/user/<user_uuid>/

    :param user_uuid: user id
    :type user_uuid: str

    Response Example:
    {"response": {
        "cause": "OK",
        "success": true,
        "user": {
            "department": "R&D",
            "display_name": "Mizan Chowdhury",
            "email": "michowdh@cisco.com",
            "email_verified": true,
            "first_name": "Mizan",
            "idp": "magen",
            "photo": "user_mizanul_chowdhury.png",
            "last_name": "Chowdhury",
            "password": "pw",
            "position": "lead",
            "registered_on": 1509017843,
            "role": "lead",
            "u_clients": [],
            "u_groups": [
                "finance"
            ],
            "user_uuid": "816bed5a-bdcc-400f-97ee-c6b2698d8156",
            "username": "michowdh@cisco.com"
        }
    },
    "status": 200,
    "title": "Get a Magen User Request"
    }

    :return: Response from server
    :rtype: JSON
    """
    partial_respond = functools.partial(RestServerApis.respond, title='Get a Magen User Request')
    magen_user = MagenUserApi()
    try:
        result = magen_user.get_user(user_uuid)
        success = bool(result.success & result.count)
    except AttributeError as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_ATTR_CAUSE, user=None))
    except Exception as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_GEN_CAUSE, user=None))
    if success:
        res = result.to_dict()
        return partial_respond(response=dict(success=success, cause=HTTPStatus.OK.phrase, user=res['json']))
    return partial_respond(http_status=HTTPStatus.NOT_FOUND,
                           response=dict(success=success, cause='Magen User is not found', user=None))


@magen_user_bp.route(MAGEN_USER_URLS['users'])
def get_magen_users():
    """
    GET REST request for All registered Magen Users

    URL: http://{host:port}/magen/id/v3/users/

    Response Example:
    {"response": {
        "cause": "OK",
        "success": true,
        "users": [
            {
                "department": "R&D",
                "display_name": "Mizan Chowdhury",
                "email": "michowdh@cisco.com",
                "email_verified": true,
                "first_name": "Mizan",
                "idp": "magen",
                "imgSrc": "user_mizanul_chowdhury.png",
                "last_name": "Chowdhury",
                "password": "pw",
                "position": "lead",
                "registered_on": 1509017843,
                "role": "lead",
                "u_clients": [],
                "u_groups": [
                    "finance"
                ],
                "user_uuid": "816bed5a-bdcc-400f-97ee-c6b2698d8156",
                "username": "michowdh@cisco.com"
            }
        ]
    },
    "status": 200,
    "title": "Get All Magen Users Request"
    }

    return: Response from server
    :rtype: JSON
    """
    partial_respond = functools.partial(RestServerApis.respond, title='Get All Magen Users Request')
    magen_user = MagenUserApi()
    try:
        result = magen_user.get_all()
        success = bool(result.success & result.count)
    except AttributeError as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_ATTR_CAUSE, users=None))
    except Exception as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_GEN_CAUSE, users=None))
    if success:
        res = result.to_dict()
        return partial_respond(response=dict(success=success, cause=HTTPStatus.OK.phrase, users=res['json']))
    return partial_respond(http_status=HTTPStatus.NOT_FOUND,
                           response=dict(success=success, cause='No Magen Users found', users=None))


@magen_user_bp.route(MAGEN_USER_URLS['user_uuid'].format('<user_uuid>'), methods=['DELETE'])
def delete_magen_user_v3(user_uuid):
    """
    Delete Magen User by user_uuid

    URL: http://{host:port}/magen/id/v3/users/user/

    Response Example:
    {"response": {
        "cause": "Document deleted",
        "success": true,
        "user": {
            "removed": 1
        }
    },
    "status": 200,
    "title": "Delete a Magen User Request"
    }

    :param user_uuid: user id
    :type user_uuid: str

    return: Response from server
    :rtype: JSON
    """
    partial_respond = functools.partial(RestServerApis.respond, title='Delete a Magen User Request')
    magen_user = MagenUserApi()
    try:
        # TODO: make sure all clients get deleted with user
        result = magen_user.delete_user(user_uuid)
    except AttributeError as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_ATTR_CAUSE, user=None))
    except Exception as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_GEN_CAUSE, user=None))
    if not result.count:
        return partial_respond(response=dict(success=result.success, cause='Document does not exist',
                                             user=dict(removed=int(result.count))))
    return partial_respond(response=dict(success=result.success, cause=result.message,
                                         user=dict(removed=int(result.count))))


@magen_user_bp.route(MAGEN_USER_URLS['user'], methods=['PUT'])
def replace_magen_user_v3():
    """
    PUT REST request for replacing Magen User.
    This request allows to create a new user or replace user data for existing user

    URL: http://{host:port}/magen/id/v3/users/user/

    Payload Example:

    {"user": [{
         "user_uuid": "c9d0388e-76ea-48f7-9df4-62ea95a27649"
         "first_name": "Mizan",
         "last_name": "Chowdhury",
         "display_name":"Mizan Chowdhury",
         "password": "pw",
         "department":"R&D",
         "position":"lead",
         "role":"lead",
         "idp": "magen",
         "u_groups": [
            "finance"
         ],
         "u_clients":[],
         "username": "michowdh@cisco.com",
         "email": "michowdh@cisco.com",
         "photo": "user_mizanul_chowdhury.png"
        }]
    }

    [Note]: `user_uuid`, `username`, `first_name`, `last_name`, `password`, `email` - are required fields for request to be processed

    :return: Response from server
    :rtype: JSON
    """
    partial_respond = functools.partial(RestServerApis.respond, title='Update Magen User Request')
    magen_user = MagenUserApi()
    required_keys = ['user_uuid', 'username', 'first_name', 'last_name', 'password', 'email']
    try:
        user_dict = request.json['user'][0]
        status, missing_keys = rest_utils.check_payload(user_dict, required_keys)
    except BadRequest as err:
        # JSON violation
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
            success=False, cause='Bad Payload Data: {}'.format(err.description), user=None))
    except (KeyError, IndexError) as err:
        # Payload format violation
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
            success=False, cause='Bad Payload Data: {} is expected'.format(str(err)), user=None))
    except TypeError as err:
        # Payload type violation
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
            success=False, cause='Bad Payload type: JSON expected', user=None))
    if not status:
        return partial_respond(http_status=HTTPStatus.BAD_REQUEST, response=dict(
            success=status, cause='Bad Payload: {} is/are missing'.format(str(missing_keys)), user=user_dict))
    try:
        result = magen_user.replace_user(user_dict['user_uuid'], user_dict)
        if result.success:
            return partial_respond(http_status=HTTPStatus.OK, response=dict(
                success=bool(result.success), cause=HTTPStatus.OK.phrase, user=user_dict))
        else:
            return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
                success=False, cause=SERVER_500_GEN_CAUSE, user=user_dict))
    except AttributeError as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_ATTR_CAUSE, user=user_dict))
    except Exception as err:
        logger.error(err)
        return partial_respond(http_status=HTTPStatus.INTERNAL_SERVER_ERROR, response=dict(
            success=False, cause=SERVER_500_GEN_CAUSE, user=user_dict))


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
