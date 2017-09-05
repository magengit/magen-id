import uuid

from id.id_service.magenid.idsapp.idsserver.lib.db.magen_user_dao import *
#
# Copyright (c) 2015 Cisco Systems, Inc. and others.  All rights reserved.
#
from magen_utils_apis.decorators_api import static_vars

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "2.0"

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)

class UserApi(object):
    @staticmethod
    def update_user(user_dict):
        try:
          db = MagenUserDao()
          ret_obj=db.update(user_dict)
          if ret_obj is None:
            return False, "User has not been updated succesfully", None
          else:
            return True, "User has been updated succesfully", ret_obj
        except Exception as e:
            logging.exception(e)
            return False, "User has not been updated succesfully", None

    @staticmethod
    def get_all():
        try:
          db = MagenUserDao()
          ret_obj= db.get_all()
          if ret_obj is None:
            return False, "Users not found", None
          else:
            return True, "Users found succesfully", ret_obj
        except Exception as e:
            logging.exception(e)
            return False, "Users not found", None


    @staticmethod
    def get_user(user_uuid):
        try:
          db = MagenUserDao()
          ret_obj = db.get_by_uuid(user_uuid)
          if ret_obj is None:
           return False, "User not found",None
          else:
           return True, "User found succesfully",ret_obj
        except Exception as e:
            logging.exception(e)
            return False, "User not found", None

    @staticmethod
    def get_user_by_name(username):
        logger.debug("username %s ", username)
        try:
          db = MagenUserDao()
          ret_obj = db.get_by_user_name(username)
          logger.debug(ret_obj)
          if ret_obj is None:
              logger.debug("==ret_obj=====NONE=====")
              return False, "User not found", None
          else:
              logger.debug("==ret_obj==NOT===NONE===== %s",ret_obj.username)
              return True, "User found succesfully", ret_obj
        except Exception as e:
            logging.exception(e)
            return False, "User not found", None

    @staticmethod
    def add_user(user_dict):
        try:
          db = MagenUserDao()
          ret_obj =db.insert(user_dict)
          if ret_obj is None:
              return False, "User not added", None
          else:
              return True, "User added succesfully", ret_obj
        except Exception as e:
            logging.exception(e)
            return False, "User not added", None


    @staticmethod
    def delete_user(user_uuid):
        try:
          db = MagenUserDao()
          ret_obj = db.delete_by_uuid(user_uuid)
          if ret_obj is None:
              return False, "user has not been deleted succesfully", None
          else:
              return True, "user has been deleted succesfully", None
        except Exception as e:
            logging.exception(e)
            return False, "user has not been deleted succesfully", None
