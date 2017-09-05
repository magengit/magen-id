#
# Copyright (c) 2016 Cisco Systems, Inc. and others.  All rights reserved.
#
import logging

from id.id_service.magenid.idsapp.idsserver.lib.db.magen_group_dao import *

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "2.0"

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)


class GroupApi(object):
    @staticmethod
    def get_group_by_group_name(ug_name):
        db = MagenGroupDao()
        ret_obj = db.get_by_name(ug_name)
        if ret_obj:
            return True, "Group found succesfully", ret_obj
        else:
            return False, "Group not found", None

    @staticmethod
    def delete_group(ug_name):
        db = MagenGroupDao()
        success = db.delete_by_name(ug_name)
        if success:
            return True, "Groups deleted", None
        else:
            return False, "Failed to delete group", None

    @staticmethod
    def get_all():
        db = MagenGroupDao()
        ret_obj = db.get_all()
        if ret_obj:
            return True, "Groups found succesfully", ret_obj
        else:
            return False, "Groups not found", None

    @staticmethod
    def add_group(group_dict):
        db = MagenGroupDao()
        ret_obj = db.insert(group_dict)
        if ret_obj:
            return True, "Group added succesfully", ret_obj
        else:
            return False, "Group not added", None

    @staticmethod
    def update_group(group_dic):
        db = MagenGroupDao()
        ret_obj = db.update(group_dic)
        if ret_obj:
            return True, "Group has been updated succesfully", ret_obj
        else:
            return False, "Group has not been updated succesfully", None
