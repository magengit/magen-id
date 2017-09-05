from id.id_service.magenid.idsapp.idsserver.lib.db.models.magen_client_models import *
from id.id_service.magenid.idsapp.idsserver.lib.db.db_exception_handler import *
from id.id_service.magenid.idsapp.idsserver.utils.utilities import *

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)


class MagenGroupDao:
    @classmethod
    def update(self, dic):
        try:
            group=MagenGroup.objects.get(ug_name=dic["ug_name"])
            if group:
              group.update(ug_id=dic["ug_id"])

            updated_group = MagenGroup.objects.get(ug_name=dic["ug_name"])
            return updated_group

        except Exception as e:
            logger.error(e.args[0])
            return DbException(e, "error")

    @classmethod
    def insert(self, group_dict):
        group=None
        try:
            group = MagenGroup(ug_name=str(group_dict["ug_name"]))
            group.ug_id = group_dict["ug_id"]
            group.save(validate=False)
            return group
        except Exception as e:
            if 'duplicate' in e.args[0]:
                logger.debug("oauth group %s already exist in the database",group_dict["ug_name"])
                return MagenGroup.objects.get(ug_name=group_dict["ug_name"])
            else:
                logger.error("ERROR: %s",e)
                return DbException(e, "error")
        return group

    @classmethod
    def insert_many(self, group_dict_list):
        list_of_return_groups = []
        try:
          for group_dict in group_dict_list:
             group = self.insert(group_dict)
             list_of_return_groups.append(group)
          return list_of_return_groups
        except Exception as e:
            logger.error("ERROR: %s",e)
            return []
        return list_of_return_groups

    @classmethod
    def get_all(self):
        return MagenGroup.objects.all()

    @classmethod
    def get_by_name(self, ug_name):
        try:
          return MagenGroup.objects.get(ug_name=ug_name)
        except Exception as e:
            logger.error("ERROR: %s",e)
            return DbException(e, "error")

    @classmethod
    def delete_by_name(self, ug_name):
        try:
            group = self.get_by_name(ug_name)
            group.delete()
            return True
        except Exception as e:
            logger.error(e.args[0])
            return False

    @classmethod
    def delete_all(self):
        try:
          groups = MagenGroup.objects.all()
          for group in groups:
            group.delete()

          new_groups = MagenGroup.objects.all()
          if len(new_groups) == 0:
            return True
          else:
              return DbException("Error in deleting all", "error")
        except Exception as e:
            logger.error(e.args[0])
            return False