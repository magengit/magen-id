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


class MagenClientDao:
    @classmethod
    def get_all(self):
        try:
            clients = MagenClient.objects.all()
        except Exception as e:  # pragma: no cover
            logger.error("ERROR: %s",e)
            return None
        return clients

    @classmethod
    def get_by_mc_id(self, mc_id):
        try:
            client = MagenClient.objects.get(mc_id=mc_id)
            logger.debug("username: %s", client.user)
            return client
        except Exception as e:  # pragma: no cover
            #logger.error("ERROR: %s",e)
            return None

    @classmethod
    def get_by_user_and_device_id(self, user,device_id):
        try:
            logger.debug("====user==== %s  ",user)
            logger.debug("====device_id==== %s  ", device_id)
            clients = self.get_all()
            found = False

            client=None
            for c in clients:
                logger.debug("%s,%s",c.user,c.device_id)
                logger.debug((c.user == user and c.device_id == device_id))
                if (c.user == user and c.device_id == device_id):
                    found = True
                    client=c
                    break
            #print("Is client found====", found)
            return client
        except Exception as e:
            logger.error("ERROR: %s",e)
            return None

    @classmethod
    def insert(self, dic):
        client = self.get_by_user_and_device_id(dic["user"],dic["device_id"])
        if client is not None:
          logger.debug("====XXXXXXX client ==== %s  ", client.user)
          logger.debug("====XXXXXXX client ==== %s  ", client.device_id)
          logger.debug("====XXXXXXX client ==== %s  ", client.ip)
          logger.debug("====XXXXXXX client ==== %s  ", client.mac)
          logger.debug("====XXXXXXX client ==== %s  ", client.revision)
        if client is None:
          try:
            client = MagenClient(mc_id=dic["mc_id"])
            client.user = dic["user"]
            client.device_id = dic["device_id"]
            client.ip = dic["ip"]
            client.mac = dic["mac"]
            client.revision = dic["revision"]
            client.save(validate=False)
            return client
          except Exception as e:
            return None
        return client

    @classmethod
    def insert_many(self, client_dict_list):
        list_of_return_clients = []
        try:
           for client_dict in client_dict_list:
             client = self.insert(client_dict)
             if client is not None:
               list_of_return_clients.append(client)
           return list_of_return_clients
        except Exception as e:  # pragma: no cover
          logger.error("ERROR: %s",e)
          return []

    @classmethod
    def delete_by_mc_id(self, mc_id):
        try:
            client = self.get_by_mc_id(mc_id)

            if self.get_by_mc_id(mc_id):
              client.delete()
              return True
            else:
              return False
        except Exception as e:  # pragma: no cover
            #logger.error("ERROR: %s",e)
            return False

    @classmethod
    def delete_all(self):
        clients = MagenClient.objects.all()
        for client in clients:
            client.delete()

        new_clients = MagenClient.objects.all()
        return new_clients

    @classmethod
    def update(self, dic):
        client_id = dic["mc_id"]
        try:
            client = MagenClient.objects.get(mc_id=client_id)
            if client is not None:
                client.update(user=dic["user"], device_id=dic["device_id"], ip=dic["ip"], mac=dic["mac"],
                              revision=dic["revision"])
                updated_client = MagenClient.objects.get(mc_id=client_id)
                return updated_client
            else:
                logger.error('problem in updating client')  # pragma: no cover
                return None  # pragma: no cover
        except Exception as e:  # pragma: no cover
            logger.error("ERROR: %s",e)
            return None
