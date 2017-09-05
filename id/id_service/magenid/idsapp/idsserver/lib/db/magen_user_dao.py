from id.id_service.magenid.idsapp.idsserver.lib.db.models.magen_client_models import *
from id.id_service.magenid.idsapp.idsserver.lib.db.db_exception_handler import *
from id.id_service.magenid.idsapp.idsserver.utils.utilities import *

from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash, gen_salt


__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)


class MagenUserDao:
    @classmethod
    def update(self, dic):
        uuid = dic["uuid"]

        try:
            user = MagenUser.objects.get(uuid=uuid)
            user.delete()
            return self.insert(dic)
        except Exception as e:
            logger.error("ERROR: %s",e)
            return None

    @classmethod
    def insert(self, user_dict):
        user=None

        try:
            user = MagenUser(uuid=user_dict["uuid"])
            user.username=user_dict["username"]
            user.password=user_dict["password"]
            user.u_clients = user_dict["u_clients"]
            user.department = user_dict["department"]
            user.u_groups = user_dict["u_groups"]
            user.position = user_dict["position"]
            user.display_name = user_dict["display_name"]
            user.first_name = user_dict["first_name"]
            user.last_name = user_dict["last_name"]
            user.email = user_dict["email"]
            user.last_login = get_now_time()
            user.registered_on = get_now_time()
            user.role =  user_dict["role"]
            user.idp = user_dict["idp"]
            user.save(validate=False)

        except Exception as e:
            if 'duplicate' in e.args[0]:
                logger.debug("user %s already exist in the database",user_dict["username"])
                user = self.get_by_user_name(user_dict["username"])
                return user
            else:
                logger.debug("problem")
                logger.error("ERROR: %s",e)
                return None
        return user

    @classmethod
    def insert_many(self, user_dict_list):
        list_of_return_users = []
        try:
           for user_dict in user_dict_list:
              user = self.insert(user_dict)
              list_of_return_users.append(user)
        except Exception as e:
            logger.error("ERROR: %s",e)
        return list_of_return_users

    @classmethod
    def get_all(self):
        new_users=[]
        try:
            users = MagenUser.objects.all()
            logger.debug(len(users))
            return users
   
        except Exception as e:
            logger.error("ERROR: %s",e)
            return None
        return new_users

    @classmethod
    def get_by_user_name(self, username):
        try:
            user = MagenUser.objects.get(username=username)

            return user
        except Exception as e:
            logger.error("ERROR: %s",e)
            return None


    @classmethod
    def get_by_uuid(self, uuid):
        try:
            user = MagenUser.objects.get(uuid=uuid)
            logger.debug("username: %s", user.username)
            return user
        except Exception as e:
            logger.error("ERROR: %s",e)
            return None

    @classmethod
    def delete_by_uuid(self, uuid):
        try:
            user = MagenUser.objects.get(uuid=uuid)
            user.delete()
            return True
        except Exception as e:
            logger.error("ERROR: %s",e)
            return False

    @classmethod
    def delete_by_username(self, username):
        try:
            user = MagenUser.objects.get(username=username)
            user.delete()
            return True
        except Exception as e:
            logger.error("ERROR: %s",e)
            return False

    @classmethod
    def delete_all(self):
        new_users=None
        try:
          users = MagenUser.objects.all()
          for user in users:
            user.delete()
          new_users = MagenUser.objects.all()
        except Exception as e:
            logger.error("ERROR: %s",e)
            return None
        return new_users

    @classmethod
    def getAllUsers(self):
        users=self.get_all()
        return users

    @classmethod
    def getUserByUserName(self,username):
        try:
            user = self.get_by_user_name(username=username)
            if user:
              logger.debug("username: %s",user.username)
            return user
        except Exception as e:
            logger.error("ERROR: %s",e)
            return None

    @classmethod
    def saveDynamicUser(self,username):
        user=None
        try:
          logger.debug('insert dynamic user: %s',username)
          user = MagenUser(username=username)
          user.password='somepass'
          user.first_name='fname'
          user.last_name="lname"
          user.last_login = get_now_time()
          user.registered_on = get_now_time()
          user.role='standard'
          user.idp=""
          user.group=""
          user.department=""
          user.photo=""
          user.local=""
          user.save(validate=False)
        except Exception as e:
            logger.error("ERROR: %s",e)
            return None
        return user

    @classmethod
    def saveUser(self,dic):
        user=None
        try:
           user=self.insert(dic)
        except Exception as e:
            logger.error("ERROR: %s",e)
            return None
        return user


    @classmethod
    def saveForMappingUser(self,dic):
        user=None
        try:
           user=self.insert(dic)
        except Exception as e:
            logger.error("ERROR: %s",e)
            return None
        return user


    @classmethod
    def updateUserInfoWithExternalIdP(self,dic):
        user=None
        try:
          user = MagenUser(username=dic["username"])
          user.password=""
          user.first_name=dic["first_name"]
          user.last_name=dic["last_name"]
          user.last_login = get_now_time()
          user.registered_on = get_now_time()
          user.photo=dic["photo"]
          user.local=dic["local"]
          user.role=""
          user.idp=dic["idp"]
          user.group=""
          user.department=""
          user.save(validate=False)
        except Exception as e:
            logger.error("ERROR: %s",e)
            try:
              user = MagenUser.objects.get(username=dic["username"])
              user.update(idp=dic["idp"],last_login = get_now_time(),first_name=dic["first_name"],last_name=dic["last_name"],photo=dic["photo"],local=dic["local"])
            except Exception as e:
                logger.error("ERROR: %s",e)
                return None
        return user

    @classmethod
    def deleteUser(self,user):
        try:
            user.delete()
        except Exception as e:
            logger.error("ERROR: %s",e)

    @classmethod
    def updateUserLoginTime(self,username):
        user = None
        try:
            user = MagenUser.objects.get(username=username)
            user.update(last_login=get_now_time())
        except Exception as e:
            logger.error("ERROR: %s",e)
            return user
        return user

    @classmethod
    def updateUser(self,dic):
        user=None
        try:
            user = MagenUser.objects.get(username=dic["username"])
            user.update(password=dic["password"],
            first_name=dic["first_name"],
            last_name=dic["last_name"],
            role=dic["role"],
            idp=dic["idp"]
            )
        except Exception as e:
            logger.error("ERROR: %s",e)
            return user
        return user