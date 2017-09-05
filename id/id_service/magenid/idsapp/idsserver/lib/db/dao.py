import datetime
from hashlib import md5
import json,traceback
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash, gen_salt

import traceback

import logging
import logging.config
from logging.handlers import RotatingFileHandler

from id.id_service.magenid.idsapp.idsserver.lib.db.models.models import *
from id.id_service.magenid.idsapp.idsserver.utils.utilities import *


__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)

class BaseDao():
    #create user object
    def _creatUser(self,username,password,first_name,last_name,last_login,registered_on,role,idp,group,department,photo,local):
        user = User(username=username)
        user.password=password
        user.first_name=first_name
        user.last_name=last_name
        user.last_login = last_name
        user.registered_on = registered_on
        user.role=role
        user.idp=idp
        user.group=group
        user.department=department
        user.photo=photo
        user.local=local
        return user

    #create client object
    def _creatClient(self,name,client_id,client_secret,user,response_type,redirect_uris,default_scopes,jwt_alg):
        client=Client(client_id=client_id)
        client.client_name = name
        client.user = user
        client.client_secret = client_secret
        client.response_type =  response_type
        client.redirect_uris = redirect_uris
        client.default_scopes = default_scopes
        client.jwt_alg = jwt_alg
        client.date_created = get_now_time()
        return client

    #create client object
    def _creatDynamicClient(self,
        client_name,
        client_id,
        client_secret,
        user,
        redirect_uris,
        expire,
        response_type=None,
        default_scopes=None,
        jwt_alg=None,
        registration_client_uri=None,
        grant_types=None,
        application_type=None,
        contacts=None,
        logo_uri=None,
        client_uri=None,
        policy_uri=None,
        tos_uri=None,
        jwks_uri=None,
        jwks=None,
        sector_identifier_uri=None,
        subject_type=None,
        id_token_signed_response_alg=None,
        id_token_encrypted_response_alg=None,
        id_token_encrypted_response_enc=None,
        userinfo_signed_response_alg=None,
        userinfo_encrypted_response_alg=None,
        userinfo_encrypted_response_enc=None,
        request_object_signing_alg=None,
        request_object_encryption_alg=None,
        request_object_encryption_enc=None,
        token_endpoint_auth_method=None,
        token_endpoint_auth_signing_alg=None,
        default_max_age=None,
        require_auth_time=None,
        default_acr_values=None,
        initiate_login_uri=None,
        request_uris=None,
        device_id=None,
        mac=None,
        ip=None,
        revision=None,
        dns_name=None,
        client_description=None,
        reuse_refresh_token=None,
        dynamically_registered=None,
        allow_introspection=None,
        id_token_validity_seconds=None,
        clear_access_tokens_on_refresh=None):
        client=Client(client_id=client_id)
        client.client_name = client_name
        client.user = user
        client.client_secret = client_secret
        client.response_type =  response_type
        client.redirect_uris = redirect_uris
        client.default_scopes = default_scopes
        client.jwt_alg = jwt_alg
        client.date_created = get_now_time()
        client.client_secret_expires_at=get_expire_time(expire)
        client.registration_client_uri=registration_client_uri

        client.grant_types=grant_types
        client.application_type= application_type
        client.contacts= contacts
        client.logo_uri= logo_uri
        client.client_uri= client_uri
        client.policy_uri= policy_uri
        client.tos_uri= tos_uri
        client.jwks_uri= jwks_uri
        client.jwks= jwks
        client.sector_identifier_uri= sector_identifier_uri
        client.subject_type= subject_type
        client.id_token_signed_response_alg= id_token_signed_response_alg
        client.id_token_encrypted_response_alg= id_token_encrypted_response_alg
        client.id_token_encrypted_response_enc= id_token_encrypted_response_enc
        client.userinfo_signed_response_alg= userinfo_signed_response_alg
        client.userinfo_encrypted_response_alg= userinfo_encrypted_response_alg
        client.userinfo_encrypted_response_enc= userinfo_encrypted_response_enc
        client.request_object_signing_alg= request_object_signing_alg
        client.request_object_encryption_alg= request_object_encryption_alg
        client.request_object_encryption_enc= request_object_encryption_enc
        client.token_endpoint_auth_method= token_endpoint_auth_method
        client.token_endpoint_auth_signing_alg= token_endpoint_auth_signing_alg
        client.default_max_age= default_max_age
        client.require_auth_time= require_auth_time
        client.default_acr_values= default_acr_values
        client.initiate_login_uri= initiate_login_uri
        client.request_uris= request_uris

        client.device_id=device_id
        client.mac=mac
        client.ip=ip
        client.revision=revision
        client.dns_name=dns_name
        return client

    # create code object
    def _creatCode(self,user, client_id,code,nonce,auth,expire,scopes,code_c,code_c_meth):
        code_obj = Code(code=code)
        code_obj.nonce = nonce
        code_obj.is_authentication = auth
        code_obj.code_challenge = code_c
        code_obj.code_challenge_method = code_c_meth
        code_obj.user = user
        code_obj.client = Client.objects.get(client_id=client_id)
        code_obj.expires = get_expire_time(expire)
        code_obj.scopes = scopes
        return code_obj

    # create grant object
    def _creatGrant(self,user, client_id,code,redirect_uri,expire):
        #logger.debug('_creatGrant=====user====', user.username)
        grant = Grant(user=user)
        grant.client = Client.objects.get(client_id=client_id)
        grant.code = code
        grant.expires = get_expire_time(expire)
        grant.redirect_uri=redirect_uri
        grant.scopes=code.scopes
        return grant

    # create token object
    def _creatToken(self,user, client,access_token,refresh_token,id_token,encoded_token,scopes,expire,magen_client_id):
        token = Token(user=user)
        token.client = client
        #token.token_type = token_type
        token.access_token = access_token
        token.refresh_token = refresh_token
        token.expires = get_expire_time(expire)
        token.scopes = scopes
        token.id_token = id_token
        token.encoded_token=encoded_token
        token.mc_id=magen_client_id
        return token

    # create token object
    def _creatService(self,state, nonce,response_type,code_c,code_c_meth,client_id,scopes,redirect_uri,username,external_token_info):
        service = Service(state=state)
        service.nonce = nonce
        service.response_type = response_type
        service.code_challenge = code_c
        service.code_challenge_method = code_c_meth
        service.client_id = client_id
        service.scopes = scopes
        service.redirect_uri=redirect_uri
        service.username=username
        service.external_token_info=external_token_info
        return service

    # create token object
    def _creatIdp(self,name,desc,client_id,client_secret,authz_url,token_url,user_info_url,redirect_uri,scopes,code_challenge,code_challenge_method,token_info_url):
        idp = ExtIdp(name=name)
        idp.desc = desc
        idp.client_id = client_id
        idp.client_secret = client_secret
        idp.authz_url = authz_url
        idp.token_url = token_url
        idp.user_info_url=user_info_url
        idp.token_info_url=token_info_url
        idp.redirect_uri=redirect_uri
        idp.scopes = scopes
        idp.code_challenge = code_challenge
        idp.code_challenge_method = code_challenge_method
        return idp

#################### DOMAIN #########################

class DomainDao(BaseDao):
    def getAllDomains(self):
        domains=Domain.objects.all()
        return domains

    def getDomainByDomainName(self,name):
        #logger.debug("====is user there=======")
        try:
            domain = Domain.objects.get(name=name)
            #logger.debug("username: %s",user.username)
            return domain
        except: # pragma: no cover
            #printErrorLog()
            return None
    def saveDomain(self,name,idp,allow):
        domain = Domain(name=name)
        domain.idp=idp
        domain.allow=allow

        try:
            domain.save(validate=False)
        except: # pragma: no cover
            domain = Domain.objects.get(name=name)
            domain.update(idp=idp,allow=allow)
            #logger.error('updated domain info ===')
        return domain

############### CLIENT #####################

class ClientDao(BaseDao):
    def getAllClients(self):
        try:
           clients=Client.objects.all()
           return clients
        except: # pragma: no cover
           printErrorLog()
           return None
    def getAllClientsByUserName(self,username):
        try:
           all_clients = Client.objects.all()
           clients=[]
           for c in all_clients:
               #logger.debug("c=====: %s ", c.client_name)
               if c.user.username==username:
                   clients.append(c)
           return clients
        except: # pragma: no cover
           printErrorLog()
           return []

    def getClientByClientId(self,client_id):
        try:
           client = Client.objects.get(client_id=client_id)
           logger.debug("client_id: %s ",client.client_id)
           return client
        except: # pragma: no cover
           printErrorLog()
           return None
    def getClientByClientIdAndCode(self, client_id,code):
        try:
           client = Client.objects.get(client_id=client_id,code=code)
           return client
        except: # pragma: no cover
           printErrorLog()
           return None
    def getRegisterClientDynamically(self,user,content,expire):

        application_type=content['application_type']
        redirect_uris=content['redirect_uris']
        client_name=content['client_name']
        client_id=get_rand_token(60)
        client_secret=get_rand_token(30)
        response_type=content['response_type']
        logo_uri=content['logo_uri']
        subject_type=content['subject_type']
        sector_identifier_uri=content['sector_identifier_uri']
        token_endpoint_auth_method=content['token_endpoint_auth_method']
        jwks_uri=content['jwks_uri']
        userinfo_encrypted_response_alg=content['userinfo_encrypted_response_alg']
        userinfo_encrypted_response_enc=content['userinfo_encrypted_response_enc']
        contacts=content['contacts']
        request_uris=content['request_uris']
        device_id=content['device_id']
        mac=content['mac']
        ip=content['ip']
        revision=content['revision']
        dns_name=content['dns_name']

        registration_client_uri=content['registration_client_uri']
        client_uri=content['client_uri']
        policy_uri=content['policy_uri']
        tos_uri=content['tos_uri']
        jwks_uri=content['jwks_uri']
        jwks=content['jwks']
        id_token_signed_response_alg=content['id_token_signed_response_alg']
        id_token_encrypted_response_alg=content['id_token_encrypted_response_alg']
        id_token_encrypted_response_enc=content['id_token_encrypted_response_enc']
        userinfo_signed_response_alg=content['userinfo_signed_response_alg']
        request_object_signing_alg=content['request_object_signing_alg']
        request_object_encryption_alg=content['request_object_encryption_alg']
        request_object_encryption_enc=content['request_object_encryption_enc']
        token_endpoint_auth_signing_alg=content['token_endpoint_auth_signing_alg']
        default_max_age=content['default_max_age']
        require_auth_time=content['require_auth_time']
        default_acr_values=content['default_acr_values']
        initiate_login_uri=content['initiate_login_uri']
        client_description=content['client_description']
        reuse_refresh_token=content['reuse_refresh_token']
        dynamically_registered=content['dynamically_registered']
        allow_introspection=content['allow_introspection']
        id_token_validity_seconds=expire
        clear_access_tokens_on_refresh=content['clear_access_tokens_on_refresh']


        grant_types=['authorization_code','implicit','refresh_token']

        jwt_alg="HS256"
        default_scopes="openid,profile,address,phone,offline_access"

        client=self._creatDynamicClient(
            client_name,
            client_id,
            client_secret,
            user,
            redirect_uris,
            expire,
            response_type,
            default_scopes,
            jwt_alg,
            registration_client_uri,
            grant_types,
            application_type,
            contacts,
            logo_uri,
            client_uri,
            policy_uri,
            tos_uri,
            jwks_uri,
            jwks,
            sector_identifier_uri,
            subject_type,
            id_token_signed_response_alg,
            id_token_encrypted_response_alg,
            id_token_encrypted_response_enc,
            userinfo_signed_response_alg,
            userinfo_encrypted_response_alg,
            userinfo_encrypted_response_enc,
            request_object_signing_alg,
            request_object_encryption_alg,
            request_object_encryption_enc,
            token_endpoint_auth_method,
            token_endpoint_auth_signing_alg,
            default_max_age,
            require_auth_time,
            default_acr_values,
            initiate_login_uri,
            request_uris,
            device_id,
            mac,
            ip,
            revision,
            dns_name,
            client_description,
            reuse_refresh_token,
            dynamically_registered,
            allow_introspection,
            id_token_validity_seconds,
            clear_access_tokens_on_refresh)
        try:
            client.save(validate=False)
        except Exception as e:
            if 'duplicate' in e.args[0]:
                logger.debug("oauth client %s is already exist",client.client_name)
                return client
            else:
                logging.exception(e)
        return client

        return dic


    def saveClient(self,user,dic):
        name=dic["client_name"]
        response_type=dic["response_type"]
        redirect_uris=dic["redirect_uris"]
        default_scopes =dic["default_scopes"]
        jwt_alg=dic["jwt_alg"]
        client_id =get_rand_token(60)
        client_secret = get_rand_token(30)

        if dic["client_id"]!='':
            client_id=dic["client_id"]
        if dic["client_secret"] != '':
            client_secret=dic["client_secret"]

        client_id=client_id
        client_secret=client_secret

        client=self._creatClient(name,client_id,client_secret,user,response_type,redirect_uris,default_scopes,jwt_alg)
        try:
            client.save(validate=False)
        except Exception as e:
            if 'duplicate' in e.args[0]:
                logger.debug("oauth %s  is already exist",client.client_name)
                return client
            else:
                logging.exception(e)
        return client

    def updateClient(self,client_id,name,response_type,redirect_uris,default_scopes,jwt_alg):
        client = Client.objects.get(client_id=client_id)
        try:
            client.update(client_name=name,response_type=response_type,redirect_uris=redirect_uris,default_scopes=default_scopes,jwt_alg=jwt_alg)
        except: # pragma: no cover
            logger.error('problem in updating client===')
            traceback.print_exc()
        return client
    def deleteClient(self,client):
        try:
            client.delete()
        except: # pragma: no cover
            logger.error('problem in deleting client===')


#######################################################
############### GRANT #####################

class GrantDao(BaseDao):
    def getAllGrants(self):
        grants=Grant.objects.all()
        return grants
    def getGrantByClientIdAndCode(self,client_id,code):
        client = Client.objects.get(client_id=client_id)
        grant = Grant.objects.get(client=client, code=code)
        return grant
    def getGrantByCode(self,code):
        grant = Grant.objects.get(code=code)
        return grant

    def saveGrant(self,user, client_id,code,nonce,auth,expire,redirect_uri,code_c,code_c_meth,scopes):
        logger.debug('######## DB SAVE CODE ######### %s',expire)
        code_obj=self._creatCode(user, client_id,code,nonce,auth,expire,scopes,code_c,code_c_meth)
        try:
            code_obj.save(validate=False)
            logger.debug('######## DB SAVE GRANT #########')
            grant = self._creatGrant(user, client_id, code_obj, redirect_uri,expire)
            try:
                grant.save(validate=False)
            except Exception as e:
                if 'duplicate' in e.args[0]:
                    logger.debug("grant %s is already exist in the database", grant.code)
                    return grant
                else:
                    logging.exception(e)

            return grant
        except: # pragma: no cover
            logging.exception(e)



#######################################################
############### CODE #####################

class CodeDao(BaseDao):
    def getAllCodes(self):
        codes=Code.objects.all()
        return codes
    def getCodeByCode(self,code):
        code = Code.objects.get(code=code)
        return code

    def deleteCode(self,code):
        code.delete()

#######################################################
############### TOKEN #####################

class TokenDao(BaseDao):
    def getAllTokens(self):
        tokens=Token.objects.all()
        return tokens
    def getTokenByClientAndRefreshToken(self,ref_token,client):
        token = Token.objects.get(refresh_token=ref_token,client=client)
        return token
    def getTokenByClientAndRefreshToken(self,client):
        token = Token.objects.get(client=client)
        return token
    def getTokenByAccessToken(self,access_token):
        token = Token.objects.get(access_token=access_token)
        return token
    def getTokenByIdToken(self,id_token):
        token = Token.objects.get(encoded_token=id_token)
        return token

    def saveToken(self,user, client,access_token,refresh_token,_id_token,encoded_token,_scopes,expire,magen_client_id):
        token = self._creatToken(user, client,access_token,refresh_token,_id_token,encoded_token,_scopes,expire,magen_client_id)
        try:
            token.save(validate=False)
        except Exception as e:
                if 'duplicate' in e.args[0]:
                    logger.debug("oauth token %s is already exist in the database", token.access_token)
                    return token
                else:
                    logging.exception(e)

        return token

#######################################################
############### USER #####################

class ServiceDao(BaseDao):
    def getAllServices(self):
        services=Service.objects.all()
        return services
    def getServiceByState(self,state):
        service = Service.objects.get(state=state)
        return service
    def updateService(self,state,external_token_info):
        service = Service.objects.get(state=state)

        return service
    def saveService(self,request,state,external_token_info):
        nonce=request.args.get('nonce')
        response_type=request.args.get('response_type')
        code_c=request.args.get('code_c')
        code_c_meth=request.args.get('code_c_meth')
        client_id=request.args.get('client_id')
        scopes=request.args.get('scopes')
        redirect_uri=request.args.get('redirect_uri')
        username=request.args.get('username')
        service=self._creatService(state, nonce,response_type,code_c,code_c_meth,client_id,scopes,redirect_uri,username,external_token_info)
        try:
            service.save(validate=False)
        except Exception as e:
                if 'duplicate' in e.args[0]:
                    logger.debug("oauth token %s is already exist in the database", service.client_id)
                    return service
                else:
                    logging.exception(e)
        return service




class ExtIdpDao(BaseDao):
    def getAllIdps(self):
        idps=ExtIdp.objects.all()
        return idps

    def getIdpByName(self,name):
        try:
           idp = ExtIdp.objects.get(name=name)
           if idp is None:
             return None
           else:
             return idp
        except:
            return None

    def saveIdp(self,request):
        name = request.form["name"]
        desc = request.form["desc"]
        client_id = request.form["client_id"]
        client_secret =  request.form["client_secret"]
        authz_url =  request.form["authz_url"]
        token_url =  request.form["token_url"]
        user_info_url =  request.form["user_info_url"]
        redirect_uri = request.form["redirect_uri"]
        scopes = request.form["scopes"]
        code_challenge = request.form["code_challenge"]
        code_challenge_method = request.form["code_challenge_method"]
        token_info_url= request.form["token_info_url"]
        idp=self._creatIdp(name,desc,client_id,client_secret,authz_url,token_url,user_info_url,redirect_uri,scopes,code_challenge,code_challenge_method,token_info_url)
        try:
            idp.save(validate=False)
        except Exception as e:
                if 'duplicate' in e.args[0]:
                    logger.debug("%s idp is already exist in the database", idp.name)
                    return idp
                else:
                    logging.exception(e)
        return idp

    def saveIdpNoRquest(self,
    name=None,
    desc=None,
    client_id=None,
    client_secret=None,
    authz_url=None,
    token_url=None,
    user_info_url=None,
    redirect_uri=None,
    scopes=None,
    code_challenge=None,
    code_challenge_method=None,
    token_info_url=None):

        idp=self._creatIdp(name,desc,client_id,client_secret,authz_url,token_url,user_info_url,redirect_uri,scopes,code_challenge,code_challenge_method,token_info_url)
        try:
            idp.save(validate=False)
        except Exception as e:
                if 'duplicate' in e.args[0]:
                    logger.debug("%s idp is already exist in the database", idp.name)
                    return idp
                else:
                    logging.exception(e)
        return idp

    def deleteIdp(self,idp):
        try:
            idp.delete()
        except: # pragma: no cover
            logger.error('problem in deleting user===')
    def updateIdp(self,name,request):
        idp = ExtIdp.objects.get(name=name)
        desc = request.form["desc"]
        client_id = request.form["client_id"]
        client_secret =  request.form["client_secret"]
        authz_url =  request.form["authz_url"]
        token_url =  request.form["token_url"]
        user_info_url =  request.form["user_info_url"]
        redirect_uri = request.form["redirect_uri"]
        scopes = request.form["scopes"]
        code_challenge = request.form["code_challenge"]
        code_challenge_method = request.form["code_challenge_method"]
        token_info_url= request.form["token_info_url"]
        try:
            idp.update(desc=desc,
            client_id=client_id,
            client_secret=client_secret,
            authz_url=authz_url,
            token_url=token_url,
            user_info_url=user_info_url,
            redirect_uri=redirect_uri,
            scopes=scopes,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            token_info_url=token_info_url)
        except: # pragma: no cover
            logger.error('problem in updating user===')
        return idp
