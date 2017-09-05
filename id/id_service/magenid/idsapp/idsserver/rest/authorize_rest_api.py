from id.id_service.magenid.idsapp.idsserver.views.home import *
from magen_rest_apis.rest_server_apis import RestServerApis
from magen_rest_apis.rest_client_apis import RestClientApis
from http import HTTPStatus

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"



@ids.route('/oauth/token', methods=['GET', 'POST'])
@openid_connect_provider.token_handler
def token(token, request,*args, **kwargs):
    """ 
    Retrieve token info
    url: http://localhost:5030/oauth/token

    :param client_id: this is the client id of the connected app
    :param grant_type: this is the grant type
    :param client_secret: this is the client secret of the connected app
    :param code: this is the authorized code
    :return: http response with token info 
    :rtype: json 
    """    
    logger.debug('token.encoded_token: %s',token.encoded_token)
    if token is None:
        client_info_dic = {}
        client_info_dic["error"] = "Token is not found"
        return (jsonify(client_info_dic))
    else:
       token_str=token.encoded_token.decode()

       token_dic={}
       token_dic['access_token']=token.access_token
       token_dic['refresh_token']=token.refresh_token
       token_dic['token_type']='magen-pop'
       token_dic['expires_in']=3600
       token_dic['magen_id_token']=token_str
       token_dic['mc_id']=token.mc_id
       logger.debug('token_dic: $s',token_dic)
       return(jsonify(token_dic))


@ids.route('/oauth/tokeninfo', methods=['GET', 'POST'])
def get_magen_client_info(*args, **kwargs):
    """ 
    Retrieve token info
    url: http://localhost:5030/oauth/tokeninfo

    :param id_token: this is the id of the token
    :return: http response with user and client info 
    :rtype: json 
    """     
    id_token = request.args.get('id_token')
    token=tokendao.getTokenByIdToken(id_token.strip())
    client_info_dic={}


    logger.debug(datetime.datetime.utcnow())
    logger.debug(token.expires)
    #validate the expire time
    if datetime.datetime.utcnow() > token.expires:
            client_info_dic["error"]= "invalid_mid_token"
            client_info_dic["error_description"]= "You MID token has been expired. It is not valid anymored"
            return(jsonify(client_info_dic))

    logger.debug("==client.client_secret=11==")
    client=token.client
    logger.debug("==client.client_secret=22==")
    user=token.user
    logger.debug("==client.client_secret=33==")
    logger.debug("==client.client_secret=== %s", client.client_secret)
    logger.debug("==client.jwt_alg=== %s",client.jwt_alg)
    logger.debug("==id_token=== %s", id_token)
    logger.debug("==user=== %s", user.username)

    decoded_id_token = jwt.decode(id_token, client.client_secret, algorithm=client.jwt_alg,options={'verify_aud': False})
    logger.debug("==decoded_id_token=== %s", decoded_id_token)

    client_info_dic["iss"]= decoded_id_token['iss']
    client_info_dic["sub"]= decoded_id_token['sub']
    client_info_dic["aud"]= decoded_id_token['aud']
    client_info_dic["iat"]= decoded_id_token['iat']
    client_info_dic["exp"]= decoded_id_token['exp']
    client_info_dic["auth_time"] = decoded_id_token['auth_time']

    client_info_dic["mc_id"]= token.mc_id
    client_info_dic["username"]= user.username
    client_info_dic["email_verified"]= "true"
    client_info_dic["first_name" ]= user.first_name
    client_info_dic["last_name" ]= user.last_name
    client_info_dic["picture"]= user.photo
    client_info_dic["locale"]= user.local
    client_info_dic["department"]= user.department
    client_info_dic["u_groups"]= user.u_groups
    client_info_dic["role"]= user.role
    client_info_dic["registered_on"]= user.registered_on
    client_info_dic["idp"]= user.idp
    client_info_dic["u_clients"] = user.u_clients
    client_info_dic["last_login"] = user.last_login
    client_info_dic["registered_on"] = user.registered_on
    client_info_dic["display_name"] = user.display_name
    client_info_dic["position"] = user.position


    logger.debug('client_info_dic: %s',client_info_dic)
    return(jsonify(client_info_dic))

@ids.route('/oauth/userinfo', methods=['GET', 'POST'])
def get_userinfo(*args, **kwargs):
        """ 
        Retrieve token info
        url: http://localhost:5030/oauth/userinfo

        :param access_token: this is the access_token in the Authorization header parameter
        :return: http response with user info 
        :rtype: json 
        """ 
        auth = request.headers['Authorization']

        access_token=auth.split(' ')[1]
        token=tokendao.getTokenByAccessToken(access_token.strip())

        #validate the expire time
        if datetime.datetime.utcnow() > token.expires:
            return get_json_response('{"access_token":"'+token.access_token
                                     +'","error":"' +'Session Expired'+'"}')

        #validate scope

        client = token.client
        user=client.user
        logger.debug('client.client_id: %s',client.client_id)
        logger.debug('user.username: %s',user.username)
        return get_json_response('{"access_token":"'+token.access_token
                                 +'","username":"' +user.username
                                 +'","first_name":"' +user.first_name
                                 +'","last_name":"' +user.last_name
                                 +'","role":"' +user.role
                                 +'","scopes":"' +client.default_scopes[0]
                                 #+'","email":"' +user.email
                                 #+'","email_verified":"' +user.email_verified
                                 +'"}')
