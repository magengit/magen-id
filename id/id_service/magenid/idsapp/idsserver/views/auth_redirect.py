
from id.id_service.magenid.idsapp.idsserver.views.home import *
from urllib.parse import urlencode
import requests,traceback
from uuid import uuid4


__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"




@ids.route('/oauth/ext/authorize', methods=['GET'])
@openid_connect_provider.authorize_handler
def ext_authorize(*args, **kwargs):
    if request.args.get('state'):
        state=request.args.get('state')
        session['org_state']=state
    else:
        state = str(uuid4())
    session['state']=state


    idp = request.args.get('idp')
    session['idp']=idp

    logger.debug('idp========== %s',idp)

    serviceDao.saveService(request,state,'')
    logger.debug('save client info in session')
    #saveClientInfoInSession(request)
    logger.debug('get external IdP info from database')
    validate = False
    idp_obj=extIdpDao.getIdpByName(idp)
    if idp_obj:
        access_token_validation_url=idp_obj.user_info_url
        if idp == 'cisco_box':
          if access_token_validation_url != '':
             validate=True
    if idp=='cisco_box':
      logger.debug('get user info from cisco_box using access token %s',idp)
      if request.args.get('username') is None:
          return 'username is not available'
      if request.args.get('access_token'):
         access_token=request.args.get('access_token')
         if validate:
           if validateAccessToken(idp_obj.user_info_url,access_token):
             client = Client.objects.get(client_id=request.args.get('client_id'))
             logger.debug('client id from database======= %s',client.client_id)
             kwargs['client'] = client
             session['username'] = request.args.get('username')
             logger.debug('USER FROM URL======= %s',request.args.get('username'))
             user = userdao.getUserByUserName(request.args.get('username'))
             if user:
               kwargs['user'] = userdao.getUserByUserName(request.args.get('username'))
               return render_template('authorize-custom.html',response_type=request.args.get('response_type'),redirect_uri=request.args.get('redirect_uri'),is_authentication=True,state=state,nonce=request.args.get('nonce') ,code_challenge=request.args.get('code_c'),code_challenge_method=request.args.get('code_c_meth'), **kwargs)
             else:
               return 'user not found in the system'
           else:
            return 'your access token is not valid anymore. Please re-authenticate'
         else:
             client = Client.objects.get(client_id=request.args.get('client_id'))
             logger.debug('client id from database======= %s', client.client_id)
             kwargs['client'] = client
             session['username'] = request.args.get('username')
             logger.debug('USER FROM URL======= %s', request.args.get('username'))
             user = userdao.getUserByUserName(request.args.get('username'))
             if user:
                 kwargs['user'] = userdao.getUserByUserName(request.args.get('username'))
                 return render_template('authorize-custom.html', response_type=request.args.get('response_type'),
                                        redirect_uri=request.args.get('redirect_uri'), is_authentication=True,
                                        state=state, nonce=request.args.get('nonce'),
                                        code_challenge=request.args.get('code_c'),
                                        code_challenge_method=request.args.get('code_c_meth'), **kwargs)
             else:
                 return 'user not found in the system'
      else:
          return 'access token is not available'
    else:
        if request.args.get('nonce'):    
          magen_ids_nonce=request.args.get('nonce')
          session['magen_ids_nonce']=magen_ids_nonce
        if request.args.get('response_type'):      
          magen_ids_response_type=request.args.get('response_type')
          session['magen_ids_response_type']=magen_ids_response_type
        if request.args.get('code_c'):  
          magen_ids_code_c=request.args.get('code_c')
          session['magen_ids_code_c']=magen_ids_code_c
        if request.args.get('code_c_meth'):
          magen_ids_code_c_meth=request.args.get('code_c_meth')
          session['magen_ids_code_c_meth']=magen_ids_code_c_meth
        if request.args.get('client_id'):
          magen_ids_client_id=request.args.get('client_id')
          session['magen_ids_client_id']=magen_ids_client_id
        if request.args.get('scopes'):
          magen_ids_scopes=request.args.get('scopes')
          session['magen_ids_scopes']=magen_ids_scopes
        if request.args.get('redirect_uri'):
          magen_ids_redirect_uri=request.args.get('redirect_uri')
          session['magen_ids_redirect_uri']=magen_ids_redirect_uri
        if request.args.get('username'):
          magen_ids_username=request.args.get('username')
          session['magen_ids_username']=magen_ids_username 
        logger.debug('save external IdP info in session')
         
    
        oauthUrl=saveExIdpInfoInSession(idp_obj,state)
        logger.debug('redirect to external IdP at %s',oauthUrl)
        return redirect(oauthUrl)

def validateAccessToken(user_info_url,access_token):
  ids.logger.debug('########   USER INFO URL ####### %s', user_info_url)
  ids.logger.debug('########   USER ACCESS TOKEN ####### %s', access_token)
  return True
  data=get_user_info_from_external_idp_using_access_token_with_bearer(user_info_url,access_token)
  ids.logger.debug('########   USER DATA FROM CISCO BOX ####### %s', data)
  if data is not None:
     return True
  else:
     return False   
    

def saveExIdpInfoInSession(idp_obj,state):
    session['authz_url']=idp_obj.authz_url
    session['token_url']=idp_obj.token_url
    session['user_info_url']=idp_obj.user_info_url
    session['token_info_url']=idp_obj.token_info_url
    session['client_secret']=idp_obj.client_secret
    session['client_id']=idp_obj.client_id
    session['redirect_uri']=idp_obj.redirect_uri
    scope=idp_obj.scopes
    #scope=app.config[idp.upper()+'_SCOPE']
    session['scope']=scope
    oauthUrl=idp_obj.authz_url + '?response_type=code&client_id=' +idp_obj.client_id +'&redirect_uri=' +idp_obj.redirect_uri +'&state=' +state+'&scope=' +idp_obj.scopes
    return oauthUrl

def saveClientInfoInSession(request):
    session['magen_ids_nonce']=request.args.get('nonce')
    session['magen_ids_response_type']=request.args.get('response_type')
    session['magen_ids_code_c']=request.args.get('code_c')
    session['magen_ids_code_c_meth']=request.args.get('code_c_meth')
    session['magen_ids_client_id']=request.args.get('client_id')
    session['magen_ids_scopes']=request.args.get('scopes')
    session['magen_ids_redirect_uri']=request.args.get('redirect_uri')
    session['magen_ids_username']=request.args.get('username')



def get_user_info_from_external_idp_using_id_token(url,id_token):
        try:
            headers={'content-type': 'application/json'}
            response = requests.get(url + '?id_token=' + id_token, headers=headers,  verify=False)
            me_json = response.json()
        except:
            printErrorLog()
            return None
        return me_json


def get_user_info_from_external_idp_using_access_token_with_bearer(url,access_token):
    try:
       authorization_header = {"Authorization": "Bearer %s" % access_token}
       response = requests.get(url,headers=authorization_header)
       me_json = response.json()
    except:
       printErrorLog()
       return None
    return me_json

def get_user_info_from_external_idp_using_access_token(url,access_token):
    try:
       authorization_header = {"Authorization": "OAuth %s" % access_token}
       response = requests.get(url,headers=authorization_header)
       me_json = response.json()
    except:
       printErrorLog()
       return None
    return me_json


