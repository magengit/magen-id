
from id.id_service.magenid.idsapp.idsserver.views.home import *
from id.id_service.magenid.idsapp.idsserver.views.auth_redirect import *
from urllib.parse import urlencode
import requests,traceback
from uuid import uuid4


__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"




@ids.route('/oauth/ext/callback', methods=['GET'])
#@openid_connect_provider.authorize_handler
def ext_callback(*args, **kwargs):
    #return redirect('https://login.salesforce.com/')
        #print(request.url)
    try:
        ret_state = request.args.get('state')
        ids.logger.debug('ret_state==========' + ret_state)

        if 'state' in session:
            state=session['state']
            ids.logger.debug('state==========' + state)
            if ret_state!=state:
                msg='State does not match'
                return render_template('error.html',msg=msg)
            idp=session['idp']
            ids.logger.debug('session state==========' + state + '    idp=' + idp)

        token_url=session['token_url']
        client_id=session['client_id']
        client_secret=session['client_secret']
        redirect_uri=session['redirect_uri']


        service=serviceDao.getServiceByState(state)
        username=service.username

        code = request.args.get('code')
        ids.logger.debug('code==========' + code)
        if code is not None:
           access_token_req = {
              "code": code,
              "client_id": client_id,
              "client_secret": client_secret,
              "redirect_uri": redirect_uri,
              "grant_type": "authorization_code",
           }
           headers={}
           content_length = len(urlencode(access_token_req))
           access_token_req['content-length'] = str(content_length)
           #r=requests.post(access_token_url, params=access_token_req, headers=headers,  verify='certs/server.crt')
           if idp=="sf":
               #get access token from the idp
               r=requests.post(token_url, params=access_token_req, headers=headers,  verify=True)
               ids.logger.debug('r.text==========' + r.text)
               data = json.loads(r.text)
               ids.logger.debug(data)
               id_token = data['id_token']
               access_token = data['access_token']
               #get user inormation from idp
               data=get_user_info_from_external_idp_using_access_token(session['user_info_url'],access_token)
               ids.logger.debug(data)
               email=data['email']
               preferred_username=data['preferred_username']
               dic={}
               
               dic["given_name"]=data['given_name']
               dic["family_name"]=data['family_name']
               dic["picture"]=data['picture']
               dic["locale"]=data['locale']
               if preferred_username==username:
                  dic={}
                  dic["username"]=username
                  user=userdao.updateUserInfoWithExternalIdP(dic)
               else:
                  domain_name = username.split("@")[1]
                  domain_db=domaindao.getDomainByDomainName(domain_name)
                  if domain_db:
                    if domain_db.allow==1:
                       dic={}
                       dic["username"]=preferred_username
                       user=userdao.updateUserInfoWithExternalIdP(dic)
                    ids.logger.debug('do not update data')
               ids.logger.debug('============111===========')

           elif idp=="go":
               r = requests.post(token_url, data=access_token_req)
               data = json.loads(r.text)
               id_token = data['id_token']
               access_token = data['access_token']
               data=get_user_info_from_external_idp_using_access_token(session['user_info_url'],access_token)
               ids.logger.debug(data)
               ids.logger.debug(data['given_name'])
               ids.logger.debug(data['family_name'])
               ids.logger.debug(data['picture'])
               ids.logger.debug(data['locale'])
               dic={}
               dic["given_name"]=data['given_name']
               dic["family_name"]=data['family_name']
               dic["picture"]=data['picture']
               dic["locale"]=data['locale']
               if 'email' in data:
                 email=data['email']
                 if email==username:
                   dic["username"]=username
                   user=userdao.updateUserInfoWithExternalIdP(dic)
                 else:
                    domain_name = username.split("@")[1]
                    domain_db=domaindao.getDomainByDomainName(domain_name)
                    if domain_db:
                      if domain_db.allow==1:
                         dic["username"]=email
                         #check if the user is in the database
                         user=userdao.updateUserInfoWithExternalIdP(dic)
                    ids.logger.debug('do not update data')                
               else:
                 ids.logger.debug('do not update data')
           else:
               r = requests.post(token_url, data=access_token_req)
               data = json.loads(r.text)
               id_token = data['id_token']

               ids.logger.debug(id_token)
               if not validate_token(id_token):
                   msg='User is not authenticated by external IdP'
                   return render_template('error.html',msg=msg)

           service =serviceDao.updateService(state,id_token)
           client_id = service.client_id
           response_type=service.response_type
           #logger.debug('current user==========', client_id)
           client = Client.objects.get(client_id=client_id)
           is_authentication=True

           kwargs['client'] = client
           kwargs['user'] = userdao.getUserByUserName(username)
           redirect_uri = service.redirect_uri

           nonce=service.nonce
           code_challenge = service.code_challenge
           code_challenge_method = service.code_challenge_method

           
           session['username'] = username


           if 'org_state' in session:
               state=session['org_state']
           else:
               state=None
           return render_template('authorize-custom.html',response_type=response_type,redirect_uri=redirect_uri,is_authentication=True,state=state,nonce=nonce ,code_challenge=code_challenge,code_challenge_method=code_challenge_method, **kwargs)

    except:
        msg='User is not authenticated by external IdP'
        print('>>>>>>>>>>>> traceback <<<<<<<<<<<<<')
        traceback.print_exc()
        print('>>>>>>>>>>>> end of traceback <<<<<<')
        return render_template('error.html',msg=msg)



def validate_token(id_token):
    return True

@ids.route('/oauth/authorize', methods=['GET', 'POST'])
@login_required
@openid_connect_provider.authorize_handler
def authorize(*args, **kwargs):
    user = current_user()

    # state = request.args.get('state')
    # logger.debug('===============I AM AT OPEN ID SERVER================')
    # return redirect('http://localhost:8000/page2?state=' + state)

    if request.method == 'GET':
        client_id = request.args.get('client_id')
        #logger.debug('current user==========', client_id)
        client = Client.objects.get(client_id=client_id)
        is_authentication=True
        #logger.debug('========authorize:client=========', client)
        if request.args.get('scope') is None:
            arrScope=client.default_scopes[0].split(',')
        else:
            arrScope=request.args.get('scope').split(',')
        client.default_scopes=arrScope
        kwargs['client'] = client
        kwargs['user'] = user
        redirect_uri = request.args.get('redirect_uri')
        #return redirect(redirect_uri)
        if request.args.get('state'):
            state= request.args.get('state')
        else:
            state= None
        ids.logger.debug("response_type==="+request.args.get('response_type'))
        ids.logger.debug("NONCE==="+request.args.get('nonce'))
        ids.logger.debug("STATE===="+request.args.get('state'))
        ids.logger.debug("client_id==="+client_id)

        if request.args.get('response_type'):
            response_type= request.args.get('response_type')
        else:
            response_type= None

        ids.logger.debug("response_type==="+response_type)

        nonce=request.args.get('nonce')
        code_challenge = request.args.get('code_challenge')
        code_challenge_method = request.args.get('code_challenge_method')

        return render_template('authorize-custom.html',response_type=response_type,redirect_uri=redirect_uri,is_authentication=is_authentication,state=state,nonce=nonce ,code_challenge=code_challenge,code_challenge_method=code_challenge_method, **kwargs)

    confirm = request.form.get('confirm', 'no')
    return True

