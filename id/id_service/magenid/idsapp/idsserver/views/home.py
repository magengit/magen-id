from flask import Flask, jsonify,render_template, session
from datetime import timedelta
import random
from urllib.parse import urlparse

from functools import wraps

from flask_login import LoginManager
from flask import Flask,session, request, flash, url_for, redirect, render_template, abort ,make_response,g
from flask_login import login_user , logout_user , current_user

from id.id_service.magenid.idsapp import ids

from id.id_service.magenid.idsapp.idsserver.lib.oidc.oidc_provider import OpenIdConnectProvider
from id.id_service.magenid.idsapp.idsserver.lib.db.models.models import *
from id.id_service.magenid.idsapp.idsserver.lib.db.dao import *
from id.id_service.magenid.idsapp.idsserver.lib.db.magen_user_dao import *
from id.id_service.magenid.idsapp.idsserver.lib.oidc.oauth_exception_handler import *

from flask_restful import Resource, Api
from flask_restful import reqparse
import urllib.parse

from id.id_service.magenid.idsapp.idsserver.lib.autenticator import *
from magen_rest_apis.server_urls import ServerUrls

api = Api(ids)

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"

domaindao=DomainDao()
userdao=MagenUserDao()
clientdao=ClientDao()
tokendao= TokenDao()
serviceDao=ServiceDao()
extIdpDao=ExtIdpDao()

login_manager = LoginManager()
login_manager.init_app(ids)
openid_connect_provider = OpenIdConnectProvider(ids)

login_manager.login_view = 'login'


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = current_user()
        if user is None:
            idpLoginUrl=getIdpLoginUrl()
            ids.logger.debug('=======idpLoginUrl======= %s', idpLoginUrl)
            if idpLoginUrl=="":
              return render_template('error.html',msg='You are not authorized')
            
            return redirect(idpLoginUrl)
        return f(*args, **kwargs)
    return decorated_function


def getIdpLoginUrl():
    enurl=urllib.parse.quote(request.url, safe='')
    ids.logger.debug("encoded redirect url" + enurl)
    if 'authorize' in request.url:
        #get the user name from the url parameter
      
        username = request.args.get('username')
        ids.logger.debug('=======username=======  %s', username)
        if username is None:
          return '/login?next=' + enurl

        if "@" not in username:
          return '/login?next=' + enurl

        #check database to see the user in the parameter is in the user table
        user=userdao.getUserByUserName(username)

        if user is None:
          ids.logger.debug('=======User not found in the database======= ')
          #get the domain name from the username
          domain_name = username.split("@")[1]
          ids.logger.debug('=======user domain=======  %s', domain_name)
          domain_db=domaindao.getDomainByDomainName(domain_name)
          if domain_db is None:
            return ""
          ids.logger.debug('=======domain_db=======  %s', domain_db)
          idp=domain_db.idp
          dic = get_user_dic(username, username, str(uuid.uuid4()), None, None, None, None,
                             [], [], idp, None, "standard", None, True)
          ids.logger.debug("=======Save user user in the db if the user is not in the db for mapping  %s",dic)
          userdao.saveForMappingUser(dic)
          return '/oauth/ext/authorize?idp=' + idp +"&"+request.query_string.decode("utf-8")
        else:
           idp=user.idp
           ids.logger.debug('============== ' + idp)
           if idp=='magen':
              return '/login?next=' + enurl

           else:
              #redirect to external IDP
              ids.logger.debug('Redirect to ' + idp)
              return '/oauth/ext/authorize?idp=' + idp +"&"+request.query_string.decode("utf-8")

    ids.logger.debug('=======AAAA======= ' + enurl)
    return '/login?next=' + enurl

def current_user():
    user = user_valid()
    return user

@ids.route('/check/')
def health():
    return render_template('health.html',isAuthorize=False)

def displayErrorMessage(msg):
    return render_template('error.html',msg=msg)


@ids.errorhandler(MagenIdServiceException)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


@ids.route('/')
def home():
    return render_template('home.html')

def get_redirect_target():
    return request.values.get('next', None)




@ids.route('/login', methods=('GET', 'POST'))
def login_form():
    error=None
    if request.method == 'GET':
       next = request.args.get('next')
       if next is not None:
           ids.logger.debug(str(next))
           if 'authorize' in next:
              resp = make_response(render_template('login.html', error=error,next=next,isAuthorize=True))

       resp = make_response(render_template('login.html', error=error, next=next,isAuthorize=False))

       # Reset session information to log user out, since the login page functions
       # also as logout page.
       g.user = None
       resp.set_cookie('XSRF-TOKEN', '', expires=0);
       return resp
    else:
       next = request.form['next']
       username = request.form['username']
       password = request.form['password']   #TODO
       #ad=True

       ids.logger.debug('=======username======= %s', username)
       ids.logger.debug('=======password======= %s', password)
       user = UserAuthentication.login(username, password)

       if user is not None:
           try:
              g.user = user
              session['username'] = user.username
              #user.last_login=get_now_time()
              userdao.updateUserLoginTime(user.username)
              if next=='None' or next=='':
                 return redirect('/admin')
              else:
                 return redirect(next)
           except:
              printErrorLog()
              return redirect('/login')
       else:
          return redirect(url_for('login'))

@ids.before_request
def before_request():
    user=current_user()

@ids.after_request
def after_request(resp):
    if "__invalidate__" in session:
        resp.delete_cookie('XSRF-TOKEN')
    if 'username' in session:
        username = session['username']
        # refresh token
        token = UserAuthentication.generate_auth_token(600,username)
        resp.set_cookie('XSRF-TOKEN', token.decode('ascii'));
    return resp

@ids.after_request
def add_header(response):
    # prevent browser caching
    response.headers['Cache-Control'] = 'public, max-age=0'
    return response

def user_valid():
    token = request.cookies.get('XSRF-TOKEN')
    
    if token is None:
        return None

    user = UserAuthentication.verify_auth_token(token)
    g.user = user
    return user



@openid_connect_provider.issuergetter
def get_issuer():
    server_urls_instance = ServerUrls.get_instance()
    issuer = server_urls_instance.identity_server_base_url

    return issuer

@openid_connect_provider.expiretimegetter
def get_expire():
    expire=ids.config['EXPIRE_TIME']
    return expire


@openid_connect_provider.usergetter
def get_user():
    return current_user()




