from functools import wraps

from flask import redirect, session
from flask import url_for

# from werkzeug import cached_property

from flask import request, Response

from urllib.parse import urlsplit, urlunsplit

from id.id_service.magenid.idsapp.idsserver.lib.db.dao import ClientDao
from id.id_service.magenid.idsapp.idsserver.lib.db.dao import GrantDao
from id.id_service.magenid.idsapp.idsserver.lib.db.dao import CodeDao
from id.id_service.magenid.idsapp.idsserver.lib.db.dao import TokenDao

from id.id_service.magenid.idsapp.idsserver.lib.oidc.exception_handler import *
from id.id_service.magenid.idsapp.idsserver.lib.oidc.oauth_exception_handler import *
from id.id_service.magenid.idsapp.idsserver.lib.db.magen_client_dao import MagenClientDao
from id.id_service.magenid.idsapp.idsserver.lib.db.magen_user_dao import MagenUserDao

from id.id_service.magenid.idsapp.idsserver.utils.utilities import *

from id.id_service.magenid.idsapp.idsserver.lib.bll.client_api import ClientApi
from id.id_service.magenid.idsapp.idsserver.lib.bll.user_api import UserApi

import logging
import logging.config
from logging.handlers import RotatingFileHandler

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)


class Params(object):
    pass


class OpenIdConnectProvider(object):
    """This is OpenID connect Provide to secure services.
        This server provides an authorize handler and a token hander,

        Like many other Flask extensions, there are two usage modes. One is
        binding the Flask app instance::
            app = Flask(__name__)
            oid = OpenIdConnectProvider(app)
    """

    _userdao = MagenUserDao()
    _clientdao = ClientDao()
    _grantdao = GrantDao()
    _codedao = CodeDao()
    _tokendao = TokenDao()
    _magenClientDao = MagenClientDao()

    def __init__(self, app=None):
        self._before_request_funcs = []
        self._after_request_funcs = []
        self._invalid_response = None
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.params = Params()
        self.errors = {
            'client_id_error': 'The client identifier (client_id) is missing or invalid.',
            'redirect_uri_error': 'The request fails due to a missing, invalid, or mismatching redirection URI (redirect_uri).',
            'invalid_request': 'The request is otherwise malformed',

            'unauthorized_client': 'The client is not authorized to request an '
                                   'authorization code using this method',

            'access_denied': 'The resource owner or authorization server denied '
                             'the request',

            'unsupported_response_type': 'The authorization server does not '
                                         'support obtaining an authorization code '
                                         'using this method',

            'invalid_scope': 'The requested scope is invalid, unknown, or '
                             'malformed',

            'server_error': 'The authorization server encountered an error',

            'temporarily_unavailable': 'The authorization server is currently '
                                       'unable to handle the request due to a '
                                       'temporary overloading or maintenance of '
                                       'the server',

            'interaction_required': 'The Authorization Server requires End-User '
                                    'interaction of some form to proceed',

            'login_required': 'The Authorization Server requires End-User '
                              'authentication',

            'account_selection_required': 'The End-User is required to select a '
                                          'session at the Authorization Server',

            'consent_required': 'The Authorization Server requires End-User'
                                'consent',

            'invalid_request_uri': 'The request_uri in the Authorization Request '
                                   'returns an error or contains invalid data',

            'invalid_request_object': 'The request parameter contains an invalid '
                                      'Request Object',

            'request_not_supported': 'The provider does not support use of the '
                                     'request parameter',

            'request_uri_not_supported': 'The provider does not support use of the '
                                         'request_uri parameter',

            'registration_not_supported': 'The provider does not support use of '
                                          'the registration parameter',
        }
        self.app = app

    def error_uri(self):
        error_uri = self.app.config.get('PROVIDER_ERROR_URI')
        if error_uri:
            return error_uri
        error_endpoint = self.app.config.get('PROVIDER_ERROR_ENDPOINT')
        if error_endpoint:
            return url_for(error_endpoint)
        return '/oauth/errors'

    # setter and getters
    def usergetter(self, f):
        self._usergetter = f
        return f

    def issuergetter(self, f):
        self._issuergetter = f
        return f

    def expiretimegetter(self, f):
        self._expiretimegetter = f
        return f

    def tokensetter(self, f):
        self._tokensetter = f
        return f

    def logout_handler(self, f):
        @wraps(f)
        def wrap(*args, **kwargs):
            session['logged_in'] = None
            return redirect('/')

        return wrap

    def login_handler(self, f):
        @wraps(f)
        def wrap(*args, **kwargs):
            if 'logged_in' in session:
                return f(*args, **kwargs)
            else:
                next_url = get_org_url(request.url)
                login_url = '%s?next=%s' % (url_for('login'), next_url)
                return redirect(login_url)

        return wrap

    def authorize_handler(self, f):
        @wraps(f)
        def wrap(*args, **kwargs):
            # validate url
            # get parameters
            uri, http_method, body, headers = get_params()
            if request.method in ('GET', 'HEAD'):
                self.set_parameters(False)
                self.validate_parameters(False)
                rv = f(*args, **kwargs)
                return rv
            else:
                logger.debug("confirm============= %s", request.form.get('confirm', 'no'))
                self.set_parameters(False)
                self.validate_parameters(False)
                # get the client id from url
                client_id = self.params.client_id
                # set the expire time (configurable) TODO
                expire = self._expiretimegetter()
                # get the rediret url from url
                redirect_uri = self.params.redirect_uri
                # create authorization code
                code = create_code()
                # get the current login user
                user = self._usergetter()
                logger.debug("=========USER========= %s", user.username)
                # get the code_challenge from url
                code_c = self.params.code_challenge
                # get the code_challenge_method from url
                code_c_meth = self.params.code_challenge_method
                # get the scope from url
                scopes = self.params.scope
                # get the nonce from url
                nonce = self.params.nonce
                # check if the user is authenticated
                auth = self.is_authentication
                # save the grant and get the authorization code
                self._grantdao.saveGrant(user, client_id, code, nonce, auth, expire, redirect_uri, code_c, code_c_meth,
                                         scopes)
                # redirect with authorization code
                if self.params.state is None:
                    url = get_the_encoded_url(self.params.redirect_uri + '?code=' + code)
                else:
                    url = get_the_encoded_url(
                        self.params.redirect_uri + '?code=' + code + "&state=" + self.params.state)
                logger.debug('redirect======%s', url)
                return redirect(url)

        return wrap

    def token_handler(self, f):
        @wraps(f)
        def wrap(*args, **kwargs):
            logger.debug('############### =============TOKEN HNDLER========= ############')
            # validate url
            # get parameters
            # uri, http_method, body, headers = get_params()
            if request.method in ('POST'):
                # get parameters from url and set parameters.
                self.set_parameters(True)
                # validate all parameters as per open id connect specification describes in
                # http://openid.net/specs/openid-connect-core-1_0.html
                self.validate_parameters(True)

                logger.debug(' TOKEN self.code.user.username  %s', self.code.user)
                logger.debug(' TOKEN self.client.client_id  %s', self.client.client_id)
                logger.debug(' TOKEN self.code.nonce  %s', self.code.nonce)
                issuer = self._issuergetter()
                expiretimegetter = self._expiretimegetter()
                # create id token dictionary if user is authenticated
                if self.code.is_authentication:
                    id_token_dic = create_id_token(
                        user=self.code.user,
                        aud=str(self.client.client_id),
                        nonce=self.code.nonce,
                        expire=expiretimegetter,
                        issuer=issuer,
                        request=request,

                    )
                else:
                    id_token_dic = {}

                logger.debug('id_token_dic %s', id_token_dic)

                # get the current login user from code object
                user = self.code.user
                logger.debug("=======CODE==USER========= %s", user.username)
                # get the current client from code object
                client = self.code.client
                # get the id token dictionary
                id_token_dic = id_token_dic
                # get the scopes from code object
                scope = self.code.scopes
                # create access_token
                access_token = uuid.uuid4().hex
                # create refresh_token
                refresh_token = uuid.uuid4().hex
                # set expire time (configurable) 
                expires = self._expiretimegetter()

                grant = self._grantdao.getGrantByClientIdAndCode(client.client_id, self.code)
                logger.debug("=========== %s , %s",user.username, grant.redirect_uri)
                o_success, o_message, magen_client = ClientApi.get_by_user_and_device_id(str(user.username),str(grant.redirect_uri))
                logger.debug("o_success ===============  %s", o_success)
                if o_success:
                    if magen_client:
                        #notify policy service
                        logger.debug("magen client is found  %s", magen_client.mc_id)
                        #n_success, n_message, ret_obj = ClientApi.Notify(client.mc_id)
                else:
                    logger.debug("get a new magen client for the user")
                    #create mc_id using username and device id
                    mc_id = get_magen_client_id(str(grant.user.username), str(grant.redirect_uri))
                    logger.debug("grant.user.username ===============  %s", grant.user.username)
                    logger.debug("grant.redirect_uri ===============  %s", grant.redirect_uri)
                    logger.debug("mc_id ===============  %s", mc_id)
                    logger.debug("request.remote_addr ===============  %s", request.remote_addr)
                    logger.debug("mac_for_ip ===============  %s", mac_for_ip(request.remote_addr))

                    cilent_dic = get_magen_client_dic(grant.user.username, grant.redirect_uri, mc_id,
                                                  request.remote_addr, mac_for_ip(request.remote_addr), 1)

                    in_success, in_message, magen_client = ClientApi.insert_client(cilent_dic)

                    logger.debug("in_success ===============  %s", in_success)

                    if not in_success:
                        rv = f(None, request, *args, **kwargs)

                if magen_client:

                       # notify policy service
                       logger.debug("Send request to Policy Service to [ add ] policy session for this client %s",
                                    magen_client.mc_id)
                       n_success, n_message, ret_obj = ClientApi.Notify("create",magen_client.mc_id)
                       logger.debug("n_success ===============  %s", n_success)
                       if n_success:
                           logger.debug('magen_client_id %s', magen_client.mc_id)
                           logger.debug('access_token %s', access_token)
                           logger.debug('expires ? %s', expires)
                           logger.debug('client.client_id ? %s', client.client_id)
                           try:
                               encoded_token = self.encode_id_token(id_token_dic, client)
                               if encoded_token:
                                 logger.debug('encoded_token %s', encoded_token)

                                 # Store the token.
                                 token = self._tokendao.saveToken(user, client, access_token, refresh_token, id_token_dic,
                                                                encoded_token, scope, expires, magen_client.mc_id)

                                 # delete code from the database becasue we do not need this cod anymore
                                 self._codedao.deleteCode(self.code)
                                 rv = f(token, request, *args, **kwargs)
                               else:
                                   rv = f(None, request, *args, **kwargs)
                           except:
                               rv = f(None, request, *args, **kwargs)
                       else:
                           rv = f(None, request, *args, **kwargs)
                else:
                    rv = f(None, request, *args, **kwargs)


                return rv

        return wrap



    def encode_id_token(self,payload, client):
        try:
          logger.debug('======= DDDDDD UUUUUUU ========')
          logger.debug('=======  client.client_secret ========  %s', client.client_secret)
          secret = client.client_secret
          alg = client.jwt_alg
          logger.debug('=======  alg ======== %s', alg)
          encoded_token = jwt.encode(payload, secret, algorithm=alg)
          #decoded_payload = jwt.decode(encoded_token, secret, algorithm=alg, options={'verify_aud': False})
          return encoded_token
        except Exception as e:
            logging.exception(e)
            return None





    def token_validation_handler(self, f):
        @wraps(f)
        def wrap(*args, **kwargs):
            logger.debug('############### ==========TOKEN VALIDATION HANDLER========= ############')
            # validate url
            # get parameters
            # uri, http_method, body, headers = get_params()
            access_token=None
            if request.method in ('POST'):
                user = self._usergetter()
                token = self._tokendao.getTokenByAccessToken(access_token)
                if token.expies > get_now_time():
                    return get_json_response('{"access_token":"' + token.access_token
                                             + '","error":"' + 'Session Expired' + '"}')
                # get user information

                user = token.user
                rv = f(user, request, *args, **kwargs)
                return rv

        return wrap

    '''
    The following code will handle the external idp authentication and authorization.

    '''

    def external_idp_handler(self, f):
        @wraps(f)
        def wrap(*args, **kwargs):
            # TODO
            uri, http_method, body, headers = get_params()
            if request.method in ('GET', 'HEAD'):
                v = f(*args, **kwargs)
                # self.set_parameters(False)
                # self.validate_parameters(False)
                code = request.values.get('code')
                if code is None:
                    # get the client_id, client_secret from the database for external idp
                    # create idp redirect url with client_id based on selected idp
                    return redirect('idp_redirect_uri')
                else:
                    # get the client_id, client_secret from the database for external idp
                    # get the code and post request to the idp with code,client_id, client_secret,grant_type and redirect url
                    # get the tokens from external idp
                    # verify access_token, id_token
                    # get user info
                    # add user dynamically in the database (configurable)
                    # save external token info and create client with external client_id and client_secret in the database
                    # creat local idp authorization code
                    # save code and grant in the local database
                    # redirect with authorization code and state
                    return redirect(self.params.redirect_uri + '?code=' + code + "&state=" + self.params.state)

        return wrap

    def set_parameters(self, token):
        # get all parameters from the url and set all parameters

        if token:
            logger.debug('###################### TOKEN AUTHZ ########################')
            self.params.grant_type = request.values.get('grant_type')
            self.params.client_secret = request.values.get('client_secret')
            self.params.code = request.values.get('code')
        else:
            logger.debug('###################### AUTHZ AUTHN ########################')
            self.params.response_type = request.values.get('response_type')
            logger.debug('self.params.response_type: %s', self.params.response_type)
            if self.params.response_type in ['code']:
                self.params.grant_type = 'authorization_code'
                logger.debug('self.params.grant_type: %s', self.params.grant_type)
            elif self.params.response_type in ['id_token', 'id_token token', 'token']:
                self.params.grant_type = 'implicit'
            else:
                self.params.grant_type = None

        self.params.client_id = request.values.get('client_id')
        self.params.redirect_uri = request.values.get('redirect_uri')

        if request.values.get('scope'):
            self.params.scope = request.values.get('scope').split()
        self.params.state = request.values.get('state')

        self.params.nonce = request.values.get('nonce')
        self.params.prompt = request.values.get('prompt')
        self.params.code_challenge = request.values.get('code_challenge')
        self.params.code_challenge_method = request.values.get('code_challenge_method')
        self.is_authentication = request.values.get('is_authentication')

    def validate_parameters(self, token):
        if token:
            logger.debug('###################### VALIDATE TO GET TOKEN ########################')
        # validate client
        if (request.values.get('client_id') != ''):
            client_id = request.values.get('client_id')
            logger.debug('client id from url: %s', client_id)
            try:
                client = self._clientdao.getClientByClientId(client_id)
                logger.debug('client id from database: %s', client.client_id)
            except:
                logger.error("problem in getting client data")
                raise MagenIdServiceException(self.errors['client_id_error'], status_code=410)

            logger.debug('redirect_uriXXXXXXXXXX: %s', client)
            logger.debug('response_type: %s', client.response_type)
            if client is None:
                logger.debug('No client ID')
                raise MagenIdServiceException(self.errors['client_id_error'], status_code=410)
            else:
                self.client = client
                logger.debug('found client')

        # validate redirect url
        logger.debug("=========REDIRECT_URI============: %s", self.params.redirect_uri)
        clean_redirect_uri = urlunsplit((urlsplit(self.params.redirect_uri))._replace(query=''))
        logger.debug("=========REDIRECT_URIS============: %s", self.client.redirect_uris)
        logger.debug("=========CLEAN_REDIRECT_URI============: %s", clean_redirect_uri)
        logger.debug('_redirect_uris = %s', self.client.redirect_uris)
        if not (clean_redirect_uri in self.client.redirect_uris):
            logger.debug('[Authorize] Invalid redirect uri: %s', clean_redirect_uri)
            raise MagenIdServiceException(self.errors['redirect_uri_error'], status_code=410)

        # Grant type validation.
        if not self.params.grant_type:
            logger.error('unsupported_response_type: %s', self.params.grant_type)
            raise MagenIdServiceException(self.errors['unsupported_response_type'], status_code=410)

        # Nonce parameter validation.
        if self.is_authentication and self.params.grant_type == 'implicit' and not self.params.nonce:
            logger.error('invalid_request: %s', self.params.grant_type)
            raise MagenIdServiceException(self.errors['invalid_request'], status_code=410)

        if self.params.code_challenge:
            if not (self.params.code_challenge_method in ['plain', 'S256']):
                logger.error('invalid_request: %s', self.params.grant_type)
                raise MagenIdServiceException(self.errors['invalid_request'], status_code=410)

        if token:
            # validate secret token
            if not (self.client.client_secret == self.params.client_secret):
                logger.error('invalid_client')
                raise MagenIdServiceException(self.errors['invalid_request'], status_code=410)

            if self.params.grant_type == 'authorization_code':
                # validate code
                if (request.values.get('code') != ''):
                    # code = self._codegetter(self.params.code)
                    code = self._codedao.getCodeByCode(self.params.code)

                    if code is None:
                        logger.debug('No client ID')
                    else:
                        self.code = code
                        logger.debug('get code.code========: %s', code.code)
                        logger.debug('get code.nonce=======: %s', code.nonce)

                    if not (self.code.client == self.client) or self.code.has_expired():
                        logger.error('invalid_grant')
                        raise MagenIdServiceException('invalid_grant', status_code=410)
            elif self.params.grant_type == 'refresh_token':
                if not self.params.refresh_token:
                    logger.error('invalid_client')
                    raise MagenIdServiceException('invalid_client', status_code=410)
                try:
                    token = self._tokendao.getTokenByClientAndRefreshToken(self.params.refresh_token, self.client)
                    if token is None:
                        logger.debug('No refresh_token is found in the db table')
                        raise MagenIdServiceException('No refresh_token is found in the db table', status_code=410)
                    else:
                        self.token = token

                except:
                    logger.debug('[Token] Refresh token does not exist: %s', self.params.refresh_token)
                    logger.error('invalid_grant')
                    raise MagenIdServiceException('[Token] Refresh token does not exist', status_code=410)

            else:
                logger.debug('[Token] Invalid grant type: %s', self.params.grant_type)
                logger.error('unsupported_grant_type')
                raise MagenIdServiceException(self.errors['unsupported_grant_type'], status_code=410)
        else:
            # Response type parameter validation.
            if self.is_authentication:
                if not (self.params.response_type in self.client.response_type):
                    logger.error('invalid_request: %s', self.params.grant_type)
                    raise MagenIdServiceException(self.errors['invalid_request'], status_code=410)
