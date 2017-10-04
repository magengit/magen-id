import uuid
from datetime import timedelta
from flask_login import LoginManager
from flask import Flask


import logging

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"


ids = Flask(__name__)

ids.debug = True
ids.secret_key = str(uuid.uuid4())


logger = logging.getLogger(__name__)

ids.config.from_pyfile('settings.py', silent=True)
ids.config['PERMANENT_SESSION_LIFETIME']=timedelta(minutes = 30)


print("======INIT======")

login_manager = LoginManager()
login_manager.init_app(ids)

login_manager.login_view = 'login'


import id.id_service.magenid.idsapp.idsserver.views.home
import id.id_service.magenid.idsapp.idsserver.views.oauth.client
import id.id_service.magenid.idsapp.idsserver.views.oauth.authorization
import id.id_service.magenid.idsapp.idsserver.views.auth_redirect
import id.id_service.magenid.idsapp.idsserver.views.oauth.external_idp
import id.id_service.magenid.idsapp.idsserver.rest.authorize_rest_api
import id.id_service.magenid.idsapp.idsserver.rest.magen_client_rest_api
import id.id_service.magenid.idsapp.idsserver.rest.magen_user_rest_api
import id.id_service.magenid.idsapp.idsserver.rest.magen_group_rest_api



