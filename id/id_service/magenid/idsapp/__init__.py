from flask import Flask, url_for, session, request, jsonify,render_template
from flask import redirect, abort
from pymongo import MongoClient
import uuid

import datetime
from datetime import datetime, timedelta

import flask
from flask_login import LoginManager
from flask import Flask,session, request, flash, url_for, redirect, render_template, abort ,g
from flask_login import login_user , logout_user , current_user , login_required

from bson import json_util


import logging

from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash, gen_salt

from urllib.parse import urlencode
import requests


import argparse
# threading imports
import socket
import time
import threading
import itertools
import sys
import os
import ssl

from requests.auth import HTTPBasicAuth

from logging.handlers import RotatingFileHandler
import aniso8601
from bson.json_util import loads, dumps
from uuid import *



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



