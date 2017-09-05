import sys, os
import logging,traceback
from logging.handlers import RotatingFileHandler

from urllib.parse import urlencode
import json
from json import dumps

import requests

from flask import Flask, make_response
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash

from flask import request, redirect, render_template, url_for, flash


from datetime import datetime, timedelta
from flask import session, request,url_for
from flask import render_template, redirect, jsonify
from werkzeug.security import gen_salt


from magen_id_client.magen_client import MagenClient
from magen_id_client.utilities import Utilities

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"


app = Flask(__name__)
app.debug = True
app.secret_key = 'secret'

app.config['PERMANENT_SESSION_LIFETIME']=timedelta(minutes = 30)

logger = logging.getLogger(__name__)

app.config.from_pyfile('settings.py', silent=True)



magen_client = MagenClient(app)
issuer=app.config["MAGEN_ID_HOST_URL"]
client_id = app.config["MAGEN_CLIENT_ID"]
client_secret = app.config["MAGEN_CLIENT_SECRET"]
alg=app.config["ALG"]
scopes='openid,profile,address'


connected_app = magen_client.register_client_app(
    'box_magen_agent',
    issuer=issuer,
    client_id=client_id,
    client_secret=client_secret,
    callback_uri=app.config["CALLBACL_URL"], 
)


@app.route('/', methods=["GET"])
def home():
    return render_template('home.html')



@app.route('/login', methods=["GET"])
def login():
    connected_app.setRedirectUri(app.config["CALLBACL_URL"])
    #return connected_app.authorize(username=app.config["USER_NAME"],access_token="")
    return connected_app.authorize(username=app.config["USER_NAME"],access_token="")


@app.route('/oauth/callback/', methods=["GET"])
@connected_app.authorized_handler
def authorized(resp):
    if resp is None:
        return 'Access denied: error=%s' % (
            request.args['error']
        )

    if 'magen_id_token' in resp:
        magen_id_token=resp['magen_id_token'].strip()
        session['magen_id_token'] = magen_id_token
        print("magen_id_token",magen_id_token)
        user_client_info_json=connected_app.validate_mid_token_against_id_service(magen_id_token)
        print(user_client_info_json)
        info={}

        info["client_info"]=user_client_info_json
        info["token_info"]=resp

        #return jsonify(info)
        return render_template('admin.html',token_info=resp,client_info=user_client_info_json)
    else:
        print(str(resp)) 
        return render_template('error.html')






if __name__ == '__main__':
   os.environ['DEBUG'] = 'true'
   os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'

   logger.setLevel(logging.DEBUG)

   # create console handler and set level to debug
   ch = logging.StreamHandler()
   ch.setLevel(logging.DEBUG)

   # create formatter
   formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

   # add formatter to ch
   ch.setFormatter(formatter)

   # add ch to logger
   logger.addHandler(ch)

   #The OpenId Connect server needs to run under SSLContext
   '''
   import ssl
   context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
   context.load_cert_chain('certs/server.crt', 'certs/server.key')
   app.run(host='0.0.0.0', debug=True, port=5228, ssl_context=context)
   '''
   app.run(host='0.0.0.0', debug=True, port=5228)
