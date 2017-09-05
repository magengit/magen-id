#! /usr/bin/python3

import argparse
import signal
import socket
import sys
import os
import ssl
import logging
import logging.config
from mongoengine import connect

from logging.handlers import RotatingFileHandler

from magen_rest_apis.magen_app import MagenApp
# If this is being run from workspace (as main module),
# import dev/magen_env.py to add workspace package directories.
src_ver = MagenApp.app_source_version(__name__)
if src_ver:
    # noinspection PyUnresolvedReferences
    import dev.magen_env
print(sys.path)
from magen_utils_apis.domain_resolver import mongo_host_port
from magen_mongo_apis.mongo_core_database import LOCAL_MONGO_LOCATOR, MongoCore
from magen_mongo_apis.mongo_utils import MongoUtils
from magen_logger.logger_config import LogDefaults, initialize_logger
from magen_rest_apis.server_urls import ServerUrls

from id.id_service.magenid.idsapp import ids
from id.id_service.magenid.idsapp.idsserver.lib.db.models.models import *
from id.id_service.magenid.idsapp.idsserver.lib.db.dao import *

from id.id_service.magenid.idsapp.idsserver.lib.db.magen_user_dao import *
from id.id_service.magenid.idsapp.idsserver.lib.db.magen_client_dao import *
from id.id_service.magenid.idsapp.idsserver.lib.db.magen_group_dao import *
from id.id_service.magenid.idsapp.idsserver.utils.utilities import *

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"


def signal_handler(signal, frame):
    print("********* ID Server got signal, STARTING ***********")
    sys.exit(0)

data_dir_dflt = os.path.join(os.path.realpath(os.path.dirname(__file__)), "data")

#: setup parser -----------------------------------------------------------
parser = argparse.ArgumentParser(description='Magen Id Server',
                                     usage=("\n   python3 id_server.py "
                                            "--data-dir <dir> "
                                            "--mongo-ip-port <port> "
                                            "--log-dir <dir> "
                                            "--console-log-level {error|info|debug} "
                                            "--clean-init "
                                            "--test\n"))

parser.add_argument('--data-dir',
                    help='Set directory for log files. '
                    'Default is %s' % data_dir_dflt)

parser.add_argument('--mongo-ip-port', default=LOCAL_MONGO_LOCATOR,
                    help='Set Mongo IP and port in form <IP>:<PORT>. '
                         'Default is %s' % LOCAL_MONGO_LOCATOR)

parser.add_argument('--clean-init', action='store_false',
                    help='Clean All data when initializing'
                         'Default is to clean)')

parser.add_argument('--log-dir', default=LogDefaults.default_dir,
                    help='Set directory for log files.'
                         'Default is %s' % LogDefaults.default_dir)
parser.add_argument('--console-log-level', choices=['debug', 'info', 'error'],
                    default='error',
                    help='Set log level for console output.'
                         'Default is %s' % 'error')
parser.add_argument('--test', action='store_true',
                        help='Run server in test mode. Used for unit tests'
                             'Default is to run in production mode)')

#: parse CMD arguments ----------------------------------------------------
args = parser.parse_args()

# we will catch both kill -15 and Interrupt. This is important for testing.
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

server_urls = ServerUrls.get_instance()
SERVER_PORT = server_urls.identity_port

if args.test:
    ids.config['MODE'] = "test"
    mongo_server_ip, mongo_port = mongo_host_port()
    connect(db="magenid", port=mongo_port,host=mongo_server_ip)
    ids.run(host='0.0.0.0', port=SERVER_PORT, debug=True, use_reloader=False)
else:
    logger = initialize_logger(console_level=args.console_log_level, output_dir=args.log_dir)
    logger.setLevel(args.console_log_level.upper())
    logger.info("ID SERVICE LOGGING LEVEL: %s(%s)", args.console_log_level, logger.getEffectiveLevel())

    mongo_server_ip, mongo_port = mongo_host_port()
    connect(db="magenid", port=mongo_port,host=mongo_server_ip)

    userdao = MagenUserDao()
    magenClientDao = MagenClientDao()
    magenGroupDao = MagenGroupDao()
    clientdao = ClientDao()
    tokendao = TokenDao()
    serviceDao = ServiceDao()
    extIdpDao = ExtIdpDao()
    domaindao = DomainDao()

    
    ret = userdao.delete_all()
    logger.debug(ret)

    data_dir = args.data_dir if args.data_dir else data_dir_dflt
    logger.debug(data_dir)
    json_url = os.path.join(data_dir, "bootstrap.json")
    data = json.load(open(json_url))


    #insert groups into mongo database
    for g in data["groups"]:
        g_dic = get_magen_group_dic(g["ug_name"], g["ug_id"])
        group = magenGroupDao.insert(g_dic)

    #insert users into mongo database
    for user in data["users"]:
        logger.debug(user["username"])
        dic = get_user_dic(user["username"], user["email"], str(uuid.uuid4()), user["firstName"], user["lastName"],
                       user["password"], user["userGroup"],
                       [], user["u_groups"], user["idp"], user["type"], user["type"], user["firstName"] +" "+ user["lastName"], True,user["imgSrc"])
   
        userdao.saveForMappingUser(dic)
    for conapp in data["connected_apps"]:
        #insert sample_oauth_client into mongo database
        name = conapp["name"]
        redirect_uris = conapp["redirect_uris"]
        jwt_alg = conapp["jwt_alg"]
        client_id = conapp["client_id"]
        client_secret = conapp["client_secret"]
        username=conapp["username"]

        client_dic = get_oauth_client_dic(name, redirect_uris, [], jwt_alg, client_id, client_secret)
        user = userdao.get_by_user_name(username)
        clientdao.saveClient(user, client_dic)


    #insert sample_magen_client into mongo database
    sample_magen_client=data["sample_magen_client"]

    c_dic = get_magen_client_dic(sample_magen_client["username"],sample_magen_client["device"])
    client = magenClientDao.insert(c_dic)

    #insert external idp information into mongo database
    for exidp in data["ext_idp"]:
      extIdpDao.saveIdpNoRquest(name=exidp["name"],
                              desc=exidp["desc"],
                              client_id=exidp["client_id"],
                              client_secret=exidp["client_secret"],
                              authz_url=exidp["authz_url"],
                              token_url=exidp["token_url"],
                              user_info_url=exidp["user_info_url"],
                              redirect_uri=exidp["redirect_uri"],
                              scopes=exidp["scopes"],
                              code_challenge=exidp["code_challenge"],
                              code_challenge_method=exidp["code_challenge_method"],
                              token_info_url=exidp["token_info_url"])

    
    #insert domain information into mongo database
    for d in data["domain"]:
       if d["allow"]=="yes":
          domaindao.saveDomain(name=d["name"], idp=d["idp"], allow=True)
       domaindao.saveDomain(name=d["name"], idp=d["idp"], allow=False)   


    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_cert_chain('/etc/ssl/certs/server.crt', '/etc/ssl/certs/server.key')
    ids.run(host='0.0.0.0', debug=True, port=SERVER_PORT, threaded=True, ssl_context=context)
