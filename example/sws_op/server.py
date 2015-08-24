#!/usr/bin/env python
# pylint: disable = missing-docstring
# -*- coding: utf-8 -*-
from __future__ import print_function
import json
import logging
import sys
import os
import traceback
import re

from mako.lookup import TemplateLookup

from six.moves.urllib.parse import parse_qs
import time
from oic.utils import shelve_wrapper
from oic.utils.authn.javascript_login import JavascriptFormMako
from oic.utils.authn.client import verify_client
from oic.utils.authn.multi_auth import setup_multi_auth
from oic.utils.authn.multi_auth import AuthnIndexedEndpointWrapper
from oic.utils.authn.saml import SAMLAuthnMethod
from oic.utils.authn.user import UsernamePasswordMako
from oic.utils.authz import AuthzHandling
from oic.utils.http_util import BadRequest
from oic.utils.http_util import Unauthorized
from oic.utils.http_util import Response
from oic.utils.http_util import NotFound
from oic.utils.http_util import wsgi_wrapper
from oic.utils.http_util import ServiceError
from oic.utils.http_util import get_post
from oic.utils.keyio import keyjar_init
from oic.utils.userinfo import UserInfo
from oic.utils.userinfo.aa_info import AaUserInfo
from oic.utils.webfinger import WebFinger
from oic.utils.webfinger import OIC_ISSUER
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.authn_context import make_auth_verify
from oic.oic.provider import EndSessionEndpoint
from oic.oic.provider import AuthorizationEndpoint
from oic.oic.provider import TokenEndpoint
from oic.oic.provider import UserinfoEndpoint
from oic.oic.provider import RegistrationEndpoint
from software_statement.provider import SWSProvider

__author__ = 'rohe0002'

LOGGER = logging.getLogger("")
LOGFILE_NAME = 'oc.log'
HDLR = logging.FileHandler(LOGFILE_NAME)
BASE_FORMATTER = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

CPC = ('%(asctime)s %(name)s:%(levelname)s '
       '[%(client)s,%(path)s,%(cid)s] %(message)s')
CPC_FORMATTER = logging.Formatter(CPC)

HDLR.setFormatter(BASE_FORMATTER)
LOGGER.addHandler(HDLR)
LOGGER.setLevel(logging.DEBUG)

URLMAP = {}
NAME = "pyoic"
OAS = None

PASSWD = {
    "diana": "krall",
    "babs": "howes",
    "upper": "crust"
}


# ----------------------------------------------------------------------------

# # ----------------------------------------------------------------------------


# noinspection PyUnusedLocal
def safe(environ, start_response, logger):
    _oas = environ["oic.oas"]
    _srv = _oas.server
    _log_info = _oas.logger.info

    _log_info("- safe -")
    # _log_info("env: %s" % environ)
    # _log_info("handle: %s" % (handle,))

    try:
        authz = environ["HTTP_AUTHORIZATION"]
        (typ, code) = authz.split(" ")
        assert typ == "Bearer"
    except KeyError:
        resp = BadRequest("Missing authorization information")
        return resp(environ, start_response)

    try:
        _sinfo = _srv.sdb[code]
    except KeyError:
        resp = Unauthorized("Not authorized")
        return resp(environ, start_response)

    info = "'%s' secrets" % _sinfo["sub"]
    resp = Response(info)
    return resp(environ, start_response)


# noinspection PyUnusedLocal
def css(environ, start_response, logger):
    try:
        info = open(environ["PATH_INFO"]).read()
        resp = Response(info)
    except (OSError, IOError):
        resp = NotFound(environ["PATH_INFO"])

    return resp(environ, start_response)


# ----------------------------------------------------------------------------


# noinspection PyUnusedLocal
def token(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.token_endpoint,
                        logger=logger)


# noinspection PyUnusedLocal
def authorization(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.authorization_endpoint,
                        logger=logger)


# noinspection PyUnusedLocal
def userinfo(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.userinfo_endpoint,
                        logger=logger)


# noinspection PyUnusedLocal
def op_info(environ, start_response, logger):
    _oas = environ["oic.oas"]
    LOGGER.info("op_info")
    return wsgi_wrapper(environ, start_response, _oas.providerinfo_endpoint,
                        logger=logger)


# noinspection PyUnusedLocal
def registration(environ, start_response, logger):
    _oas = environ["oic.oas"]

    if environ["REQUEST_METHOD"] == "POST":
        return wsgi_wrapper(environ, start_response, _oas.registration_endpoint,
                            logger=logger)
    elif environ["REQUEST_METHOD"] == "GET":
        return wsgi_wrapper(environ, start_response, _oas.read_registration,
                            logger=logger)
    else:
        resp = ServiceError("Method not supported")
        return resp(environ, start_response)


# noinspection PyUnusedLocal
def check_id(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.check_id_endpoint,
                        logger=logger)


# noinspection PyUnusedLocal
def swd_info(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.discovery_endpoint,
                        logger=logger)


# noinspection PyUnusedLocal
def trace_log(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.tracelog_endpoint,
                        logger=logger)


# noinspection PyUnusedLocal
def endsession(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.endsession_endpoint,
                        logger=logger)


# noinspection PyUnusedLocal
def meta_info(environ, start_response, logger):
    """
    Returns something like this::

         {"links":[
             {
                "rel":"http://openid.net/specs/connect/1.0/issuer",
                "href":"https://openidconnect.info/"
             }
         ]}

    """
    pass


def webfinger(environ, start_response, _):
    query = parse_qs(environ["QUERY_STRING"])
    try:
        assert query["rel"] == [OIC_ISSUER]
        resource = query["resource"][0]
    except KeyError:
        resp = BadRequest("Missing parameter in request")
    else:
        web_finger = WebFinger()
        resp = Response(web_finger.response(subject=resource, base=OAS.baseurl))
    return resp(environ, start_response)


def static_file(path):
    try:
        os.stat(path)
        return True
    except OSError:
        return False


# noinspection PyUnresolvedReferences
def static(environ, start_response, path):
    LOGGER.info("[static]sending: %s", path)

    try:
        text = open(path).read()
        if path.endswith(".ico"):
            start_response('200 OK', [('Content-Type', "image/x-icon")])
        elif path.endswith(".html"):
            start_response('200 OK', [('Content-Type', 'text/html')])
        elif path.endswith(".json"):
            start_response('200 OK', [('Content-Type', 'application/json')])
        elif path.endswith(".txt"):
            start_response('200 OK', [('Content-Type', 'text/plain')])
        elif path.endswith(".css"):
            start_response('200 OK', [('Content-Type', 'text/css')])
        else:
            start_response('200 OK', [('Content-Type', "text/xml")])
        return [text]
    except IOError:
        resp = NotFound()
        return resp(environ, start_response)


def check_session_iframe(environ, start_response, logger):
    return static(environ, start_response, "htdocs/op_session_iframe.html")


# ----------------------------------------------------------------------------


def key_rollover(environ, start_response, _):
    # expects a post containing the necessary information
    _jwks = json.loads(get_post(environ))
    OAS.do_key_rollover(_jwks, "key_%d_%%d" % int(time.time()))
    resp = Response("OK")
    return resp(environ, start_response)


def clear_keys(environ, start_response, _):
    OAS.remove_inactive_keys()
    resp = Response("OK")
    return resp(environ, start_response)


# ----------------------------------------------------------------------------

ENDPOINTS = [
    AuthorizationEndpoint(authorization),
    TokenEndpoint(token),
    UserinfoEndpoint(userinfo),
    RegistrationEndpoint(registration),
    EndSessionEndpoint(endsession),
]

URLS = [
    (r'^.well-known/openid-configuration', op_info),
    (r'^.well-known/simple-web-discovery', swd_info),
    (r'^.well-known/host-meta.json', meta_info),
    (r'^.well-known/webfinger', webfinger),
    #    (r'^.well-known/webfinger', webfinger),
    (r'.+\.css$', css),
    (r'safe', safe),
    (r'^keyrollover', key_rollover),
    (r'^clearkeys', clear_keys),
    (r'^check_session', check_session_iframe)
    #    (r'tracelog', trace_log),
]


def add_endpoints(extra):
    global URLS

    for endp in extra:
        URLS.append(("^%s" % endp.etype, endp))


# ----------------------------------------------------------------------------

ROOT = './'

LOOKUP = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')


# ----------------------------------------------------------------------------


def application(environ, start_response):
    """
    The main WSGI application. Dispatch the current request to
    the functions from above and store the regular expression
    captures in the WSGI environment as  `oic.url_args` so that
    the functions from above can access the url placeholders.

    If nothing matches call the `not_found` function.

    :param environ: The HTTP application environment
    :param start_response: The application to run when the handling of the
        request is done
    :return: The response as a list of lines
    """
    global OAS

    # user = environ.get("REMOTE_USER", "")
    path = environ.get('PATH_INFO', '').lstrip('/')

    logger = logging.getLogger('oicServer')

    if path == "robots.txt":
        return static(environ, start_response, "static/robots.txt")

    environ["oic.oas"] = OAS

    if path.startswith("static/"):
        return static(environ, start_response, path)

    for regex, callback in URLS:
        match = re.search(regex, path)
        if match is not None:
            try:
                environ['oic.url_args'] = match.groups()[0]
            except IndexError:
                environ['oic.url_args'] = path

            logger.info("callback: %s", callback)
            try:
                return callback(environ, start_response, logger)
            except Exception as err:
                print("%s" % err, file=sys.stderr)
                message = traceback.format_exception(*sys.exc_info())
                print(message, file=sys.stderr)
                logger.exception("%s" % err)
                resp = ServiceError("%s" % err)
                return resp(environ, start_response)

    LOGGER.debug("unknown side: %s", path)
    resp = NotFound("Couldn't find the side you asked for!")
    return resp(environ, start_response)


# ----------------------------------------------------------------------------

if __name__ == '__main__':
    import argparse
    import importlib

    from cherrypy import wsgiserver
    from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

    from oic.utils.sdb import SessionDB

    PARSER = argparse.ArgumentParser()
    PARSER.add_argument('-v', dest='verbose', action='store_true')
    PARSER.add_argument('-d', dest='debug', action='store_true')
    PARSER.add_argument('-p', dest='port', default=80, type=int)
    PARSER.add_argument('-k', dest='insecure', action='store_true')
    PARSER.add_argument(
        '-c', dest='capabilities',
        help="A file containing a JSON representation of the capabilities")
    PARSER.add_argument('-b', dest='baseurl', help="base url of the OP")
    PARSER.add_argument(dest="config")
    ARGS = PARSER.parse_args()

    # Client data base
    CDB = shelve_wrapper.open("client_db", writeback=True)

    sys.path.insert(0, ".")
    CONFIG = importlib.import_module(ARGS.config)
    if ARGS.baseurl:
        CONFIG.BASEURL = ARGS.baseurl

    CONFIG.ISSUER = CONFIG.ISSUER.format(base=CONFIG.BASEURL, port=ARGS.port)
    CONFIG.SERVICE_URL = CONFIG.SERVICE_URL.format(issuer=CONFIG.ISSUER)

    AC = AuthnBroker()

    SAML_AUTHN = None

    END_POINTS = CONFIG.AUTHENTICATION["UserPassword"]["END_POINTS"]
    FULL_END_POINT_PATHS = ["%s%s" % (CONFIG.ISSUER, ep) for ep in END_POINTS]
    USERNAME_PASSWORD_AUTHN = UsernamePasswordMako(
        None, "login.mako", LOOKUP, PASSWD, "%sauthorization" % CONFIG.ISSUER,
        None, FULL_END_POINT_PATHS)

    for authkey, value in CONFIG.AUTHENTICATION.items():
        authn = None

        if "UserPassword" == authkey:
            PASSWORD_END_POINT_INDEX = 0
            end_point = CONFIG.AUTHENTICATION[authkey]["END_POINTS"][
                PASSWORD_END_POINT_INDEX]
            authn = AuthnIndexedEndpointWrapper(USERNAME_PASSWORD_AUTHN,
                                                PASSWORD_END_POINT_INDEX)
            URLS.append((r'^' + end_point, make_auth_verify(authn.verify)))

        # Ensure javascript_login_authn to be defined
        try:
            javascript_login_authn
        except NameError:
            javascript_login_authn = None

        if "JavascriptLogin" == authkey:
            if not javascript_login_authn:
                END_POINTS = CONFIG.AUTHENTICATION[
                    "JavascriptLogin"]["END_POINTS"]
                FULL_END_POINT_PATHS = [
                    "%s/%s" % (CONFIG.ISSUER, ep) for ep in END_POINTS]
                javascript_login_authn = JavascriptFormMako(
                    None, "javascript_login.mako", LOOKUP, PASSWD,
                    "%s/authorization" % CONFIG.ISSUER, None,
                    FULL_END_POINT_PATHS)
            AC.add("", javascript_login_authn, "", "")
            JAVASCRIPT_END_POINT_INDEX = 0
            end_point = CONFIG.AUTHENTICATION[authkey]["END_POINTS"][
                JAVASCRIPT_END_POINT_INDEX]
            authn = AuthnIndexedEndpointWrapper(javascript_login_authn,
                                                JAVASCRIPT_END_POINT_INDEX)
            URLS.append((r'^' + end_point, make_auth_verify(authn.verify)))

        if "SAML" == authkey:
            from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST

            if not SAML_AUTHN:
                SAML_AUTHN = SAMLAuthnMethod(
                    None, LOOKUP, CONFIG.SAML, CONFIG.SP_CONFIG, CONFIG.ISSUER,
                    "%s/authorization" % CONFIG.ISSUER,
                    userinfo=CONFIG.USERINFO)
            AC.add("", SAML_AUTHN, "", "")
            SAML_END_POINT_INDEX = 0
            end_point = CONFIG.AUTHENTICATION[authkey]["END_POINTS"][
                SAML_END_POINT_INDEX]
            end_point_indexes = {BINDING_HTTP_REDIRECT: 0, BINDING_HTTP_POST: 0,
                                 "disco_end_point_index": 0}
            authn = AuthnIndexedEndpointWrapper(SAML_AUTHN, end_point_indexes)
            URLS.append((r'^' + end_point, make_auth_verify(authn.verify)))

        if "SamlPass" == authkey:
            from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST

            if not SAML_AUTHN:
                SAML_AUTHN = SAMLAuthnMethod(
                    None, LOOKUP, CONFIG.SAML, CONFIG.SP_CONFIG, CONFIG.ISSUER,
                    "%s/authorization" % CONFIG.ISSUER,
                    userinfo=CONFIG.USERINFO)
            PASSWORD_END_POINT_INDEX = 1
            SAML_END_POINT_INDEX = 1
            password_end_point = CONFIG.AUTHENTICATION["UserPassword"][
                "END_POINTS"][PASSWORD_END_POINT_INDEX]
            saml_endpoint = CONFIG.AUTHENTICATION["SAML"]["END_POINTS"][
                SAML_END_POINT_INDEX]

            end_point_indexes = {BINDING_HTTP_REDIRECT: 1, BINDING_HTTP_POST: 1,
                                 "disco_end_point_index": 1}
            multi_saml = AuthnIndexedEndpointWrapper(SAML_AUTHN,
                                                     end_point_indexes)
            multi_password = AuthnIndexedEndpointWrapper(
                USERNAME_PASSWORD_AUTHN, PASSWORD_END_POINT_INDEX)

            auth_modules = [(multi_saml, r'^' + saml_endpoint),
                            (multi_password, r'^' + password_end_point)]
            authn = setup_multi_auth(AC, URLS, auth_modules)

        if "JavascriptPass" == authkey:
            if not javascript_login_authn:
                END_POINTS = CONFIG.AUTHENTICATION[
                    "JavascriptLogin"]["END_POINTS"]
                FULL_END_POINT_PATHS = [
                    "%s/%s" % (CONFIG.ISSUER, ep) for ep in END_POINTS]
                javascript_login_authn = JavascriptFormMako(
                    None, "javascript_login.mako", LOOKUP, PASSWD,
                    "%s/authorization" % CONFIG.ISSUER, None,
                    FULL_END_POINT_PATHS)

            PASSWORD_END_POINT_INDEX = 2
            JAVASCRIPT_POINT_INDEX = 1

            password_end_point = CONFIG.AUTHENTICATION["UserPassword"][
                "END_POINTS"][PASSWORD_END_POINT_INDEX]
            javascript_end_point = CONFIG.AUTHENTICATION["JavascriptLogin"][
                "END_POINTS"][JAVASCRIPT_POINT_INDEX]

            multi_password = AuthnIndexedEndpointWrapper(
                USERNAME_PASSWORD_AUTHN, PASSWORD_END_POINT_INDEX)
            multi_javascript = AuthnIndexedEndpointWrapper(
                javascript_login_authn, JAVASCRIPT_POINT_INDEX)

            auth_modules = [(multi_password, r'^' + password_end_point),
                            (multi_javascript, r'^' + javascript_end_point)]
            authn = setup_multi_auth(AC, URLS, auth_modules)

        if authn is not None:
            AC.add(CONFIG.AUTHENTICATION[authkey]["ACR"], authn,
                   CONFIG.AUTHENTICATION[authkey]["WEIGHT"],
                   "")

    # dealing with authorization
    AUTHZ = AuthzHandling()

    KWARGS = {
        "template_lookup": LOOKUP,
        "template": {"form_post": "form_response.mako"},
        # "template_args": {"form_post": {"action": "form_post"}}
    }

    # Should I care about verifying the certificates used by other entities
    if ARGS.insecure:
        KWARGS["verify_ssl"] = False
    else:
        KWARGS["verify_ssl"] = True

    if ARGS.capabilities:
        KWARGS["capabilities"] = json.loads(open(ARGS.capabilities).read())
    else:
        pass

    OAS = SWSProvider(CONFIG.ISSUER, SessionDB(CONFIG.BASEURL), CDB, AC, None,
                      AUTHZ, verify_client, CONFIG.SYM_KEY, CONFIG.TRUSTED_CERT_DOMAINS,
                      verify_signer_ssl=CONFIG.VERIFY_SIGNER_SSL, **KWARGS)

    OAS.baseurl = CONFIG.ISSUER

    for authn in AC:
        authn.srv = OAS

    if CONFIG.USERINFO == "SIMPLE":
        # User info is a simple dictionary in this case statically defined in
        # the configuration file
        OAS.userinfo = UserInfo(CONFIG.USERDB)
    elif CONFIG.USERINFO == "SAML":
        OAS.userinfo = UserInfo(CONFIG.SAML)
    elif CONFIG.USERINFO == "AA":
        OAS.userinfo = AaUserInfo(CONFIG.SP_CONFIG, CONFIG.ISSUER, CONFIG.SAML)
    else:
        raise Exception("Unsupported userinfo source")

    try:
        OAS.cookie_ttl = CONFIG.COOKIETTL
    except AttributeError:
        pass

    try:
        OAS.cookie_name = CONFIG.COOKIENAME
    except AttributeError:
        pass

    # print URLS
    if ARGS.debug:
        OAS.debug = True

    # All endpoints the OpenID Connect Provider should answer on
    add_endpoints(ENDPOINTS)
    OAS.endpoints = ENDPOINTS

    try:
        JWKS = keyjar_init(OAS, CONFIG.KEYS, kid_template="op%d")
    except Exception as err:
        LOGGER.error("Key setup failed: %s", err)
        OAS.key_setup("static", sig={"format": "jwk", "alg": "rsa"})
    else:
        NEW_NAME = "static/jwks.json"
        F = open(NEW_NAME, "w")
        F.write(json.dumps(JWKS))
        F.close()
        OAS.jwks_uri.append("%s%s" % (OAS.baseurl, NEW_NAME))

    for b in OAS.keyjar[""]:
        LOGGER.info("OC3 server keys: %s", b)

    # Setup the web server
    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', ARGS.port), application)

    HTTPS = ""
    if CONFIG.SERVICE_URL.startswith("https"):
        HTTPS = "using HTTPS"
        SRV.ssl_adapter = BuiltinSSLAdapter(
            CONFIG.SERVER_CERT, CONFIG.SERVER_KEY, CONFIG.CERT_CHAIN)

    LOGGER.info("OC server starting listening on port:%s %s", ARGS.port, HTTPS)
    print("OC server starting listening on port:%s %s" % (ARGS.port, HTTPS))
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
