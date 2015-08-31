# pylint: disable=missing-docstring,import-error
import json
import os
import six
import pytest
import responses
from time import time

from jwkest import BadSignature
from jwkest.jwk import import_rsa_key, RSAKey
from mock.mock import patch
from oic.oauth2.message import MissingRequiredAttribute
from oic.oauth2 import rndstr
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import AuthzHandling
from oic.utils.keyio import KeyJar
from oic.utils.keyio import keybundle_from_local_file
from oic.utils.sdb import SessionDB

from software_statement.message import SWSMessage
from six.moves.urllib.parse import urlparse, parse_qs
from software_statement.provider import SWSProvider, SWS_CACHE_KEY

OP_ISSUER = "https://connect-op.heroku.com"

CLIENT_ID = "client_1"
SIGNING_KEY_FILE = "private.key"

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "keys"))
KC_RSA = keybundle_from_local_file(os.path.join(BASE_PATH, SIGNING_KEY_FILE),
                                   "RSA", ["ver", "sig"])

KEYJAR = KeyJar()
KEYJAR[CLIENT_ID] = [KC_RSA]
KEYJAR[""] = KC_RSA

CDB = {}


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, **kwargs):
        if cookie == "FAIL":
            return None, 0
        else:
            return {"uid": self.user}, time()


# AUTHN = UsernamePasswordMako(None, "login.mako", tl, PASSWD, "authenticated")
AUTHN_BROKER = AuthnBroker()
AUTHN_BROKER.add("UNDEFINED", DummyAuthn(None, "username"))

# dealing with authorization
AUTHZ = AuthzHandling()
SYMKEY = rndstr(16)  # symmetric key used to encrypt cookie info

PATH = os.path.dirname(__file__)
SOFTWARE_API_PUBLISHER_URL = "https://localhost:9000"


def create_signed_sws(sws_data, pem):
    sws = SWSMessage(**sws_data)
    rsa_key = import_rsa_key(pem)
    key = [RSAKey().load_key(rsa_key)]
    alg = 'RS256'
    return sws.to_jwt(key=key, algorithm=alg)


def read_key_from_file(key_file_name):
    sig_pem_file = open(os.path.join(PATH, "keys/%s" % key_file_name))
    signing_pem = sig_pem_file.read()
    sig_pem_file.close()
    return signing_pem


def create_unpacked_reg_request_dict(client_id, request):
    reg_request_dict = request
    if isinstance(request, six.string_types):
        reg_request_dict = json.loads(request)

    reg_request_dict['client_id'] = client_id
    return reg_request_dict


def generate_signed_sws(key_file=SIGNING_KEY_FILE, sws_content=None):
    signing_pem = read_key_from_file(key_file)
    if not sws_content:
        sws_content = {"iss": SOFTWARE_API_PUBLISHER_URL,
                       "redirect_uris": ["https://localhost:9000"]}
    sws_jwts = create_signed_sws(sws_content, signing_pem)
    return sws_jwts, sws_content


class TestProvider:
    @pytest.fixture(autouse=True)
    def create_provider(self):
        self.provider = SWSProvider("pyoicserv",
                                    SessionDB(OP_ISSUER),
                                    CDB,
                                    AUTHN_BROKER,
                                    None,
                                    AUTHZ,
                                    verify_client,
                                    SYMKEY,
                                    trusted_domains=[SOFTWARE_API_PUBLISHER_URL],
                                    urlmap=None,
                                    keyjar=KEYJAR)

    def generate_sws_request_info(self, sws_content=None):
        sws_jwts, _ = generate_signed_sws(sws_content=sws_content)
        unpacked_request = create_unpacked_reg_request_dict(CLIENT_ID,
                                                            request={"software_statement": str(
                                                                sws_jwts)})
        sws_message, _ = self.provider._retrieve_software_statement(unpacked_request)
        return sws_message, unpacked_request

    @staticmethod
    def set_software_api_publisher_response():
        responses.add(responses.GET,
                      SOFTWARE_API_PUBLISHER_URL,
                      body=KC_RSA.jwks(),
                      status=200,
                      content_type='application/json')

    def test_set_sws_chache(self):
        sws_id = "sws_id"
        sws_message, unpacked_request = self.generate_sws_request_info()
        self.provider.update_registered_data(sws_id, sws_message, unpacked_request)
        assert self.provider.cdb[CLIENT_ID][SWS_CACHE_KEY] == sws_id

    @pytest.mark.parametrize("sws_data", ["client_id",
                                          "client_secret",
                                          "registration_access_token",
                                          "registration_client_uri",
                                          "client_secret_expires_at",
                                          "client_id_issued_at"])
    def test_should_not_overwrite_reg_attributes_with_sws_attributes(self, sws_data):
        sws_value = "SWS_VALUE"
        sws_message, unpacked_request = self.generate_sws_request_info(
            sws_content={sws_data: sws_value})
        self.provider.update_registered_data(None, sws_message, unpacked_request)
        database_info = self.provider.cdb[CLIENT_ID][sws_data]
        assert database_info != sws_value

    def test_client_secret_is_persistent_after_multiple_update_registered_data(self):
        sws_message, unpacked_request = self.generate_sws_request_info()

        self.provider.update_registered_data(None, sws_message, unpacked_request)
        client_secret_1 = self.provider.cdb[CLIENT_ID]['client_secret']

        self.provider.update_registered_data(None, sws_message, unpacked_request)
        client_secret_2 = self.provider.cdb[CLIENT_ID]['client_secret']

        assert client_secret_1 == client_secret_2

    @responses.activate
    def test_sws_as_client_id_authorization_end_point(self):
        self.set_software_api_publisher_response()
        software_statement, sws_content = generate_signed_sws()
        state = "id-6da9ca0cc23959f5f33e8becd9b08cae"

        authorization_request = {"scope": ["openid"],
                                 "state": state,
                                 "redirect_uri": SOFTWARE_API_PUBLISHER_URL,
                                 "response_type": ["code"],
                                 "client_id": str(software_statement),
                                 "nonce": "Nonce"}
        unpacked_request = create_unpacked_reg_request_dict(client_id=str(software_statement),
                                                            request={"software_statement": str(
                                                                software_statement)})
        assert not self.provider.is_in_cache(unpacked_request)
        response = self.provider.authorization_endpoint(request=json.dumps(authorization_request))
        assert self.provider.is_in_cache(unpacked_request)

        parsed_response = parse_qs(urlparse(response.message).query)
        assert parsed_response["state"][0] == state

    @responses.activate
    def test_if_sws_is_added_to_cache_in_registration_endpoint(self):
        self.set_software_api_publisher_response()
        sws_message, sws_content = generate_signed_sws()
        request = json.dumps({"software_statement": str(sws_message)})
        resp = self.provider.registration_endpoint(request)
        client_id = json.loads(resp.message)['client_id']
        registration_request = create_unpacked_reg_request_dict(client_id, request)
        assert self.provider.is_in_cache(registration_request)

    @responses.activate
    def test_check_if_unknown_registration_request_is_in_cache(self):
        software_statement, sws_content = generate_signed_sws()
        request = {"software_statement": str(software_statement)}
        registration_request = create_unpacked_reg_request_dict(client_id="UNKNOWN_CLIENT_ID",
                                                                request=json.dumps(request))
        assert not self.provider.is_in_cache(registration_request)

    def test_missing_software_statement_at_registration_request(self):
        with pytest.raises(MissingRequiredAttribute):
            self.provider.registration_endpoint('{"application_type": "web"}')

    @responses.activate
    def test_retrieve_software_statement_with_valid_signature(self):
        self.set_software_api_publisher_response()
        software_statement, sws_content = generate_signed_sws()

        sws_message = self.provider.parse_software_statement_as_jwt(software_statement)
        assert SWSMessage(**sws_content) == sws_message

    @responses.activate
    def test_retrieve_software_statement_with_invalid_signature(self):
        self.set_software_api_publisher_response()
        software_statement, _ = generate_signed_sws(key_file="private_2.key")

        with pytest.raises(BadSignature):
            self.provider.parse_software_statement_as_jwt(software_statement)

    @responses.activate
    @patch("oic.oic.provider.Provider.registration_endpoint")
    def test_unpack_sws_and_overwrite_registration_request_info(self,
                                                                super_registration_endpoint_mock):
        self.set_software_api_publisher_response()
        software_statement, sws_content = generate_signed_sws()
        url_to_overwrite = "https://localhost"

        request = {"redirect_uris": [url_to_overwrite],
                   "application_type": "web",
                   "software_statement": str(software_statement)}
        self.provider.registration_endpoint(json.dumps(request))
        # Get argument which the super class where called with
        unpacked_registration_request = super_registration_endpoint_mock.mock_calls[0][1][0]

        assert url_to_overwrite != sws_content['redirect_uris']
        assert unpacked_registration_request['redirect_uris'] == sws_content['redirect_uris']
