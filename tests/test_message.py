# pylint: disable=missing-docstring,import-error,protected-access,no-member
import os
import pytest
import responses
from jwkest import BadSignature
from jwkest.jwk import import_rsa_key
from jwkest.jwk import RSAKey
from oic.oauth2.message import SchemeError
from oic.oauth2.message import MissingRequiredAttribute
from software_statement.message import SWSMessage
from software_statement.message import UntrustedDomainException
from six.moves.urllib.parse import urlsplit

__author__ = 'mathiashedstrom'

PATH = os.path.dirname(__file__)


def test_dict():
    sws_data = {"iss": "https://test.com", "redirect_uris": ["https://example.com"]}
    sws_m = SWSMessage()
    sws_m.from_dict(sws_data)
    data = sws_m.to_dict()
    for key in data:
        assert sws_data[key] == data[key]
    assert len(sws_data) == len(data)


@pytest.mark.parametrize("domain", [
    ("https://not-valid.com"),
    ("http://example.com"),
    ("http://test.com"),
    ("http://example.se"),
])
def test_assert_valid_domain_fail(domain):
    valid_domains = ["https://example.com", "https://test.com"]
    sws_m = SWSMessage(trusted_domains=valid_domains)

    with pytest.raises(UntrustedDomainException):
        sws_m._assert_valid_domain(urlsplit(domain))


@pytest.mark.parametrize("domain", [
    ("https://example.com"),
    ("https://test.com"),
])
def test_assert_valid_domain_success(domain):
    trusted_domains = ["https://example.com", "https://test.com"]
    sws_m = SWSMessage(trusted_domains=trusted_domains)
    sws_m._assert_valid_domain(urlsplit(domain))


@responses.activate
def test_get_cert_key():
    port = "8565"
    iss = "https://localhost:{}/static/keys/key.pub".format(port)
    sws_data = {"iss": iss, "redirect_uris": ["https://example.com"]}

    key_file = open(os.path.join(PATH, "keys/public.key"))
    key = key_file.read()
    key_file.close()

    responses.add(responses.GET, iss, body=key, status=200, content_type='application/json')

    trusted_domains = ["https://localhost:8565"]
    sws_m = SWSMessage(trusted_domains=trusted_domains, verify_signer_ssl=False, **sws_data)
    downloaded_key = sws_m._get_cert_key(iss)
    assert downloaded_key == key

    with pytest.raises(SchemeError):
        sws_m._get_cert_key("http://example.com")

    trusted_domains = ["http://localhost:8565"]
    sws_m = SWSMessage(trusted_domains=trusted_domains, verify_signer_ssl=False, **sws_data)
    with pytest.raises(UntrustedDomainException):
        sws_m._get_cert_key(iss)


@pytest.mark.parametrize("sws_data", [
    ({"iss": "https:/iss.com"}),
    ({"redirect_uris": ["https://example.com"]}),
])
def test_missing_required_attr(sws_data):
    sws_m = SWSMessage(**sws_data)
    with pytest.raises(MissingRequiredAttribute):
        sws_m.verify()


@responses.activate
def test_valid_signature():
    sig_pem_file = open(os.path.join(PATH, "keys/private.key"))
    signing_pem = sig_pem_file.read()
    sig_pem_file.close()

    ver_pem_file = open(os.path.join(PATH, "keys/public.key"))
    ver_pem = ver_pem_file.read()
    ver_pem_file.close()

    iss = "https://test.com"
    trusted_domains = [iss]
    sws_data = {"iss": iss, "redirect_uris": ["https://example.com"]}
    signed_sws_jwt = _create_sig_sws(sws_data, signing_pem)

    responses.add(responses.GET, iss, body=ver_pem, status=200, content_type='application/json')

    sws_m = SWSMessage(trusted_domains=trusted_domains)
    sws_m.from_jwt(signed_sws_jwt)


@responses.activate
def test_invalid_signature():
    sig_pem_file = open(os.path.join(PATH, "keys/private_2.key"))
    signing_pem = sig_pem_file.read()
    sig_pem_file.close()

    ver_pem_file = open(os.path.join(PATH, "keys/public.key"))
    ver_pem = ver_pem_file.read()
    ver_pem_file.close()

    iss = "https://example.com"
    trusted_domains = [iss]
    sws_data = {"iss": iss, "redirect_uris": ["https://localhost"]}
    signed_sws_jwt = _create_sig_sws(sws_data, signing_pem)

    responses.add(responses.GET, iss, body=ver_pem, status=200, content_type='application/json')

    sws_m = SWSMessage(trusted_domains=trusted_domains)
    with pytest.raises(BadSignature):
        sws_m.from_jwt(signed_sws_jwt)


def _create_sig_sws(sws_data, pem):
    sws = SWSMessage(**sws_data)
    rsa_key = import_rsa_key(pem)
    key = [RSAKey().load_key(rsa_key)]
    alg = 'RS256'
    return sws.to_jwt(key=key, algorithm=alg)
