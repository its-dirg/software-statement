import json
from oic.utils.keyio import KeyBundle, KeyJar
import requests
from requests.exceptions import ConnectionError
from oic.oauth2.message import SINGLE_REQUIRED_STRING
from jwkest import jws, BadSignature

from six.moves.urllib.parse import urlsplit
from oic.oauth2.message import SchemeError
from oic.oic.message import RegistrationRequest

__author__ = 'mathiashedstrom'


class UntrustedDomainException(Exception):
    pass


class SWSMessage(RegistrationRequest):
    c_param = {"iss": SINGLE_REQUIRED_STRING}
    c_param.update(RegistrationRequest.c_param)
    c_default = {}

    def __init__(self, trusted_domains=[], verify_signer_ssl=True, **kwargs):
        super(SWSMessage, self).__init__(**kwargs)
        self.verify_signer_ssl = verify_signer_ssl
        self.trusted_domains = trusted_domains
        self.sws_jwt = None

    def from_jwt(self, txt, key=None, verify=True, keyjar=None, **kwargs):
        super(SWSMessage, self).from_jwt(txt, key=key, verify=False, keyjar=keyjar, **kwargs)
        self.sws_jwt = txt
        if verify:
            self.verify(txt, **kwargs)

    def verify(self, txt=None, verify_signature=True, **kwargs):
        super(SWSMessage, self).verify(**kwargs)
        if verify_signature:
            self._verify_signature(txt=txt)

    def _verify_signature(self, txt=None):
        if not txt:
            txt = self.sws_jwt
        _jw = jws.factory(txt)
        if not _jw:
            raise BadSignature("SWS message not signed")
        _jw.verify_compact(txt, self._get_cert_key(self._dict["iss"]))


    def _get_cert_key(self, issuer):
        split_iss = urlsplit(issuer)
        try:
            assert split_iss.scheme == "https"
        except AssertionError:
            raise SchemeError("iss in software_statement is not HTTPS, {}".format(issuer))

        self._assert_valid_domain(split_iss)

        try:
            res = requests.get(issuer, verify=self.verify_signer_ssl)
        except ConnectionError as con_exc:
            raise ConnectionError("Could not connect to sws signer server: {}".format(str(con_exc)))
        try:
            kb = KeyBundle(keys=json.loads(res.text)["keys"])
            kj = KeyJar()
            kj.issuer_keys[issuer] = [kb]
        except (ValueError, KeyError):
            raise ValueError("Unknown key format: {}".format(res.text))
        return kj.get_verify_key(owner=issuer)

    def _assert_valid_domain(self, iss):
        for domain in self.trusted_domains:
            split_domain = urlsplit(domain)
            if split_domain.scheme == iss.scheme and split_domain.netloc == iss.netloc:
                return
        raise UntrustedDomainException(
            "The cert issuer is not present in the list of trusted domains, {}".format(iss))
