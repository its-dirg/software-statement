import hashlib

from six import iteritems

from oic.oauth2 import rndstr
from oic.oauth2.message import MissingRequiredAttribute
from oic.oic.message import RegistrationRequest, AuthorizationRequest
from oic.oic.provider import Provider, secret, RegistrationEndpoint
from oic.utils.http_util import Response
from oic.utils.time_util import utc_time_sans_frac
from software_statement.message import SWSMessage

__author__ = 'mathiashedstrom'


class SWSProvider(Provider):
    def __init__(self, name, sdb, cdb, authn_broker, userinfo, authz,
                 client_authn, symkey, trusted_domains, verify_signer_ssl=True, **kwarg):
        Provider.__init__(self, name, sdb, cdb, authn_broker, userinfo, authz,
                          client_authn, symkey, **kwarg)

        self.trusted_domains = trusted_domains
        self.verify_signer_ssl = verify_signer_ssl

    def registration_endpoint(self, request, authn=None, **kwargs):
        unpacked_request = self.unpack_request(request, RegistrationRequest)

        ignore = ["iss"]
        try:
            software_statement = self.retrieve_software_statement(
                unpacked_request["software_statement"])
        except KeyError:
            raise MissingRequiredAttribute("Request did not contain a software statement")

        for key, value in iteritems(software_statement.to_dict()):
            if key not in ignore:
                unpacked_request[key] = value

        # Update cache
        unpacked_request["software_statement_cache"] = self._get_sws_id(
            unpacked_request["software_statement"])

        return super(SWSProvider, self).registration_endpoint(unpacked_request, authn=authn,
                                                              unpack_request=False, **kwargs)

    def _get_sws_id(self, txt):
        return hashlib.md5(txt.encode("utf-8")).hexdigest()

    def authorization_endpoint(self, request="", cookie=None, **kwargs):
        unpacked_request = self.unpack_request(request, AuthorizationRequest)

        try:
            software_statement = self.retrieve_software_statement(unpacked_request["client_id"],
                                                                  verify=False)
        except Exception:
            software_statement = self.retrieve_software_statement(
                unpacked_request["software_statement"], verify=False)

        ignore = ["iss"]
        for key, value in iteritems(software_statement.to_dict()):
            if key not in ignore:
                unpacked_request[key] = value

        # Check the received sws against the cache.
        if not self.is_in_cache(unpacked_request):
            software_statement.verify()
            sws_id = self._get_sws_id(unpacked_request["software_statement"])
            resp = self.update_registered_data(sws_id, software_statement, unpacked_request)
            if resp:
                return resp

        request = unpacked_request.to_urlencoded()

        return super(SWSProvider, self).authorization_endpoint(request=request, cookie=cookie,
                                                               **kwargs)

    def update_registered_data(self, sws_id, software_statement, unpacked_request):
        client_id = unpacked_request["client_id"]

        if client_id not in self.cdb:
            client_secret = secret(self.seed, client_id)
            _rat = rndstr(32)
            reg_enp = ""
            for endp in self.endp:
                if endp == RegistrationEndpoint:
                    reg_enp = "%s%s" % (self.baseurl, endp.etype)
                    break

            self.cdb[client_id] = {
                "client_id": client_id,
                "client_secret": client_secret,
                "registration_access_token": _rat,
                "registration_client_uri": "%s?client_id=%s" % (reg_enp, client_id),
                "client_secret_expires_at": utc_time_sans_frac() + 86400,
                "client_id_issued_at": utc_time_sans_frac()}

            self.cdb[_rat] = client_id

        _cinfo = self.do_client_registration(software_statement.to_dict(), client_id,
                                             ignore=["redirect_uris",
                                                     "policy_uri", "logo_uri",
                                                     "tos_uri", "client_id",
                                                     "client_secret", "registration_access_token",
                                                     "registration_client_uri",
                                                     "client_secret_expires_at",
                                                     "client_id_issued_at", "software_statement"])
        if isinstance(_cinfo, Response):
            return _cinfo

        cinfo = self.cdb[client_id]

        args = dict([(k, v) for k, v in _cinfo.items()
                     if k in RegistrationRequest.c_param])

        for key, value in iteritems(args):
            cinfo[key] = value

        # Update cache
        cinfo["software_statement_cache"] = sws_id

        self.cdb[client_id] = cinfo
        try:
            self.cdb.sync()
        except AttributeError:  # Not all databases can be sync'ed
            pass

    def unpack_request(self, request, request_class):
        try:
            request_dict = request_class().deserialize(request, "json")
        except ValueError:
            request_dict = request_class().deserialize(request)

        return request_dict

    def is_in_cache(self, unpacked_request):
        # Check cache if the software statement need to be verified
        try:
            client_id = unpacked_request["client_id"]
            return self.cdb[client_id]["software_statement_cache"] == self._get_sws_id(
                unpacked_request["software_statement"])
        except KeyError:
            return False

    def retrieve_software_statement(self, text, verify=True):
        sws_m = SWSMessage(trusted_domains=self.trusted_domains,
                           verify_signer_ssl=self.verify_signer_ssl)
        sws_m.from_jwt(text, verify=verify)
        return sws_m
