# pylint: disable = missing-docstring
import json
import ssl

from jwkest.jws import alg2keytype
from http.server import HTTPServer, SimpleHTTPRequestHandler

from oic.utils.keyio import build_keyjar
import os
from software_statement.message import SWSMessage

__author__ = 'mathiashedstrom'

PATH = os.path.dirname(__file__)

PORT = 8096
HOST = "localhost"

KEYS = [
    {"type": "RSA", "key": os.path.join(PATH, "sign_keys/private.key"),
     "use": ["enc", "sig"]},
]


def create_software_statement(sws_data):
    sws_data["iss"] = "https://{host}:{port}/static/jwks.json".format(host=HOST, port=PORT)
    sws = SWSMessage()
    sws.from_dict(sws_data)

    _, keyjar, _ = build_keyjar(KEYS)
    alg = 'RS256'
    ckey = keyjar.get_signing_key(alg2keytype(alg), "",
                                  alg=alg)
    return sws.to_jwt(key=ckey, algorithm=alg)


if __name__ == '__main__':

    if not os.path.exists("static"):
        os.makedirs("static")
    JWKS, _, _ = build_keyjar(KEYS)
    JWKS_PATH = "static/jwks.json"
    F = open(JWKS_PATH, "w")
    F.write(json.dumps(JWKS))
    F.close()

    HTTPD = HTTPServer((HOST, PORT), SimpleHTTPRequestHandler)
    HTTPD.socket = ssl.wrap_socket(HTTPD.socket, certfile='cp_keys/cert.pem', server_side=True,
                                   keyfile="cp_keys/key.pem")
    print("serving at port", PORT)
    HTTPD.serve_forever()
