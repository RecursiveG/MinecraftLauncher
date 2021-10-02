#!/usr/bin/python3

# XSTS =? Xbox One Security Token Service

# Request device token
# Xbox SISU authenticate
#   Microsoft OAuth2 login
#   Microsoft OAuth2 token  <= refresh this token
# Xbox SISU authorization
# Xbox XSTS authorization
# Minecraft login with xbox

import httplib2
import sys
import json
import logging
from absl import app
from absl import flags
from pathlib import Path
import uuid
import base64
import hashlib
import time
from datetime import datetime as DT
from datetime import timezone
import dateutil.parser
import secrets
import string
import urllib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

FLAGS = flags.FLAGS
flags.DEFINE_string("credential", "credential.json", "Location to credential database")
flags.DEFINE_bool("verbose", False, "")
#flags.DEFINE_bool("force_refresh_oauth2_access_token", False, "")
#flags.mark_flag_as_required("credential")

logger = logging.getLogger()
logger.setLevel(logging.CRITICAL)
http = httplib2.Http()


def gen_pkce_code(verifier_len=86) -> (str, str, str):
    # returns verifier, challenge_method, challenge
    verifier = ''.join(secrets.choice(string.ascii_letters + string.digits + "-_.~") for _ in range(verifier_len))
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode()
    challenge = challenge.replace('=', '')
    return verifier, "S256", challenge


def load_credential() -> dict:
    p = Path(FLAGS.credential)
    if not p.exists():
        return dict()
    with open(p, "r") as f:
        return json.load(f)


def save_credential(cred: dict):
    with open(Path(FLAGS.credential), "w") as f:
        json.dump(cred, f, indent=2)


def near_expire(d: dict, before_exp=24 * 60 * 60) -> bool:
    if "NotAfter" not in d: return True
    exp_time = dateutil.parser.isoparse(d["NotAfter"])
    zoned_now = DT.now(timezone.utc)
    remaining_seconds = (exp_time - zoned_now).total_seconds()
    if remaining_seconds < before_exp:
        # expire in x seconds
        return True
    else:
        return False


# returns the "Signature" header string
# siging code taken from https://github.com/Jviguy/queueProxy/blob/master/gophertunnel/minecraft/auth/xbox.go
# http_method: POST etc.
# uri_path: /device/authenticate etc.
def sign(http_method: str, uri_path: str, payload: str, priv_key: ec.EllipticCurvePrivateKey) -> str:
    # windows timestamp
    win_time = (int(time.time()) + 11644473600) * 10000000

    data = b''
    # version 0.0.0.1 followed by null byte
    data += b"\0\0\0\1\0"
    # uint64 timestamp + null byte
    data += win_time.to_bytes(8, "big") + b'\0'
    # http method
    data += http_method.encode() + b'\0'
    # uri path
    data += uri_path.encode() + b'\0'
    #
    data += b'\0'
    # payload
    data += payload.encode() + b'\0'

    # sign
    sig = priv_key.sign(data, ec.ECDSA(hashes.SHA256()))
    (r, s) = decode_dss_signature(sig)
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder="big")
    s_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder="big")

    # signature = version + timestamp + r + s
    raw_sig = b'\0\0\0\1' + win_time.to_bytes(8, "big") + r_bytes + s_bytes
    sig = base64.b64encode(raw_sig).decode("ascii")
    return sig


def get_proofkey(priv_key: ec.EllipticCurvePrivateKey):
    def int_to_base64(x: int, length=32, byteorder='big') -> str:
        return base64.urlsafe_b64encode(x.to_bytes(length, byteorder)).decode("ascii").replace('=', '')

    return dict(alg="ES256",
                crv="P-256",
                kty="EC",
                use="sig",
                x=int_to_base64(priv_key.private_numbers().public_numbers.x),
                y=int_to_base64(priv_key.private_numbers().public_numbers.y))


# ============== #


def get_device_key(cred) -> ec.EllipticCurvePrivateKey:
    if "device_private_key" not in cred:
        logging.info("Creating new device private key")
        priv_key = ec.generate_private_key(ec.SECP256R1)
        priv_key_pem = priv_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        cred["device_private_key"] = priv_key_pem.decode("ascii")
        save_credential(cred)
        return priv_key
    else:
        return load_pem_private_key(cred["device_private_key"].encode(), None)


# returns device token string
def get_device_token(cred) -> str:
    if "device_token" in cred and not near_expire(cred["device_token"]):
        return cred["device_token"]["Token"]

    priv_key: ec.EllipticCurvePrivateKey = get_device_key(cred)
    # yapf: disable
    payload_obj = dict(
        Properties=dict(
            AuthMethod="ProofOfPossession",
            DeviceType="Win32",
            Id="{" + str(uuid.uuid4()).upper() + "}",
            ProofKey=get_proofkey(priv_key),
            #SerialNumber="{" + str(uuid.uuid4()) + "}",
            #Version="6.1.7601"
        ),
        RelyingParty="http://auth.xboxlive.com",
        TokenType="JWT"
    )
    # yapf: enable

    payload = json.dumps(payload_obj, indent=2)
    target = 'https://device.auth.xboxlive.com/device/authenticate'
    sig = sign("POST", '/device/authenticate', payload, priv_key)

    (resp, content) = http.request(target,
                                   "POST",
                                   headers={
                                       "Content-Type": "application/json",
                                       "x-xbl-contract-version": "1",
                                       "Signature": sig
                                   },
                                   body=payload)
    assert resp["status"] == '200', (resp, content)
    device_token = json.loads(content.decode())
    cred["device_token"] = device_token
    save_credential(cred)
    return device_token["Token"]


def get_login_url(cred) -> (str, str):
    # returns uri, verifier
    priv_key: ec.EllipticCurvePrivateKey = get_device_key(cred)
    device_token: str = get_device_token(cred)
    (verifier, challenge_method, challenge) = gen_pkce_code()

    # yapf: disable
    payload_obj = dict(
        AppId='00000000402b5328',
        DeviceToken=device_token,
        Offers=['service::user.auth.xboxlive.com::MBI_SSL'],
        Query=dict(
            code_challenge=challenge,
            code_challenge_method=challenge_method,
            state=""
        ),
        RedirectUri="https://login.live.com/oauth20_desktop.srf",
        Sandbox="RETAIL",
        TokenType="code",
    )
    # yapf: enable
    payload = json.dumps(payload_obj, indent=2)
    target = 'https://sisu.xboxlive.com/authenticate'
    sig = sign("POST", '/authenticate', payload, priv_key)
    (resp, content) = http.request(target,
                                   "POST",
                                   headers={
                                       "Content-Type": "application/json",
                                       "x-xbl-contract-version": "1",
                                       "Signature": sig
                                   },
                                   body=payload)
    assert resp["status"] == '200', (resp, content)
    return json.loads(content.decode())["MsaOauthRedirect"], verifier


def get_oauth2_auth_code(cred) -> (str, str):
    # returns oauth2 autherization code, verifier
    (uri, verifier) = get_login_url(cred)

    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from urllib.parse import urlparse, parse_qs
    driver = webdriver.Chrome()
    driver.get(uri)
    _w = WebDriverWait(driver, 600).until(EC.url_matches('^https://login.live.com/oauth20_desktop.srf'))
    redirected_url = driver.current_url
    driver.quit()
    q = urlparse(redirected_url).query
    return parse_qs(q)["code"][0], verifier


def get_oauth2_accesstoken(cred) -> str:
    # returns oauth2_accesstoken
    need_refresh = False
    if "oauth2_accesstoken" not in cred or "oauth2_accesstoken_expiration" not in cred:
        need_refresh = True
    else:
        seconds_till_expire = cred["oauth2_accesstoken_expiration"] - int(time.time())
        if seconds_till_expire < 600:
            need_refresh = True
    if not need_refresh:
        return cred["oauth2_accesstoken"]["access_token"]

    # try refresh token
    if "oauth2_accesstoken" in cred and "refresh_token" in cred["oauth2_accesstoken"]:
        logger.info("refreshing oauth2 access token")
        refresh_token = cred["oauth2_accesstoken"]["refresh_token"]
        payload_obj = dict(
            client_id="00000000402b5328",
            refresh_token=refresh_token,
            grant_type="refresh_token",
            redirect_uri="https://login.live.com/oauth20_desktop.srf",
            scope="service::user.auth.xboxlive.com::MBI_SSL",
        )
        payload = urllib.parse.urlencode(payload_obj)
        target = 'https://login.live.com/oauth20_token.srf'
        (resp, content) = http.request(target,
                                       "POST",
                                       headers={"Content-Type": "application/x-www-form-urlencoded"},
                                       body=payload)
        if resp["status"] == "200":
            rsp_obj = json.loads(content.decode())
            cred["oauth2_accesstoken"] = rsp_obj
            cred["oauth2_accesstoken_expiration"] = int(time.time()) + rsp_obj["expires_in"]
            save_credential(cred)
            return rsp_obj["access_token"]
        else:
            logger.info("oauth2 token refresh failed")
            logger.debug(resp, content)

    # require re-login
    (auth_code, verifier) = get_oauth2_auth_code(cred)
    logger.info("getting oauth2 access token")
    payload_obj = dict(
        client_id="00000000402b5328",
        code=auth_code,
        code_verifier=verifier,
        grant_type="authorization_code",
        redirect_uri="https://login.live.com/oauth20_desktop.srf",
        scope="service::user.auth.xboxlive.com::MBI_SSL",
    )
    payload = urllib.parse.urlencode(payload_obj)
    target = 'https://login.live.com/oauth20_token.srf'
    (resp, content) = http.request(target,
                                   "POST",
                                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                                   body=payload)
    assert resp["status"] == '200', (resp, content)
    rsp_obj = json.loads(content.decode())
    cred["oauth2_accesstoken"] = rsp_obj
    cred["oauth2_accesstoken_expiration"] = int(time.time()) + rsp_obj["expires_in"]
    save_credential(cred)
    return rsp_obj["access_token"]


def sisu_authorization(cred):
    def need_refresh(cred):
        if "sisu_token_dict" not in cred: return True
        td = cred["sisu_token_dict"]
        if "sisu_token_dict" not in td: return True
        if "TitleToken" not in td or near_expire(td["TitleToken"]): return True
        if "UserToken" not in td or near_expire(td["UserToken"]): return True
        #Authorization token is not used
        #if "AuthorizationToken" not in td or near_expire(td["AuthorizationToken"]): return True
        return False

    if not need_refresh(cred):
        return cred["sisu_token_dict"]

    oauth2_access_token = get_oauth2_accesstoken(cred)
    device_token = get_device_token(cred)
    priv_key = get_device_key(cred)

    payload_obj = dict(
        AccessToken="t=" + oauth2_access_token,
        AppId="00000000402b5328",
        DeviceToken=device_token,
        ProofKey=get_proofkey(priv_key),
        RelyingParty="http://xboxlive.com",
        Sandbox="RETAIL",
    # SessionId="00fbafefcd8f4b4e8f3ef3402cfc79543",
        SiteName="user.auth.xboxlive.com",
        UseModernGamertag=True,
    )
    payload = json.dumps(payload_obj, indent=2)
    target = 'https://sisu.xboxlive.com/authorize'
    sig = sign("POST", '/authorize', payload, priv_key)
    (resp, content) = http.request(target,
                                   "POST",
                                   headers={
                                       "Content-Type": "application/json",
                                       "Signature": sig
                                   },
                                   body=payload)
    assert resp["status"] == '200', (resp, content)
    sisu_token_dict = json.loads(content.decode())
    cred["sisu_token_dict"] = sisu_token_dict
    save_credential(cred)
    return sisu_token_dict


def get_xsts_token(cred) -> (str, str):
    # returns xsts_token, userhash
    if "xsts_token" in cred and not near_expire(cred["xsts_token"], 600):
        return cred["xsts_token"]["Token"], cred["xsts_token"]["DisplayClaims"]["xui"][0]["uhs"]

    sisu_token_dict = sisu_authorization(cred)
    priv_key = get_device_key(cred)
    # yapf: disable
    payload_obj = dict(
        Properties=dict(
            SandboxId="RETAIL",
            UserTokens=[sisu_token_dict["UserToken"]["Token"]]
        ),
        RelyingParty="rp://api.minecraftservices.com/",
        TokenType="JWT"
    )
    # yapf: enable
    payload = json.dumps(payload_obj, indent=2)
    target = 'https://xsts.auth.xboxlive.com/xsts/authorize'
    sig = sign("POST", '/xsts/authorize', payload, priv_key)
    (resp, content) = http.request(target,
                                   "POST",
                                   headers={
                                       "Content-Type": "application/json",
                                       "x-xbl-contract-version": "1",
                                       "Signature": sig
                                   },
                                   body=payload)
    assert resp["status"] == '200', (resp, content)
    xsts_token_obj = json.loads(content.decode())
    assert len(xsts_token_obj["DisplayClaims"]["xui"]) == 1, (resp, content)
    cred["xsts_token"] = xsts_token_obj
    save_credential(cred)
    return xsts_token_obj["Token"], xsts_token_obj["DisplayClaims"]["xui"][0]["uhs"]


def get_minecraft_accesstoken(cred) -> str:
    if "minecraft_accesstoken_expiration" in cred:
        seconds_till_expire = cred["minecraft_accesstoken_expiration"] - int(time.time())
        if seconds_till_expire > 12 * 3600:
            return cred["minecraft_accesstoken"]["access_token"]

    (xsts_token, userhash) = get_xsts_token(cred)
    payload_obj = dict(identityToken="XBL3.0 x=%s;%s" % (userhash, xsts_token))
    payload = json.dumps(payload_obj, indent=2)
    target = 'https://api.minecraftservices.com/authentication/login_with_xbox'
    (resp, content) = http.request(target, "POST", headers={"Content-Type": "application/json"}, body=payload)
    assert resp["status"] == '200', (resp, content)
    rsp_obj = json.loads(content.decode())
    cred["minecraft_accesstoken"] = rsp_obj
    cred["minecraft_accesstoken_expiration"] = int(time.time()) + rsp_obj["expires_in"]
    save_credential(cred)
    return rsp_obj["access_token"]


def main(argv):
    del argv

    if FLAGS.verbose:
        logger.setLevel(logging.DEBUG)
        httplib2.debuglevel = 1

    cred = load_credential()
    mc_accesstoken = get_minecraft_accesstoken(cred)
    print(mc_accesstoken)


if __name__ == '__main__':
    app.run(main)
