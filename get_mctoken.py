#!/usr/bin/python3

import httplib2
import sys
import json
import logging
from absl import app
from absl import flags
from pathlib import Path
import uuid

FLAGS = flags.FLAGS
flags.DEFINE_string("token_file", None, "File containing the access token")
flags.mark_flag_as_required("token_file")

logger = logging.getLogger()
#logger.setLevel(logging.DEBUG)
logger.setLevel(logging.CRITICAL)
http = httplib2.Http()

def new_access_token(client_token, old_token) -> str:
    if old_token != "":
        # try validation
        target = "https://authserver.mojang.com/validate"
        payload = r'{"accessToken": "%s", "clientToken": "%s"}'%(old_token, client_token)
    
        logging.debug("Validating ... %s %s", target, payload)
        (resp, content) = http.request(target, "POST", headers={"Content-Type": "application/json"}, body=payload)
        logging.debug("Validation result: %s", resp)
    
        if resp["status"] == "204":
            logging.info("accessToken is VALID")
            return old_token

    
    # Token is invalid, now refresh
    logging.info("accessToken is INVALID")
    target = "https://authserver.mojang.com/refresh"
    payload = r'{"accessToken": "%s", "clientToken": "%s"}'%(old_token, client_token)
    
    logging.debug("Refreshing ... %s %s", target, payload)
    (resp, content) = http.request(target, "POST", headers={"Content-Type": "application/json"}, body=payload)
    logging.debug("Refreshing result header: %s", resp)
    logging.debug("Refreshing result body: %s", content)
    
    if resp["status"][0] == '2': # 2xx return code
        logging.info("Refreshing SUCCESS")
        resp_json = json.loads(content.decode("UTF-8"))
        assert resp_json["clientToken"] == client_token
        return resp_json["accessToken"]
        
    # Refresh failed, need reauthenticate
    logging.info("Refreshing FAILED")
    auth_username = input("Username: ")
    auth_password = input("Password: ")

    target = "https://authserver.mojang.com/authenticate"
    payload = r'{"agent":{"name":"Minecraft","version":1},"username":"%s","password":"%s","clientToken":"%s"}'\
            %(auth_username, auth_password, client_token)

    
    logging.debug("Authenticating ... %s %s", target, payload)
    (resp, content) = http.request(target, "POST", headers={"Content-Type": "application/json"}, body=payload)
    logging.debug("Authentication result header: %s", resp)
    logging.debug("Authentication result body: %s", content)

    if resp["status"][0] == '2': # 2xx return code
        logging.info("Authentication SUCCESS")
        resp_json = json.loads(content.decode("UTF-8"))
        assert resp_json["clientToken"] == client_token
        return resp_json["accessToken"]
    
    assert False, "Authentication failed"
    return ""

def main(argv):
    del argv
    token_file_path = Path(FLAGS.token_file).resolve()
    assert token_file_path.is_file() or not token_file_path.exists()
    if token_file_path.exists():
        with open(token_file_path, 'r') as f:
            account_info = json.load(f)
    else:
        account_info = dict()
    if "client_id" not in account_info:
        account_info["client_id"] = str(uuid.uuid4()).replace('-','')
        account_info["access_token"] = ""
    if "access_token" not in account_info:
        account_info["access_token"] = ""
    account_info["access_token"] = new_access_token(account_info["client_id"], account_info["access_token"])
    with open(token_file_path, "w") as f:
        f.write(json.dumps(account_info, sort_keys=True, indent=2, separators=(',', ': ')))
    print(account_info["access_token"])

if __name__ == '__main__':
  app.run(main)
