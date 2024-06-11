import json
import logging
import os
import requests
from typing import Tuple, Optional

logging.basicConfig(level=logging.INFO)

TL_URL = os.environ.get("TL_URL")

def getINCS(token: str):
    auditsURL = TL_URL + "/api/v1/audits/runtime/container/download?limit=10"
    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    response = requests.get(
        auditsURL, headers=headers, timeout=60, verify=False
    )

    print(response.content)

def generateCwpToken(accessKey: str, accessSecret: str) -> Tuple[int, str]:
    authURL = TL_URL + "/api/v1/authenticate"
    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
    }
    body = {"username": accessKey, "password": accessSecret}
    response = requests.post(
        authURL, headers=headers, json=body, timeout=60, verify=False
    )

    if response.status_code == 200:
        data = json.loads(response.text)
        logging.info("Token acquired")
        return 200, data["token"]
    else:
        logging.error(
            "Unable to acquire token with error code: %s", response.status_code
        )

    return response.status_code, ""

def main():
    accessKey = os.environ.get("PC_IDENTITY")
    accessSecret = os.environ.get("PC_SECRET")
    response, cwpToken = generateCwpToken(accessKey, accessSecret)
    getINCS(cwpToken)


if __name__ == "__main__":
    main()


