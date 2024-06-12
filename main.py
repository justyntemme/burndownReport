import json
import csv
import logging
import io
import os
import requests
from typing import Tuple, Optional

logging.basicConfig(level=logging.INFO)

TL_URL = os.environ.get("TL_URL")


def getINCS(token: str) -> Tuple[int, str]:
    auditsURL = TL_URL + "/api/v1/audits/runtime/container/download?limit=1"
    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    response = requests.get(auditsURL, headers=headers, timeout=60, verify=False)
    return (response.status_code, response.text)


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


def parseString(content: str) -> str:
    fieldnames = (
        "Type",
        "Attack",
        "Container",
        "Image",
        "Hostname",
        "Message",
        "Rule",
        "Effect",
        "Custom Labels",
        "Date",
        "AttackTechniques",
    )
    reader = csv.DictReader(io.StringIO(content), fieldnames)
    out = json.dumps([row for row in reader])
    return out


def count_unique_values(json_list, keys):
    # Initialize a dictionary to store counts for each key
    counts = {key: {} for key in keys}

    # Iterate through each JSON object in the list
    for obj in json_list:
        for key in keys:
            # Get the value for the key in the current object
            value = obj.get(key)
            if value is not None:
                # Update the count for the value in the corresponding key's dictionary
                if value in counts[key]:
                    counts[key][value] += 1
                else:
                    counts[key][value] = 1

    return counts


def main():
    accessKey = os.environ.get("PC_IDENTITY")
    accessSecret = os.environ.get("PC_SECRET")
    responseCode, cwpToken = generateCwpToken(accessKey, accessSecret)
    responseCode, content = getINCS(cwpToken)

    jsonContent = parseString(content)

    j = json.loads(jsonContent)
    for item in j:
        print(item)


if __name__ == "__main__":
    main()
