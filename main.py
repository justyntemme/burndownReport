import json
import csv
import logging
import io
import os
import requests
import numpy as np
from typing import Tuple, Optional
import matplotlib.pyplot as plt
import seaborn as sns

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


def count_unique_values(json_list) -> dict:
    keys = [
        "Type",
        "Attack",
        "Container",
        "Image",
        "Hostname",
        'Rule"',
        "AttackTechniques",
    ]
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


def visualize_data(data):
    # Set font size for general plots
    sns.set(font_scale=1.0)

    # Extract data from the dictionary
    type_data = data["Type"]
    attack_data = data["Attack"]
    container_data = data["Container"]
    image_data = data["Image"]
    hostname_data = data["Hostname"]

    # General font size for most plots
    general_font_size = 12

    # Specific font size for image and hostname plots
    specific_font_size = 8

    # Figure for type distribution with log scale
    plt.figure(figsize=(10, 6))
    sns.barplot(x=list(type_data.keys()), y=list(type_data.values()))
    plt.yscale("log")
    plt.title("Type Distribution (Log Scale)", fontsize=general_font_size)
    plt.xlabel("Type", fontsize=general_font_size)
    plt.ylabel("Count (Log Scale)", fontsize=general_font_size)
    plt.xticks(rotation=45, fontsize=general_font_size)
    plt.yticks(fontsize=general_font_size)
    plt.tight_layout()
    plt.show()

    # Figure for attack distribution with log scale
    plt.figure(figsize=(12, 8))
    sns.barplot(x=list(attack_data.keys()), y=list(attack_data.values()))
    plt.yscale("log")
    plt.title("Attack Distribution (Log Scale)", fontsize=general_font_size)
    plt.xlabel("Attack", fontsize=general_font_size)
    plt.ylabel("Count (Log Scale)", fontsize=general_font_size)
    plt.xticks(rotation=45, fontsize=general_font_size)
    plt.yticks(fontsize=general_font_size)
    plt.tight_layout()
    plt.show()

    # Figure for container distribution with log scale
    plt.figure(figsize=(12, 8))
    sns.barplot(x=list(container_data.keys()), y=list(container_data.values()))
    plt.yscale("log")
    plt.title("Container Distribution (Log Scale)", fontsize=general_font_size)
    plt.xlabel("Container", fontsize=general_font_size)
    plt.ylabel("Count (Log Scale)", fontsize=general_font_size)
    plt.xticks(rotation=90, fontsize=general_font_size)
    plt.yticks(fontsize=general_font_size)
    plt.tight_layout()
    plt.show()

    # Figure for image distribution with log scale and smaller font size
    plt.figure(figsize=(12, 8))
    sns.barplot(x=list(image_data.keys()), y=list(image_data.values()))
    plt.yscale("log")
    plt.title("Image Distribution (Log Scale)", fontsize=general_font_size)
    plt.xlabel("Image", fontsize=specific_font_size)
    plt.ylabel("Count (Log Scale)", fontsize=specific_font_size)
    plt.xticks(rotation=90, fontsize=specific_font_size)
    plt.yticks(fontsize=specific_font_size)
    plt.tight_layout()
    plt.show()

    # Figure for hostname distribution with log scale and smaller font size
    plt.figure(figsize=(12, 8))
    sns.barplot(x=list(hostname_data.keys()), y=list(hostname_data.values()))
    plt.yscale("log")
    plt.title("Hostname Distribution (Log Scale)", fontsize=general_font_size)
    plt.xlabel("Hostname", fontsize=specific_font_size)
    plt.ylabel("Count (Log Scale)", fontsize=specific_font_size)
    plt.xticks(rotation=90, fontsize=specific_font_size)
    plt.yticks(fontsize=specific_font_size)
    plt.tight_layout()
    plt.show()


def main():
    accessKey = os.environ.get("PC_IDENTITY")
    accessSecret = os.environ.get("PC_SECRET")
    responseCode, cwpToken = generateCwpToken(accessKey, accessSecret)
    logging.info(responseCode)
    responseCode, content = getINCS(cwpToken)
    logging.info(responseCode)
    jsonContent = parseString(content)

    j = json.loads(jsonContent)
    result = count_unique_values(j)
    visualize_data(result)


if __name__ == "__main__":
    main()
