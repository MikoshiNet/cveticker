# pylint: disable=missing-docstring

#This product uses the NVD API but is not endorsed or certified by the NVD.
#Sample Time: "2024-03-29T01:26:11-07:00.999" # "2024-04-04T06:37:27.140"

from datetime import datetime, UTC
import time
import re

import requests
from bs4 import BeautifulSoup

from modules.config import Config
from modules.output.webhook import output_discord_webhook
from modules.db import load_db, populate_db, get_last_query_timestamp

from modules.logger import log_critical, log_error, log_info, log_debug # pylint: disable=unused-import


webhook_list = [
    "https://discord.com/api/webhooks/1227621566720901182/JSWUSb4g68MNTbZATl00yrRH8pEtcaadKHURoVSEzqPAQEobaQjFzCKjpn2TcYHtIS3R" # pylint: disable=line-too-long
]


MESSAGE_USERNAME = "cveticker"
CVSS_SCORE_FILTER = 6

def parse_nist_html(html, cve):
    soup = BeautifulSoup(html, "html.parser")
    cvss_score_text = soup.find("a", {"data-testid": "vuln-cvss3-cna-panel-score"}).text
    if cvss_score_text:
        pattern = r"\b\d+\.\d+\b"
        match = re.search(pattern, cvss_score_text)
        if match:
            cvss_score = match.group()
            log_info(f"Successfully matched: {cvss_score} in {cvss_score_text} available at {f'https://nvd.nist.gov/vuln/detail/{cve}'}")
            return cvss_score
        else:
            log_error(f"Failed to find a match on {cvss_score_text} with pattern {pattern}")
    return cvss_score if cvss_score else None



def fetch_nist_html_cve(cve):
    response = requests.get(f"https://nvd.nist.gov/vuln/detail/{cve}", timeout=10)

    return response.text

def get_nist_html_cve_cvss_of(cve):
    return parse_nist_html(fetch_nist_html_cve(cve), cve)

def fetch_nist_api_cves_since(last_date:str, current_date:str) -> dict:
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0/'
    params = {
        'pubStartDate': last_date,
        'pubEndDate': current_date
    }

    response = requests.get(url, params=params, timeout=10)

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err)
        if response.status_code == 204:
            pass # TODO: Try again after X seconds
        return None # FIXME
    return response.json()

def get_nist_api_cves():
    last_tracked_timestamp = ""
    current_timestamp = datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
    fetch_nist_api_cves_since(last_tracked_timestamp, current_timestamp)


waiting_list = [] # This needs to be stored somewhere not in memory

def get_content_for_output(db_data:dict, index:int, message_content="") -> None:
    log_debug(f"len(db_data['vulnerabilities']) == {len(db_data['vulnerabilities'])}")
    db_data = db_data['vulnerabilities'][index]['cve']
    cvss_score = None
    try:
        cvss_score = db_data['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']

    except KeyError as err:
        missing_key = err.args[0]
        if missing_key == 'cvssMetricV31':
            log_info(f"Missing 'cvssMetricV31' in db_data: {db_data}")
            waiting_list.append(db_data['id'])
        else:
            log_critical(f"db_data: {db_data}\nError Message: {err}")


    if cvss_score is not None:
        if cvss_score >= CVSS_SCORE_FILTER:
            return {
                "content" : message_content,
                "username" : MESSAGE_USERNAME,
                "embeds": [
                    {
                        "description" : f"Base Score: {cvss_score}\nBase Severity: {db_data['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']}\nUser Interaction: {db_data['metrics']['cvssMetricV31'][0]['cvssData']['userInteraction']}\nPrivileges Required: {db_data['metrics']['cvssMetricV31'][0]['cvssData']['privilegesRequired']}\nAttack Vector: {db_data['metrics']['cvssMetricV31'][0]['cvssData']['attackVector']}\n\n{db_data['descriptions'][0]['value']}\n\nReferences: {db_data['references'][0]['url']}\n\n{db_data['published'][:-13]}", # pylint: disable=line-too-long
                        "title" : db_data['id']
                    }
                ]
            }
        log_info("CVSS Score lower than Filter")
        return None
    # CVSS Score is None
    return {
        "content" : message_content,
        "username" : MESSAGE_USERNAME,
        "embeds": [
            {
                "description" : f"Base Score: \"AWAITING ANALYSIS\"\n{db_data['descriptions'][0]['value']}\n\nReferences: {db_data['references'][0]['url']}\n\n{db_data['published'][:-13]}", # pylint: disable=line-too-long
                "title" : db_data['id']
            }
        ]
    }

def get_new_cves():
    db_data = load_db()
    lastquery = get_last_query_timestamp(db_data)
    query_data = fetch_nist_api_cves_since(lastquery, date_time)



def main():
    while True:
        db_data = load_db()
        print("[*]Database has been loaded.")
        lastquery = get_last_query_timestamp(db_data)
        print(f"[*]Last query was {lastquery}")
        date_time = datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
        print(f"[*]Current Date/Time is {date_time}")
        query_data = fetch_nist_api_cves_since(lastquery, date_time)
        print("[*]Querying NIST...")
        print(query_data)


        if query_data is not None:
            log_debug(f"RANGE USED IN LOOP IS {range(query_data['totalResults'])}")
            for i in range(query_data['totalResults']):
                for webhook in webhook_list:
                    log_debug(str(i))
                    output_discord_webhook(webhook, get_content_for_output(query_data, i))
            populate_db(query_data)
        else:
            pass
        time.sleep(60 * 120)


if __name__ == "__main__":
    main()
