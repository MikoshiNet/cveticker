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
from modules.nist.source import fetch_nist_api_cves_since, fetch_nist_html_cve

webhook_list = [
    "https://discord.com/api/webhooks/1227621566720901182/JSWUSb4g68MNTbZATl00yrRH8pEtcaadKHURoVSEzqPAQEobaQjFzCKjpn2TcYHtIS3R" # pylint: disable=line-too-long
]


MESSAGE_USERNAME = "cveticker"
CVSS_SCORE_FILTER = 6


class ExternalAnalysisNotProvidedException(Exception):
    pass


def parse_nist_html(html, cve):
    soup = BeautifulSoup(html, "html.parser")
    cvss_score_text = soup.find("a", {"data-testid": "vuln-cvss3-cna-panel-score"}).text
    if cvss_score_text:
        pattern = r"\b\d+\.\d+\b"
        match = re.search(pattern, cvss_score_text)
        if match:
            cvss_score = match.group()
            log_info(f"Successfully matched: {cvss_score} in {cvss_score_text}Available at {f'https://nvd.nist.gov/vuln/detail/{cve}'}")
            return cvss_score
        else:
            log_error(f"Failed to find a match on {cvss_score_text} with pattern {pattern}")
    if cvss_score:
        return cvss_score
    else:
        raise ExternalAnalysisNotProvidedException


def get_nist_html_cve_cvss_of(cve):
    return parse_nist_html(fetch_nist_html_cve(cve), cve)


def parse_nist_api_response(nist_response:dict):
    data = {}
    for vulnerability in nist_response["vulnerabilities"]:
        try:
            cvss_score = vulnerability['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
        except KeyError as err:
            missing_key = err.args[0]
            if missing_key == 'cvssMetricV31':
                log_info(f"Missing 'cvssMetricV31' in vulnerability: {vulnerability['cve']['id']}")
                try:
                    cvss_score = get_nist_html_cve_cvss_of(cve=vulnerability["cve"]["id"])
                except ExternalAnalysisNotProvidedException:
                    cvss_score = "Not Available"

        data[vulnerability["cve"]["id"]] = {
            "cvss_score": cvss_score,
            "released_date": vulnerability['cve']['published'],
            "modified_date": vulnerability['cve']['lastModified'],
            "status": vulnerability["cve"]["vulnStatus"],
            "tags": []
        }
    return data


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
                        "description" : f"Base Score: {cvss_score}\nBase Severity: {db_data['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']}\nUser Interaction: {db_data['metrics']['cvssMetricV31'][0]['cvssData']['userInteraction']}\nPrivileges Required: {db_data['metrics']['cvssMetricV31'][0]['cvssData']['privilegesRequired']}\nAttack Vector: {db_data['metrics']['cvssMetricV31'][0]['cvssData']['attackVector']}\n\n{db_data['descriptions'][0]['value']}\n\nReferences: {db_data['references'][0]['url']}\n\n{db_data['published'][:-13]}",
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
                "description" : f"Base Score: \"AWAITING ANALYSIS\"\n{db_data['descriptions'][0]['value']}\n\nReferences: {db_data['references'][0]['url']}\n\n{db_data['published'][:-13]}",
                "title" : db_data['id']
            }
        ]
    }


def get_new_cves():
    current_data:dict = load_db()
    current_timestamp = datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
    last_timestamp = get_last_query_timestamp(current_data)

    data_waiting_for_comparison = parse_nist_api_response(fetch_nist_api_cves_since(last_timestamp, current_timestamp))
    new_cves = {cve: data for cve, data in data_waiting_for_comparison.items() if cve not in current_data}

    current_data.update(new_cves)
    return new_cves
