# pylint: disable=missing-docstring,fixme

#This product uses the NVD API but is not endorsed or certified by the NVD.
#Sample Time: "2024-03-29T01:26:11-07:00.999" # "2024-04-04T06:37:27.140"

from datetime import datetime, timedelta
import time
import json
import requests

from modules.logger import log_critical, log_error, log_info, log_debug # pylint: disable=unused-import
from modules.file_handler import get_file_json_content


webhook_list = [
    "https://discord.com/api/webhooks/1227621566720901182/JSWUSb4g68MNTbZATl00yrRH8pEtcaadKHURoVSEzqPAQEobaQjFzCKjpn2TcYHtIS3R" # pylint: disable=line-too-long
]


MESSAGE_USERNAME = "cveticker"
CVSS_SCORE_FILTER = 6


def get_datetime() -> str:
    utc_now = datetime.utcnow()
    formatted_datetime = utc_now.isoformat()
    return formatted_datetime[:-3]


def get_lastquery(loaded_db:dict):
    try:
        return loaded_db['timestamp']
    except KeyError:
        return (datetime.utcnow() - timedelta(hours=48)).isoformat()


def output_discord_webhook(webhook, data):
    send_request = requests.post(webhook, json=data, timeout=10)

    try:
        send_request.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err)
    else:
        rate_limit = send_request.headers['x-ratelimit-limit']
        rate_remaining = send_request.headers['x-ratelimit-remaining']
        rate_reset = send_request.headers['x-ratelimit-reset-after']
        print(f"Rate Remaining:{rate_remaining} " +
              "| Rate Reset:{rate_reset}, | Status Code:{send_request.status_code}")
        if int(rate_remaining) < int(rate_limit)-2:
            time.sleep(int(rate_reset))


def populate_db(data:dict) -> None:
    with open("database_file.json", "w", encoding='utf-8') as write_file:
        json.dump(data, write_file)


def load_db() -> dict:
    return get_file_json_content("database_file.json")


def query_nist(last_date:str, current_date:str) -> dict:
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
        return None # FIXME: Is this the way?
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


def main():
    while True:
        db_data = load_db()
        print("[*]Database has been loaded.")
        lastquery = get_lastquery(db_data)
        print(f"[*]Last query was {lastquery}")
        date_time = get_datetime()
        print(f"[*]Current Date/Time is {date_time}")
        query_data = query_nist(lastquery, date_time)
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
