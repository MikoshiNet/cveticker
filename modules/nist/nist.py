

#This product uses the NVD API but is not endorsed or certified by the NVD.
#Sample Time: "2024-03-29T01:26:11-07:00.999" # "2024-04-04T06:37:27.140"

import requests
import time
import json
import datetime


webhook_list = [

]


MESSAGE_USERNAME = "CVE"              #username that will be displayed when the embeded message is output into the channel
content = ""                          #text that will be sent as an actual message outside the embed
CVSS_SCORE_FILTER = 6                 #Value used to compare results to, if the CVSS is higher or equal to this value, an embed will be sent



def get_datetime() -> str:
    utc_now = datetime.datetime.utcnow()
    formatted_datetime = utc_now.isoformat()
    return formatted_datetime[:-3]


def send_discord_message(webhook:str, title:str, score:str, date:str, description:str, userInteraction:str, privilegesRequired:str, baseSeverity:str, references:str, attackVector:str) -> None:
    data = {
    "content" : content,
    "username" : MESSAGE_USERNAME
    }
    data["embeds"] = [
        {
            "description" : f"Base Score: {score} \n Base Severity: {baseSeverity} \n User Interaction: {userInteraction} \n Privileges Required: {privilegesRequired} \n Attack Vector: {attackVector} \n \n {description} \n \n References: {references} \n \n {date}",
            "title" : title
        }
    ]
    send_request = requests.post(webhook, json=data)

    try:
        send_request.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err)
    else:
        rate_limit = send_request.headers['x-ratelimit-limit']
        rate_remaining = send_request.headers['x-ratelimit-remaining']
        rate_reset = send_request.headers['x-ratelimit-reset-after']

        print(f"Rate Remaining:{rate_remaining} | Rate Reset:{rate_reset}, | Status Code:{send_request.status_code}")

        if int(rate_remaining) < int(rate_limit)-2:
            time.sleep(int(rate_reset))


def populate_db(data:dict) -> None:
    with open("database_file.json", "w") as write_file:
        json.dump(data, write_file)

 
def load_db() -> dict:
    with open("database_file.json", "r") as read_file:
        return json.load(read_file)


def query_nist(last_date:str, current_date:str) -> dict:
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0/'


    params = {
        'pubStartDate': last_date,
        'pubEndDate': current_date
    }

    response = requests.get(url, params=params)

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err)
    else:
        return response.json()


def get_lastquery(loaded_db:dict):
    return loaded_db['timestamp']


def parse_send(webhook:str, db_data:dict, index:int) -> None:
    db_data = db_data['vulnerabilities'][index]['cve']
    cve_id = db_data['id']
    cve_published = db_data['published']
    cve_published = cve_published[:-13]
    cve_description = db_data['descriptions'][0]
    cve_description = cve_description['value']
    cvss_score = db_data['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
    cvss_severity = db_data['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
    cvss_privilegesRequired = db_data['metrics']['cvssMetricV31'][0]['cvssData']['privilegesRequired']
    cvss_userinteraction = db_data['metrics']['cvssMetricV31'][0]['cvssData']['userInteraction']
    cvss_attackvector = db_data['metrics']['cvssMetricV31'][0]['cvssData']['attackVector']
    references = db_data['references'][0]['url']

    if cvss_score >= CVSS_SCORE_FILTER:
        send_discord_message(
            webook,
            cve_id,
            str(cvss_score), 
            cve_published, 
            cve_description, 
            cvss_privilegesRequired, 
            cvss_userinteraction, 
            cvss_severity, 
            references, 
            cvss_attackvector
            )



if __name__ == "__main__":
            

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


        if query_data != None:
            for i in range(query_data['totalResults']):
                try:
                    for webhook in webhook_list:
                        parse_send(webhook, db_data, i)
                except:
                    pass

                else:
                    pass
            populate_db(query_data)
        else:
            pass
        time.sleep(60 * 120)

  
