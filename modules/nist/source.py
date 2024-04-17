# pylint: disable=missing-docstring
import requests

def fetch_nist_html_cve(cve):
    response = requests.get(f"https://nvd.nist.gov/vuln/detail/{cve}", timeout=10)
    return response.text


def fetch_nist_api_cves_since(last_timestamp:str, current_timestamp:str,) -> dict: # This handles solely HTTP request and returns content
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0/'
    params = {
        'pubStartDate': last_timestamp,
        'pubEndDate': current_timestamp
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

def fetch_nist_api_cve(cve):
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0/?cveId={cve}'

    response = requests.get(url, timeout=10)

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err)
        if response.status_code == 204:
            pass # TODO: Try again after X seconds
        return None # FIXME
    return response.json()
