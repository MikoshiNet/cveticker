# pylint: disable=missing-docstring
from datetime import datetime, UTC, timedelta

from pprint import pprint

from modules.nist.source import fetch_nist_api_cves_since, fetch_nist_api_cve

def iwantcve():
    pprint(fetch_nist_api_cve('CVE-2024-32472'))

def iwantcvesince():
    current_time = datetime.now(UTC)
    current_timestamp = current_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
    last_timestamp = (current_time - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
    pprint(fetch_nist_api_cves_since(last_timestamp, current_timestamp))

def main():
    iwantcve()

if __name__ == "__main__":
    main()
