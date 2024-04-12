# pylint: disable=missing-docstring
import time
import requests


def output_discord_webhook(webhook, data): # TODO: Find a way to unify this function across all webhooks and only tentatively use headers used by Discord
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
