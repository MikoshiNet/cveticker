# pylint: disable=missing-docstring
"""Provides interface functions for DB"""
import json
from datetime import datetime, timedelta

from modules.file_handler import get_file_json_content


from modules.logger import log_critical


def load_db() -> dict:
    return get_file_json_content("database_file.json")
    # TODO: Handle error if file doesnt exist or is empty and return either None or {}

def populate_db(data:dict) -> None:
    with open("database_file.json", "w", encoding='utf-8') as write_file:
        json.dump(data, write_file)


def get_last_query_timestamp(loaded_db:dict):
    try:
        return loaded_db['timestamp']
    except KeyError:
        return (datetime.utcnow() - timedelta(hours=48)).isoformat() # FIXME
