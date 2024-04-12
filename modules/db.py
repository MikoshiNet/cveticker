"""Provides interface functions for DB"""
from modules.file_handler import get_file_json_content, set_file_json_content

from modules.rss.data import Data
from modules.logger import log_critical, log_info


class Database:
    def __init__(self, file):
        self.load(file)

    def load(self, file):
        try:
            self.db = get_file_json_content(file)
        except FileNotFoundError as e:
            log_critical(f"File was not found: {file}\nError: {e}")

    def save(self, value:dict):
        set_file_json_content

    def get_all_data(self) -> set[Data]:
        pass

    def get_data(self, key):
        pass