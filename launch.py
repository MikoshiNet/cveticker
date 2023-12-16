# pylint: disable=missing-docstring, expression-not-assigned
import asyncio
import aiohttp

from modules.file_handler import get_file_json_content, set_file_json_content
from modules.source import fetch_and_process_feed
from modules.data import Dataset, Data
from modules.db import Database

class Config:
    def __init__(self) -> None:    
        try:
            self.urls = get_file_json_content("urls.json")
        except FileNotFoundError:
            print("urls.json missing")

async def main():
    config = Config()
    db_config:dict = get_file_json_content("config/db.json")
    db:Database = Database(
        user=db_config["user"],
        password=db_config["password"],
        database=db_config["database"],
        address=db_config["address"],
        collection=db_config["collection"]
        )

    dataset:Dataset = Dataset(db.get_all_data())

    async with aiohttp.ClientSession() as session:
        tasks = [asyncio.create_task(fetch_and_process_feed(session, url, dataset)) for url in config.urls]
        await asyncio.gather(*tasks)
    
    [db.insert_data(data) for data in dataset]

if __name__ == "__main__":
    asyncio.run(main())
