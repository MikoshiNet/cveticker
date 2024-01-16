"""Provides interface functions for DB"""
from pymongo import MongoClient
import json
import os

from modules.data import Data
from modules.logger import log_critical, log_info

data_schema = {
    "bsonType": "object",
    "required": ["post", "content"],
    "properties": {
        "post": {
            "bsonType": "string",
            "minLength": 64,
            "maxLength": 64,
            "description": "must be a string of 64 characters (SHA-256 hash)"
        },
        "content": {
            "bsonType": "string",
            "description": "must be a string"
        },
        "mentioned_cves": {
            "bsonType": "array",
            "items": {
                "bsonType": "string"
            },
            "description": "optional array of strings"
        },
        "cve": {
            "bsonType": "string",
            "description": "optional string"
        }
    }
}

class Database:
    def __init__(self, database:str=None, address:str=None, user:str=None, password:str=None, collection:str=None):
        self.address = address if address else "127.0.0.1"
        self.user = user if user else "app"
        self.collection = collection if collection else "data"
        self.connection_string = f"mongodb://{self.user}:{password}@{self.address}/{database}"

        self.client:MongoClient = MongoClient(self.connection_string)
        self.database = self.client.get_database(database)
        self.ensure_collection_schema(self.collection, data_schema)

    def ensure_collection_schema(self, collection_name, desired_schema):
        try:
            current_validation = self.database.command('listCollections', filter={'name': collection_name})
            current_schema = current_validation['cursor']['firstBatch'][0].get('options', {}).get('validator', {})
        except (IndexError, KeyError):
            current_schema = {}
        if current_schema != desired_schema:
            try:
                self.database.command("collMod", collection_name, validator=desired_schema)
                print(f"Schema updated for collection '{collection_name}'.")
            except Exception as e:
                print(f"Error updating schema: {e}")
        else:
            print(f"Collection '{collection_name}' already has the desired schema.")


    def get_database(self):
        return self.client['web_data']

    def insert_data(self, data:Data):
        dic:dict = {}
        dic["post"] = data.post
        dic["content"] = data.content
        dic["mentioned_cves"] = data.mentioned_cves
        dic["cve"] = data.cve
      
        collection = self.database[self.collection]
        result = collection.insert_one({"post": data.post, "content": data.content, "mentioned_cves": data.mentioned_cves, "cve": data.cve})
        return result.inserted_id

    def get_all_data(self) -> set[Data]:
        """
        Returns:
            set[Data]: returns a set of custom Data objects
        """
        collection = self.database[self.collection]
        documents = list(collection.find({}))
        return {Data(document["post"], document["content"], document["mentioned_cves"], document["cve"], is_hash=True) for document in documents}

    def get_data(self, key):
        collection = self.database[self.collection]
        document = collection.find_one({"post": key})
        return Data(document["post"], document["content"], document["mentioned_cves"], document["cve"], is_hash=True)
