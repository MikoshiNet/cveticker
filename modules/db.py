"""Provides interface functions for DB"""
from pymongo import MongoClient
import json

from modules.data import Data

data_schema = {
    "bsonType": "object",
    "required": ["post", "content", "mentioned_cves"],
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
            "description": "must be an array of strings"
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
       # Retrieve current collection info
       current_info = self.database.command('listCollections', filter={'name': collection_name})
       current_validation = current_info['cursor']['firstBatch'][0].get('options', {}).get('validator', {})

       # Convert the desired schema to a format that can be compared
       desired_validation = {'$jsonSchema': desired_schema}

       # Check if the current validation rules match the desired schema
       if json.dumps(current_validation) != json.dumps(desired_validation):
           # Update the collection with the new schema
           self.database.command('collMod', collection_name, validator=desired_validation)
           print(f"Schema updated for collection '{collection_name}'.")
       else:
           print(f"Collection '{collection_name}' already has the desired schema.")


    def get_database(self):
        return self.client['web_data']

    def insert_data(self, data:Data):
        dic:dict = {}
        dic["post"] = data.post
        dic["content"] = data.content
        dic["cve"] = data.cve
        dic["mentioned_cves"] = data.mentioned_cves
      
        collection = self.database.web_data
        result = collection.insert_one(dic)
        return result.inserted_id

    def get_all_data(self):
        collection = self.database[self.collection]
        documents = list(collection.find({}))
        return documents

    def get_data(self, key):
        collection = self.database[self.collection]
        documents = list(collection.find_one({"post": key}))
        return documents
