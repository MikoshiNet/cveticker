import pytest
from mongomock import MongoClient as MockMongoClient
from hashlib import sha256
from unittest.mock import patch, MagicMock

from modules.db import Database
from modules.data import Dataset, Data

# def get_mock_database(mock_mongo_client):
#     mock_mongo_database = mock_mongo_client["dev"]
#     mock_mongo_collection = mock_mongo_database["data"]
#     return Database(mongoclient=mock_mongo_database, database="dev", collection="data")

MOCK_DOCUMENT_POST = "MOCK_POST"
MOCK_DOCUMENT_CONTENT = "MOCKING MOCKS IS MOCKING MOCKING, HENCE WE MOCK CVE-2023-36884"
MOCK_DOCUMENT_MENTIONED_CVES:list = list(["CVE-2023-36884"])
MOCK_DOCUMENT_CVE = "CVE-2023-36884"

MOCK_DATA:Data = Data(MOCK_DOCUMENT_POST, MOCK_DOCUMENT_CONTENT, MOCK_DOCUMENT_MENTIONED_CVES, MOCK_DOCUMENT_CVE)

@pytest.fixture(scope="function")
def mock_mongo_client():
    with patch('modules.db.MongoClient', new=MockMongoClient):
        mock_client = MockMongoClient()

        mock_client.get_database('testdb').command = MagicMock(return_value={'ok': 1.})
        yield

def test_database(mock_mongo_client):
    # mock_database = get_mock_database(database_client)
    
    mock_database = Database(database="testdb", address="127.0.0.1", user="testuser", password="testpass", collection="testcollection")
    
    assert mock_database is not None

    mock_database.insert_data(MOCK_DATA)
    data = mock_database.get_all_data()
    data = data[0]
    data.pop('_id')
    mencve = MOCK_DATA.mentioned_cves
    assert data["post"] == MOCK_DATA.post
    assert data["content"] == MOCK_DATA.content
    assert data["mentioned_cves"] == mencve
    assert data["cve"] == MOCK_DATA.cve
