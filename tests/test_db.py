import pytest
from pymongo import MongoClient

from modules.db import Database
from modules.data import Dataset, Data


@pytest.fixture
def mock_database():
    return Database(user="testuser", password="testpass", database="test", collection="data")


def test_database(mock_database):    
    print(mock_database.get_database())
    assert mock_database is not None
