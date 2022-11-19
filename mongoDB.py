import pymongo
from pymongo import MongoClient
import urllib

"""
For stoage, mongo database will be used as suggested.
>pip install pymongo

The Mongo Database account:
User email: group.hccw@gmail.com
User Password: ****(Ask me in the wts group)

The admin user account of this Mongo Database:
User Name: dbAdmin
User Password: ****(Ask me in the wts group)
Additionally, IP address need to be whitelisted...

The expected data format (json-like):
{
    "index": 0
    "timestamp": 0.0
    "previous_hash": ''
    "current_hash": ''
    "difficulty": 1
    "nonce": 1
    "transaction": []
    "merkle_root": ''
}

How to insert data? Example:
testData1 = {"id":0, "name":"Martin"}
testData2 = {"id":1, "name":"Martin No Two"}
insert_collection_RawData([testData1, testData2])

Reference List:
[1] https://www.youtube.com/watch?v=rE_bJl2GAY8
[2] https://www.youtube.com/watch?v=nYNAH8K_UhI
"""

try:
    dbAdmin_password = "@bcdef123456"
    cluster = MongoClient("mongodb+srv://dbAdmin:" + urllib.parse.quote(dbAdmin_password) + "@atlascluster.g7wziyq.mongodb.net/?retryWrites=true&w=majority&authSource=admin")
    database = cluster["COMP4142-BLOCKCHAIN"] # cluster the name of the database on mongodb
except Exception:
    print("Connection Error: " + Exception)

# Storage - Raw Data
def insert_collection_RawData(rawData):
    collection_RawData = database["rawdata"] # access to the "rawdata" collection on mongodb
    collection_RawData.insert_many(rawData)

# Storage - Transactions (UTXO)
def insert_collection_transactionPool(transactionsData):
    collection_transactionPool = database["transactionPool"] # access to the "transactionPool" collection on mongodb
    collection_transactionPool.insert_many(transactionsData)

# Scheme for the "rawdata" collection
rawData_validator = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": [ "index", "timestamp", "previous_hash", "current_hash", "difficulty", "nonce", "transaction", "merkle_root"],
        "properties": {
            "index": {
                "bsonType": "int",
                "minimum": 0,
                "description": "index must be an integer and it is required"
            },
            "timestamp": {
                "bsonType": "int",
                "description": "timestamp must be an integer and it is required"
            },
            "previous_hash": {
                "bsonType": "string",
                "description": "previous_hash must be a string and it is required"
            },
            "current_hash": {
                "bsonType": "string",
                "description": "current_hash must be a string and it is required"
            },
            "difficulty": {
                "bsonType": "int",
                "description": "difficulty must be an integer and it is required"
            },
            "nonce": {
                "bsonType": "int",
                "description": "nonce must be an integer and it is required"
            },
            "transaction": {
                "bsonType": "array",
                "description": "transaction must be an array and it is required"
            },
            "merkle_root": {
                "bsonType": "string",
                "description": "merkle_root must be a string and it is required"
            },
        }
    }
}

# Scheme for the "transactionPool" collection
transactionPool_validator = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": [ "sender", "recipient", "amount", "txid", "previous_hash"],
        "properties": {
            "sender": {
                "bsonType": "string",
                "description": "sender must be a string and it is required"
            },
            "recipient": {
                "bsonType": "string",
                "description": "recipient must be a string and it is required"
            },
            "amount": {
                "bsonType": "string",
                "description": "amount must be a string and it is required"
            },
            "txid": {
                "bsonType": "string",
                "description": "txid must be a string and it is required"
            },
            "previous_hash": {
                "bsonType": "string",
                "description": "previous_hash must be a string and it is required"
            },
        }
    }
}

if __name__ == "__main__":
    database.command("collMod", "rawdata", validator=rawData_validator)
    database.command("collMod", "rawdata", validator=transactionPool_validator)