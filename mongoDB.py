import pymongo
from pymongo import MongoClient
import urllib

"""
For disk stoage which is synced with other nodes in network, an atlas mongo database will be used to simulate as suggested.
>pip install pymongo

The Mongo Database account:
User email: group.hccw@gmail.com
User Password: ****(Ask me in the wts group)

The admin user account of this Mongo Database:
User Name: dbAdmin
User Password: ****(Ask me in the wts group)

Reference List:
[1] https://www.youtube.com/watch?v=rE_bJl2GAY8
[2] https://www.youtube.com/watch?v=nYNAH8K_UhI
"""

try:
    dbAdmin_password = "@bcdef123456"
    # may convert to localhost database later, the main idea to to simulate a synced local disk
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
    collection_transactionPool.insert_one(transactionsData)

# Remove Data - Transactions
def remove_from_transationPool(transation):
    collection_transactionPool = database["transactionPool"] # access to the "transactionPool" collection on mongodb
    collection_transactionPool.delete_one(transation)

# Get Data - Lastest block
def get_latestblock_fromDB():
    collection_RawData = database["rawdata"] # access to the "rawdata" collection on mongodb
    return(collection_RawData.find_one({},sort=[( '_id', pymongo.DESCENDING )]))

# Check Data - If block exist
def check_blockExist(blockIndex):
    collection_RawData = database["rawdata"] # access to the "rawdata" collection on mongodb
    if collection_RawData.count_documents({ "index": blockIndex }):
        return(True)
    return(False)

# Count Data
def count_rawdata():
    collection_RawData = database["rawdata"]
    return(collection_RawData.count_documents({}))
def count_transactionPool():
    collection_transactionPool = database["transactionPool"]
    return(collection_transactionPool.count_documents({}))

# Find Data
def find_document(label, value, collection):
    collection_RawData = database[collection] # access to the collection on mongodb
    return(collection_RawData.find_one({label:value}))

# Delete all document
def reset_data():
    collection_RawData = database["rawdata"]
    collection_transactionPool = database["transactionPool"]
    collection_RawData.delete_many({})
    collection_transactionPool.delete_many({})
# Examples of inserting new data to collections

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
        "required": [ "txID", "txIndex", "address", "signature", "amount"],
        "properties": {
            "txID": {
                "bsonType": "string",
                "description": "txID must be a string and it is required"
            },
            "txIndex": {
                "bsonType": "int",
                "description": "txIndex must be an integer and it is required"
            },
            "address": {
                "bsonType": "string",
                "description": "address must be a string and it is required"
            },
            "signature": {
                "bsonType": "string",
                "description": "signature must be a string and it is required"
            },
            "amount": {
                "bsonType": "int",
                "description": "amount must be an integer and it is required"
            },
        }
    }
}

if __name__ == "__main__":
    database.command("collMod", "rawdata", validator=rawData_validator)
    database.command("collMod", "transactionPool", validator=transactionPool_validator)
    #reset_data()