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
    collection_RawData = database["rawdata"] # access to the "rawdata" collection on mongodb
    return(collection_RawData.count_documents({}))

# Find Data
def find_document(label, value, collection):
    collection_RawData = database[collection] # access to the collection on mongodb
    return(collection_RawData.find_one({label:value}))

# Delete all document in rawdata
def reset_rawdata():
    collection_RawData = database["rawdata"] # access to the collection on mongodb
    collection_RawData.delete_many({})
# Examples of inserting new data to collections
"""
insert_collection_RawData([{
    "index":0, 
    "timestamp":123141, 
    "previous_hash":"0000000000078YEW78RHW8EHFWEFHWEUS", 
    "current_hash":"0000000000078YEW78RHW8EHFWEFHWEUS", 
    "difficulty":3, 
    "nonce":1, 
    "transaction":["000982J9R3F2EWSNEWIEU3WIDNJWOGBS0DFSJEO3446","0000000000078YEW78RHW8EHFWEFHWEUS"], 
    "merkle_root":"0000000000078YEW78RHW8EHFWEFHWEUS"
}])

insert_collection_transactionPool([{
    "sender":"Martin", 
    "recipient":"Martin No.2", 
    "amount":"0.5", 
    "txid":"000982J9R3F2EWSNEWIEU3WIDNJWOGBS0DFSJEO3446", 
    "previous_hash":"0000000000078YEW78RHW8EHFWEFHWEUS",
}])
"""

# Scheme for the "rawdata" collection
rawData_validator = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": [ "index", "timestamp", "current_hash", "difficulty", "nonce"],
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
                "description": "previous_hash must be a string"
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
                "description": "transaction must be an array"
            },
            "merkle_root": {
                "bsonType": "string",
                "description": "merkle_root must be a string"
            },
        }
    }
}

# Scheme for the "transactionPool" collection
transactionPool_validator = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": [ "txID", "txIndex", "address", "amount"],
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
                "description": "signature must be a string"
            },
            "amount": {
                "bsonType": "string",
                "description": "amount must be a string and it is required"
            },
        }
    }
}

if __name__ == "__main__":
    database.command("collMod", "rawdata", validator=rawData_validator)
    database.command("collMod", "transactionPool", validator=transactionPool_validator)
    # reset_rawdata()