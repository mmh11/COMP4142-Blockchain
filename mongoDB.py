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
"""

try:
    cluster = MongoClient("mongodb+srv://dbAdmin:" + urllib.parse.quote("@bcdef123456") + "@atlascluster.g7wziyq.mongodb.net/?retryWrites=true&w=majority")
    database = cluster["COMP4142-BLOCKCHAIN"] # cluster the name of the database on mongodb
except Exception:
    print("Connection Error: " + Exception)

# Storage - Raw Data
collection_RawData = database["rawdata"] # access to the "rawdata" collection on mongodb

def insert_collection_RawData(rawdata):
    collection_RawData.insert_many(rawdata)