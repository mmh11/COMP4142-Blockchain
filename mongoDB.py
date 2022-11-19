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

Reference List:
[1] https://www.youtube.com/watch?v=rE_bJl2GAY8
"""


cluster = MongoClient("mongodb+srv://dbAdmin:" + urllib.parse.quote("@bcdef123456") + "@atlascluster.g7wziyq.mongodb.net/?retryWrites=true&w=majority")
database = cluster["COMP4142-BLOCKCHAIN"] # cluster the name of the database on mongodb


# Storage - Raw Data
collection_RawData = database["rawdata"] # access to the "rawdata" collection on mongodb
print(MongoClient.list_database_names)
