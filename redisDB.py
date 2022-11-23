import redis
from redis import StrictRedis, ConnectionPool
import pickle
from LatestState import LatestState

"""
For memory storage, a localhost redis database will be used as suggested.
>pip install redis

redis for windows:
https://github.com/microsoftarchive/redis/releases?page=1

reference:
https://stackoverflow.com/questions/15219858/how-to-store-a-complex-object-in-redis-using-redis-py
"""

try:
    pool = ConnectionPool(host='localhost', port=6379, db=0)
    redis = StrictRedis(connection_pool=pool)
except Exception:
    print("Connection Error: " + Exception)

def redisPush(latest_state):
    pickled_object = pickle.dumps(latest_state)
    redis.set(latest_state.height, pickled_object)

def redisGet(key):
    unpacked_object = pickle.loads(redis.get(key))
    return(unpacked_object)