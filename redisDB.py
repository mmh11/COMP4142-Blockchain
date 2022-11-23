import redis
from redis import StrictRedis, ConnectionPool

"""
For memory storage, a localhost redis database will be used as suggested.
>pip install redis
"""

try:
    pool = ConnectionPool(host='localhost', port=6379, db=0, password='p@ssw0rd')
    redis = StrictRedis(connection_pool=pool)
except Exception:
    print("Connection Error: " + Exception)