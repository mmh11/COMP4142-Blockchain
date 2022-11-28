# COMP4142-Blockchain
COMP4142 Group Project

redis must be downloaded and the redis server must be setup before testing any code, or you can just command all code in redisDB.py and function redisPush() in main.py
Steps:
1. Open redis-server.exe with default port 6379
2. Open redis-cli.exe to interact with redis
3. Type "ping" in redis-cli.exe, and wait for the response "pong", to test the connection with the redis server


How to test multiple user networking interaction:
1. Open a Terminal (Terminal 1)
2. input Terminal 1 with command:
    .\main.py 1111
3. Open another Terminal (Terminal 2)
4. input Terminal 3 with command:
    .\main.py 9999 127.0.0.1:1111
5. observing result
