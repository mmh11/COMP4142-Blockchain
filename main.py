import hashlib
import json
import time

from hashlib import sha256

"""
Reference List:
[1] https://www.youtube.com/watch?v=zVqczFZr124
[2] https://www.activestate.com/blog/how-to-build-a-blockchain-in-python/
[3] 
"""

# Blockchain prototype - The basic content
class Block:
    def __init__(self, index, timestamp, transactions, nonce, difficulty, merkle_root, previous_hash = ''):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = nonce
        self.difficulty = difficulty
        self.merkle_root = merkle_root
        self.previous_hash = previous_hash
        self.current_hash = self.hash_sha256()

    def hash_sha256(self):
        hash_data = json.dumps(self.__dict__)
        return sha256(hash_data.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [self.generate_genesis_block()]
        
    def generate_genesis_block(self):
        return(Block(0, time.time(), ["COMP4142 Group Project"], 1, 5, "0", "0"))

    def lastest_block(self):
        return(self.chain[len(self.chain)-1])

    def proof_of_work():
        return
