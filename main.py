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
        return(self.latest_nth_block(1))
    
    def latest_nth_block(self, nth: int):
        return(self.chain[len(self.chain)-nth])

    def proof_of_work(self, block: Block):
        block.nonce = 1
        computed_hash = block.hash_sha256()
        while not computed_hash.startswith('0' * block.difficulty):
            block.nonce += 1
            computed_hash = block.hash_sha256()
        return computed_hash

    def add_block(self, block: Block, proof):
        previous_hash = self.lastest_block().current_hash
        if previous_hash != block.previous_hash:
            return False
        if not self.is_valid_proof(block, proof):
            return False
        block.current_hash = proof
        self.chain.append(block)
        return True
 
    def is_valid_proof(self, block: Block, block_hash: str):
        return (block_hash.startswith('0' * block.difficulty) and block_hash == block.hash_sha256())
    
    def adjust_current_block_difficulty(self, block: Block, num_of_previous_block: int):
        latest_block_timestamps = []
        for loop_index in range(num_of_previous_block):
            latest_block_timestamps.append(self.latest_nth_block(loop_index).timestamp)
        current_block_timestamp = block.timestamp

        return

if __name__ == "__main__":
    Blockchain() 
    
