import hashlib
import json
import time

from hashlib import sha256

"""
Reference List:
[1] https://www.youtube.com/watch?v=zVqczFZr124
[2] https://www.activestate.com/blog/how-to-build-a-blockchain-in-python/
[3] https://ithelp.ithome.com.tw/users/20119982/ironman/2255?page=1 <- more comprehensive tutorial, recommend refer this pls.
"""

# Blockchain prototype - The basic content
class Block:
    def __init__(self, index, timestamp, nonce, difficulty, merkle_root, previous_hash, transactions = ''):
        self.index = index
        self.timestamp = timestamp
        self.nonce = nonce
        self.difficulty = difficulty
        self.merkle_root = merkle_root
        self.previous_hash = previous_hash
        self.current_hash = self.hash_sha256()
        self.data = transactions

    def hash_sha256(self):
        hash_data = json.dumps(self.__dict__)
        return sha256(hash_data.encode()).hexdigest()


class Blockchain:
    def __init__(self):
        self.chain = [self.generate_genesis_block()]
        self.adjust_difficulty_blocks = 20
        self.difficulty = 1
        self.block_time = 30
        self.mining_rewards = 10
        self.block_limitation = 32
        self.pending_transactions = []
        
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
    
    def adjust_current_block_difficulty(self):
        if len(self.chain) % self.adjust_difficulty_blocks != 1:
            return self.difficulty
        elif len(self.chain) <= self.adjust_difficulty_blocks:
            return self.difficulty
        else:
            start = self.chain[-1*self.adjust_difficulty_blocks-1].timestamp
            finish = self.chain[-1].timestamp
            average_time_consumed = round((finish - start) / (self.adjust_difficulty_blocks), 2)
            
            if average_time_consumed > self.block_time:
                print(f"Average block time:{average_time_consumed}s. Lower the difficulty")
                self.difficulty -= 1
            else:
                print(f"Average block time:{average_time_consumed}s. High up the difficulty")
                self.difficulty += 1
             
            return self.difficulty

if __name__ == "__main__":
    Blockchain() 
