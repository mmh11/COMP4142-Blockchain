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

class Transaction:
    def __init__(self, sender, receiver, amounts):
        self.sender = sender
        self.receiver = receiver
        self.amounts = amounts

class Block:

  def __init__(self,
               difficulty,
               previous_hash=''):
    self.index = 0
    self.timestamp = int(time.time())
    self.nonce = 0
    self.difficulty = difficulty
    self.merkle_root = ''
    self.previous_hash = previous_hash
    self.current_hash = self.hash_sha256()
    self.transaction = []

  def __str__(self):
    return str(self.__class__) + ": " + str(self.__dict__)

  def hash_sha256(self):
    hash_data = json.dumps(self.__dict__)
    return sha256(hash_data.encode()).hexdigest()


class Blockchain:

  def __init__(self):
    self.chain = []
    self.adjust_difficulty_blocks = 20
    self.difficulty = 1
    self.block_time = 30
    self.mining_rewards = 10
    self.block_limitation = 32
    self.pending_transactions = []

  def __str__(self):
    return str(self.__class__) + ": " + str(self.__dict__)

  def create_genesis_block(self):
    genesis = Block(self.difficulty, ["COMP4142 Group Project"])
    #hash genesis?
    self.chain.append(genesis)

  def hash_sha256(self):
    hash_data = json.dumps(self.__dict__)
    return sha256(hash_data.encode()).hexdigest()
  
  def transaction_to_string(self, transaction):
        transaction_dict = {
            'sender': str(transaction.sender),
            'receiver': str(transaction.receiver),
            'amounts': transaction.amounts,
        }
        return str(transaction_dict)

  def get_transactions_string(self, block):
        transaction_str = ''
        for transaction in block.transactions:
            transaction_str += self.transaction_to_string(transaction)
        return transaction_str

  def add_transaction_to_block(self, block):
        if len(self.pending_transactions) > self.block_limitation:
            transcation_accepted = self.pending_transactions[:self.block_limitation]
            self.pending_transactions = self.pending_transactions[self.block_limitation:]
        else:
            transcation_accepted = self.pending_transactions
            self.pending_transactions = []
        block.transactions = transcation_accepted
  
  def lastest_block(self):
    return (self.latest_nth_block(1))

  def latest_nth_block(self, nth: int):
    return (self.chain[len(self.chain) - nth])

  def mine_block(self):
        start = time.process_time()
        last_block = self.lastest_block()
        new_block = Block(last_block.current_hash, self.difficulty)

        self.add_transaction_to_block(new_block)
        new_block.index = last_block.index + 1
        new_block.previous_hash = last_block.current_hash
        new_block.difficulty = self.difficulty
        new_block.current_hash = new_block.hash_sha256()
        while new_block.current_hash[0: self.difficulty] != '0' * self.difficulty:
            new_block.nonce += 1
            new_block.current_hash = new_block.hash_sha256()
            
            

        time_consumed = round(time.process_time() - start, 5)
        print(f"Hash found: {new_block.current_hash} @ difficulty {self.difficulty}, time cost: {time_consumed}s")
        self.chain.append(new_block)

  
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
    return (block_hash.startswith('0' * block.difficulty)
            and block_hash == block.hash_sha256())

  def adjust_current_block_difficulty(self):
    if len(self.chain) % self.adjust_difficulty_blocks != 1:
      return self.difficulty
    elif len(self.chain) <= self.adjust_difficulty_blocks:
      return self.difficulty
    else:
      start = self.chain[-1 * self.adjust_difficulty_blocks - 1].timestamp
      finish = self.chain[-1].timestamp
      average_time_consumed = round(
        (finish - start) / (self.adjust_difficulty_blocks), 2)

      if average_time_consumed > self.block_time:
        print(
          f"Average block time:{average_time_consumed}s. Lower the difficulty")
        self.difficulty -= 1
      else:
        print(
          f"Average block time:{average_time_consumed}s. High up the difficulty"
        )
        self.difficulty += 1

      return self.difficulty


if __name__ == "__main__":
  b = Blockchain()
  b.create_genesis_block()
  b.mine_block()
  print(b.chain[1])
