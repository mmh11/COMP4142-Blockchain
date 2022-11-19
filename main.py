import hashlib
import json
import time
import rsa
import math

from hashlib import sha256
from mongoDB import insert_collection_RawData
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

  def __str__(self):
    return str(self.__class__) + ": " + str(self.__dict__)


class Block:

  def __init__(self, index, difficulty, previous_hash=''):
    self.index = 0
    self.timestamp = int(time.time())
    self.nonce = 0
    self.difficulty = difficulty
    self.merkle_root = ''
    self.previous_hash = previous_hash
    self.current_hash = ''
    self.time_consumed = 0
    self.transaction = []

  def __str__(self):
    return str(self.__class__) + ": " + str(self.__dict__)

  def hash_sha256(self):
    hash_data = str(self.index) + str(self.timestamp) + str(self.nonce) + str(
      self.difficulty) + self.merkle_root + self.previous_hash
    return sha256(hash_data.encode()).hexdigest()


class Blockchain:

  BITCOIN_ONE_BLOCK_MILLISECONDS = 600

  def __init__(self):
    self.chain = []
    self.adjust_difficulty_blocks = 10
    self.difficulty = 3
    self.block_time = 30
    self.mining_rewards = 10
    self.block_limitation = 32
    self.pending_transactions = []
    self.mine_address = []

  def __str__(self):
    return str(self.__class__) + ": " + str(self.__dict__)

  def create_genesis_block(self):
    genesis = Block(self.difficulty, ["COMP4142 Group Project"])
    genesis.current_hash = genesis.hash_sha256()
    self.chain.append(genesis)

  def add_transaction_to_block(self, block):
    if len(self.pending_transactions) > self.block_limitation:
      transcation_accepted = self.pending_transactions[:self.block_limitation]
      self.pending_transactions = self.pending_transactions[self.block_limitation:]
    else:
      transcation_accepted = self.pending_transactions
      self.pending_transactions = []
    block.transaction = transcation_accepted

  def lastest_block(self):
    return (self.latest_nth_block(1))

  def latest_nth_block(self, nth: int):
    return (self.chain[len(self.chain) - nth])

  def pow_mine(self, address):
    start = time.process_time()
    last_block = self.lastest_block()
    new_block = Block(last_block.current_hash, self.difficulty)

    self.add_transaction_to_block(new_block)
    new_block.index = last_block.index + 1
    new_block.previous_hash = last_block.current_hash
    new_block.difficulty = self.difficulty
    # new_block.merkle_root =
    new_block.current_hash = new_block.hash_sha256()
    while new_block.current_hash[0:self.difficulty] != '0' * self.difficulty:
      new_block.nonce += 1
      new_block.current_hash = new_block.hash_sha256()


    new_block.time_consumed = time.process_time() - start # adjust to milliseconds
    print(
      f"Hash found: {new_block.current_hash} @ difficulty {self.difficulty}, time cost: {new_block.time_consumed}s"
    )
    self.add_mine_reward(address)
    self.chain.append(new_block)
    self.adjust_current_block_difficulty()

  def add_mine_reward(self, address):
    mine = Transaction('', address, self.mining_rewards)
    self.pending_transactions.append(mine)

  def adjust_current_block_difficulty(self):

    if len(self.chain) % self.adjust_difficulty_blocks != 1:
      return self.difficulty
    elif len(self.chain) <= self.adjust_difficulty_blocks:
      return self.difficulty
    else:

      total_consume_time = 0
      for i in range(self.adjust_difficulty_blocks):
        total_consume_time += self.chain[-1 * i - 1].time_consumed

      if total_consume_time > 0:
        average_time_consumed = (total_consume_time / self.adjust_difficulty_blocks)
      else:
        average_time_consumed = 0
      
      print(f"Average block time:{average_time_consumed}s.")
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

  def get_balance(self, address):
    balance = 0
    for block in self.chain:
      for tran in block.transaction:
        if tran.sender == address:
          balance -= tran.amounts

        if tran.receiver == address:
          balance += tran.amounts

    return balance

  def generate_address(self):
    public, private = rsa.newkeys(1024)
    public_key_address = str(public.save_pkcs1())
    public_key_address = public_key_address.replace("\\n", '')
    public_key_address = public_key_address.replace(
      "b'-----BEGIN RSA PUBLIC KEY-----", '')
    public_key_address = public_key_address.replace(
      "-----END RSA PUBLIC KEY-----'", '')
    private_key = private.save_pkcs1()

    return public_key_address, private_key

  def build_transaction(self, sender, receiver, amount):
    if self.get_balance(sender) < amount:
      return False

    else:
      tran = Transaction(sender, receiver, amount)
      return tran

  def transaction_to_string(self, transaction):
    tran = {
      'sender': str(transaction.sender),
      'receiver': str(transaction.receiver),
      'amounts': transaction.amounts,
    }
    return str(tran)

  def get_transactions_string(self, block):
    transaction = ''
    for tran in block.transactions:
      transaction += self.transaction_to_string(tran)
    return transaction

  def sign_transaction(self, transaction, private):
    private_key = rsa.PrivateKey.load_pkcs1(private)
    tran = self.transaction_to_string(transaction)
    sign = rsa.sign(tran.encode('utf-8'), private_key, 'SHA-256')
    return sign

  def add_transaction(self, transaction, signature):
    public = '-----BEGIN RSA PUBLIC KEY-----\n'
    public += transaction.sender
    public += '\n-----END RSA PUBLIC KEY-----\n'
    public_key = rsa.PublicKey.load_pkcs1(public.encode('utf-8'))
    tran = self.transaction_to_string(transaction)
    if transaction.amounts > self.get_balance(transaction.sender):
      return False
    try:
      rsa.verify(tran.encode('utf-8'), signature, public_key)
      self.pending_transactions.append(transaction)
      return True
    except Exception:
      print("Signature not verified!")


if __name__ == "__main__":
  b = Blockchain()
  b.create_genesis_block()
  address, private = b.generate_address()
  b.pow_mine(address)
  b.pow_mine('123')
  for i in range(30):
    b.pow_mine('123')
  print("Before")
  print("address balance: " + str(b.get_balance(address)))
  print("test balance: " + str(b.get_balance('test')))
  tran = b.build_transaction(address, 'test', 5)
  if tran:
    sign = b.sign_transaction(tran, private)
    b.add_transaction(tran, sign)
  b.pow_mine('123')
  print("After")
  print("address balance: " + str(b.get_balance(address)))
  print("test balance: " + str(b.get_balance('test')))
