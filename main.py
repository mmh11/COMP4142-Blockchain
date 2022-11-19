import hashlib
import json
import time
import rsa

from hashlib import sha256
"""
Reference List:
[1] https://www.youtube.com/watch?v=zVqczFZr124
[2] https://www.activestate.com/blog/how-to-build-a-blockchain-in-python/
[3] https://ithelp.ithome.com.tw/users/20119982/ironman/2255?page=1 <- more comprehensive tutorial, recommend refer this pls.
"""

# Blockchain prototype - The basic content


class Transaction:

  def __init__(self, type, txID, address, amounts, signature):
    self.type = type
    self.txID = txID
    self.address = address
    self.amounts = amounts
    self.signature = signature

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
    self.transaction = []

  def __str__(self):
    return str(self.__class__) + ": " + str(self.__dict__)

  def hash_sha256(self):
    hash_data = str(self.index) + str(self.timestamp) + str(self.nonce) + str(
      self.difficulty) + self.merkle_root + self.previous_hash
    return sha256(hash_data.encode()).hexdigest()

  def add_transaction(self, transaction):
    self.transaction.append(transaction)

  def cal_merkle_root(self):
    ###
    return True


class UTXO:

  def __init__(self, txID, txIndex, address, sig, amount):
    self.txID = txID
    self.txIndex = txIndex
    self.address = address
    self.signature = sig
    self.amount = amount

  def __str__(self):
    return str(self.__class__) + ": " + str(self.__dict__)

class Blockchain:

  def __init__(self):
    self.chain = []
    self.adjust_difficulty_blocks = 3
    self.difficulty = 1
    self.block_time = 30
    self.mining_rewards = 10
    self.block_limitation = 32
    self.pending_transactions = []
    self.UTXO_list = []

  def __str__(self):
    return str(self.__class__) + ": " + str(self.__dict__)

  def create_genesis_block(self):
    genesis = Block(self.difficulty, ["COMP4142 Group Project"])
    genesis.current_hash = genesis.hash_sha256()
    self.chain.append(genesis)

  def add_pending_transaction_to_block(self, block):
    ###
    if len(self.pending_transactions) > self.block_limitation:
      accpeted_tran = self.pending_transactions[:self.block_limitation]
      self.pending_transactions = self.pending_transactions[self.
                                                            block_limitation:]
    else:
      accpeted_tran = self.pending_transactions
      self.pending_transactions = []
    
    for tran in accpeted_tran:
      block.transaction.append(tran)

  def lastest_block(self):
    return (self.latest_nth_block(1))

  def latest_nth_block(self, nth: int):
    return (self.chain[len(self.chain) - nth])

  def pow_mine(self, address):
    start = time.process_time()
    last_block = self.lastest_block()
    new_block = Block(last_block.current_hash, self.difficulty)

    # add coinbase transaction
    reward_tran = Transaction("Output", "COMP4142", address, self.mining_rewards, '')
    new_block.add_transaction(reward_tran)

    # add pending transaction
    self.add_pending_transaction_to_block(new_block)

    # cal merkle root value
    new_block.cal_merkle_root()

    # mine block
    new_block.index = last_block.index + 1
    new_block.current_hash = new_block.hash_sha256()
    while new_block.current_hash[0:self.difficulty] != '0' * self.difficulty:
      new_block.nonce += 1
      new_block.current_hash = new_block.hash_sha256()

    time_consumed = round(time.process_time() - start, 5)
    print(
      f"Hash found: {new_block.current_hash} @ difficulty {self.difficulty}, time cost: {time_consumed}s"
    )
    
    # add new mined block to blockchain
    self.chain.append(new_block)
    
    # update transactions to UTXO list
    self.update_UTXO_list(new_block)
    self.adjust_current_block_difficulty()

  def cal_txID(self,block):
    id = ''
    for tran in block.transaction:
      if tran.type == "Output":
        id += str(tran.address)
      elif tran.type == "Input":
        id += str(tran.txID)
    txid = sha256(id.encode()).hexdigest()
    return txid

  def update_UTXO_list(self, block):
    # cal txID
    txid = self.cal_txID(block)

    # update UTXO 
    for tran in block.transaction:
      if tran.type == "Output":
        utxo = UTXO(txid, block.index, tran.address, tran.signature, tran.amounts)
        self.UTXO_list.append(utxo)

      elif tran.type == "Input":
        remove = []
        amount = tran.amounts
        i = 0
        while not(amount == 0):
          if self.UTXO_list[i].address == tran.address:
            if self.UTXO_list[i].amount > amount:
              self.UTXO_list[i].amount -= amount
              break
            else:
              remove.append(self.UTXO_list[i])
              amount -= self.UTXO_list[i].amount
          i += 1
              
        # delete the spent utxo
        for utxo in remove:
          self.UTXO_list.remove(utxo)
          
          
      
    #UTXO(txID, txIndex, address, sig, amount)
    
    return True

  def adjust_current_block_difficulty(self):
    if len(self.chain) % self.adjust_difficulty_blocks != 1:
      return self.difficulty
    elif len(self.chain) <= self.adjust_difficulty_blocks:
      return self.difficulty
    else:
      start = self.chain[-1 * self.adjust_difficulty_blocks - 1].timestamp
      finish = self.chain[-1].timestamp
      avg_time = round((finish - start) / (self.adjust_difficulty_blocks), 2)

      if avg_time > self.block_time:
        self.difficulty -= 1
        print(
          f"Average block time:{avg_time}s: Decrease difficulty to {self.difficulty}"
        )

      else:
        self.difficulty += 1
        print(
          f"Average block time:{avg_time}s: Increase difficulty to {self.difficulty}"
        )

      return self.difficulty

  def get_balance(self, address):
    balance = 0
    for UTXO in self.UTXO_list:
      if UTXO.address == address:
        balance += UTXO.amount

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

  # p2p transaction
  def build_transaction(self, sender, receiver, amount):
    if self.get_balance(sender) < amount:
      return False

    else:
      tran_list = []
      # build input transactions
      temp = amount
      i = 0
      while not(temp == 0):
        if self.UTXO_list[i].address == sender:
          if self.UTXO_list[i].amount >= temp:
            tran = Transaction("Input", self.UTXO_list[i].txID, address, temp, '')
            tran_list.append(tran)
            break
          else:
            tran = Transaction("Input", self.UTXO_list[i].txID, address, self.UTXO_list[i].amount, '')
            tran_list.append(tran)
            temp -= self.UTXO_list[i].amount

        i += 1

      # build output transactions
      tran = Transaction("Output", '', address, amount, '')
      tran_list.append(tran)
      
      return tran_list
  
  def sign_transaction(self, transaction, private):
    private_key = rsa.PrivateKey.load_pkcs1(private)
    txID = str(transaction.txID)
    sign = rsa.sign(txID.encode('utf-8'), private_key, 'SHA-256')
    return sign

  def add_transaction(self, transaction, signature):
    if transaction.type == "Input":
      # add Input transaction to pending
      public = '-----BEGIN RSA PUBLIC KEY-----\n'
      public += transaction.address
      public += '\n-----END RSA PUBLIC KEY-----\n'
      public_key = rsa.PublicKey.load_pkcs1(public.encode('utf-8'))
      txID = str(transaction.txID)
      try:
        rsa.verify(txID.encode('utf-8'), signature, public_key)
        self.pending_transactions.append(transaction)
        return True
      except Exception:
        print("Signature not verified!")
        
    else:
      # add Output transaction to pending 
      self.pending_transactions.append(transaction)
      
if __name__ == "__main__":
  
  b = Blockchain()
  b.create_genesis_block()
  address, private = b.generate_address()
  # mine 1
  b.pow_mine(address)
  # mine 2
  b.pow_mine(address)
  # check UTXO
  print("Block 2: UTXO")
  for i in range(len(b.UTXO_list)):
    print(str(i) + ":")
    print(b.UTXO_list[i])

  # add a new transcation
  transactions = b.build_transaction(address, 'test', 12)
  for tran in transactions:
    sign = b.sign_transaction(tran, private)
    b.add_transaction(tran, sign)


  print()
   # check pending
  print("Pending")
  for i in b.pending_transactions:
    print(i)
  
  b.pow_mine('456')

  print()
  # check UTXO
  print("Block 3: UTXO")
  for i in range(len(b.UTXO_list)):
    print(str(i) + ":")
    print(b.UTXO_list[i])
  
  '''
  b.
  b.pow_mine('123')
  for tran in b.build_transaction('123','test',12):
    print(tran)
  #print(b.build_transaction('123','test',5))
  
  b.pow_mine(address)
  print(b.chain[1].transaction[0])
  for i in range(len(b.UTXO_list)):
    print(str(i) + ":")
    print(b.UTXO_list[i])
  '''
  
