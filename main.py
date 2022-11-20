import hashlib
import json
import time
import rsa
import threading
import socket
import sys
import pickle
import tkinter
from transaction import Transaction
from UTXO import UTXO
from multiprocessing import Process

from hashlib import sha256
"""
Reference List:
[1] https://www.youtube.com/watch?v=zVqczFZr124
[2] https://www.activestate.com/blog/how-to-build-a-blockchain-in-python/
[3] https://ithelp.ithome.com.tw/users/20119982/ironman/2255?page=1 <- more comprehensive tutorial, recommend refer this pls.
"""

# Blockchain prototype - The basic content

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

  def add_transaction(self, transaction):
    self.transaction.append(transaction)


  def cal_merkle_root(self):
    ###
    return True

class Blockchain:

  BITCOIN_ONE_BLOCK_MILLISECONDS = 600

  def __init__(self):
    # define Blockchain data
    self.chain = []
    self.adjust_difficulty_blocks = 10
    self.difficulty = 3
    self.block_time = 30
    self.mining_rewards = 10
    self.block_limitation = 32
    self.pending_transactions = []
    self.UTXO_list = []       
    
    # For P2P connection
    self.socket_host = "127.0.0.1"
    self.socket_port = int(sys.argv[1])
    self.node_address = {f"{self.socket_host}:{self.socket_port}"}
    self.connection_nodes = {}
    print("len(sys.argv): "+str(len(sys.argv)))
    if len(sys.argv) == 3:
      print("Request cloning blockchain....")
      self.clone_blockchain(sys.argv[2])
      print(f"Node list: {self.node_address}")
      self.broadcast_message_to_nodes("add_node", self.socket_host+":"+str(self.socket_port))
    # For broadcast block
    self.receive_verified_block = False
    self.start_socket_server()

  def start_socket_server(self):
    t = threading.Thread(target=self.wait_for_socket_connection)
    t.start()

  def wait_for_socket_connection(self):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.bind((self.socket_host, self.socket_port))
      s.listen()
      while True:
        conn, address = s.accept()

        client_handler = threading.Thread(
          target=self.receive_socket_message,
          args=(conn, address)
        )
        client_handler.start()
  
  # cloning
  def clone_blockchain(self, address):
    print(f"Start to clone blockchain by {address}")
    target_host = address.split(":")[0]
    target_port = int(address.split(":")[1])
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((target_host, target_port))
    message = {"request": "clone_blockchain"}
    client.send(pickle.dumps(message))
    response = b""
    print(f"Start to receive blockchain data by {address}")
    while True:
        response += client.recv(4096)
        if len(response) % 4096:
            break
    client.close()
    response = pickle.loads(response)["blockchain_data"]

    self.adjust_difficulty_blocks = response.adjust_difficulty_blocks
    self.difficulty = response.difficulty
    self.block_time = response.block_time
    self.miner_rewards = response.mining_rewards
    self.block_limitation = response.block_limitation
    self.chain = response.chain
    self.pending_transactions = response.pending_transactions
    self.UTXO_list = response.UTXO_list
    self.node_address.update(response.node_address)
  
  # broadcast
  def broadcast_block(self, new_block):
    self.broadcast_message_to_nodes("broadcast_block", new_block)

  def broadcast_transaction(self, new_transaction):
      self.broadcast_message_to_nodes("broadcast_transaction", new_transaction)

  def broadcast_message_to_nodes(self, request, data=None):
      address_concat = self.socket_host + ":" + str(self.socket_port)
      message = {
          "request": request,
          "data": data
      }
      for node_address in self.node_address:
          if node_address != address_concat:
              target_host = node_address.split(":")[0]
              target_port = int(node_address.split(":")[1])
              client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
              client.connect((target_host, target_port))
              client.sendall(pickle.dumps(message))
              client.close()
      
  def receive_broadcast_block(self, block_data):
    last_block = self.chain[-1]
    # Check the hash of received block
    if block_data.previous_hash != last_block.current_hash:
        print("[**] Received block error: Previous hash not matched!")
        return False
    elif block_data.difficulty != self.difficulty:
        print("[**] Received block error: Difficulty not matched!")
        return False
    elif block_data.current_hash != block_data.hash_sha256():
        print(block_data.current_hash)
        print("[**] Received block error: Hash calculation not matched!")
        return False
    else:
        if block_data.hash[0: self.difficulty] == '0' * self.difficulty:
            for each_transaction in block_data.transaction:
                    self.pending_transaction.remove(each_transaction)
            self.receive_verified_block = True
            self.chain.append(block_data)
            print(f"[**] Received block successfully!")
            return True
        else:
            print(f"[**] Received block error: Hash not matched by diff!")
            return False
  
  # receive client request
  def receive_socket_message(self, connection, address):
    with connection:
      # print(f'Connected by: {address}')
      address_concat = address[0]+":"+str(address[1])
      while True:
        message = b""
        while True:
          message += connection.recv(4096)
          if len(message) % 4096:
            break
        try:
          parsed_message = pickle.loads(message)
        except Exception:
          print(f"{message} cannot be parsed")
        if message:
          if parsed_message["request"] == "get_balance":
            print("Start to get the balance for client...")
            address = parsed_message["address"]
            balance = self.get_balance(address)
            response = {
              "address": address,
              "balance": balance
            }
          elif parsed_message["request"] == "transaction":
            print("Start to transaction for client...")
            new_transaction = parsed_message["data"]
            result, result_message = self.add_transaction(
              new_transaction,
              parsed_message["signature"]
            )
            response = {
              "result": result,
              "result_message": result_message
            }
            if result:
              self.broadcast_transaction(new_transaction)
          # 接收到同步區塊的請求
          elif parsed_message["request"] == "clone_blockchain":
            print(f"[*] Receive blockchain clone request by {address}...")
            message = {
              "request": "upload_blockchain",
              "blockchain_data": self
            }
            connection.sendall(pickle.dumps(message))
            continue
          # 接收到挖掘出的新區塊
          elif parsed_message["request"] == "broadcast_block":
            print(f"[*] Receive block broadcast by {address}...")
            self.receive_broadcast_block(parsed_message["data"])
            continue
          # 接收到廣播的交易
          elif parsed_message["request"] == "broadcast_transaction":
            print(f"[*] Receive transaction broadcast by {address}...")
            self.pending_transactions.append(parsed_message["data"])
            continue
          # 接收到新增節點的請求
          elif parsed_message["request"] == "add_node":
            print(f"[*] Receive add_node broadcast by {address}...")
            self.node_address.add(parsed_message["data"])
            continue
          else:
            response = {
              "message": "Unknown command."
            }
          response_bytes = str(response).encode('utf8')
          connection.sendall(response_bytes)

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


    new_block.time_consumed = time.process_time() - start # adjust to milliseconds
    print(
      f"Hash found: {new_block.current_hash} @ difficulty {self.difficulty}, time cost: {new_block.time_consumed}s"
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
    
    return True

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

      if average_time_consumed > self.block_time:
        self.difficulty -= 1
        print(
          f"Average block time:{average_time_consumed}s: Decrease difficulty to {self.difficulty}"
        )

      else:
        self.difficulty += 1
        print(
          f"Average block time:{average_time_consumed}s: Increase difficulty to {self.difficulty}"
        )

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
      tran = Transaction("Output", '', receiver, amount, '')
      tran_list.append(tran)
      
      return tran_list

  def sign_transaction(self, transactions, private):
    tran_list = []
    for tran in transactions:
      if tran.type == "Input":
        tran.signature = self.get_sign(tran, private)
        tran_list.append(tran)
      else: tran_list.append(tran)

    return tran_list
  
  def get_sign(self, transaction, private):
    private_key = rsa.PrivateKey.load_pkcs1(private)
    txID = str(transaction.txID)
    sign = rsa.sign(txID.encode('utf-8'), private_key, 'SHA-256')
    return sign

  # verify and add transaction to pending
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
  
  def start(self):
    address, private = self.generate_address()
    print(f"Miner address: {address}")
    print(f"Miner private: {private}")
    if len(sys.argv) < 3:
      self.create_genesis_block()
    while(True):
      self.pow_mine(address)

  def handle_receive(self):
    while True:
        response = self.client.recv(4096)
        if response:
          print(f"[*] Message from node: {response}")



    '''
      if str(command) not in command_dict.keys():
          print("Unknown command.")
          continue
      message = {
          "request": command_dict[str(command)]
      }
      if command_dict[str(command)] == "generate_address":
          address, private_key = self.generate_address()
          print(f"Address: {address}")
          print(f"Private key: {private_key}")

      elif command_dict[str(command)] == "transaction":
          address = input("Address: ")
          private_key = input("Private_key: ")
          receiver = input("Receiver: ")
          amount = input("Amount: ")
          fee = input("Fee: ")
          comment = input("Comment: ")
          new_transaction = self.build_transaction(
            address, receiver, int(amount)
          )
          signature = self.sign_transaction(new_transaction, private_key)
          message["data"] = new_transaction
          message["signature"] = signature

          self.client.send(pickle.dumps(message))
  '''
        
if __name__ == "__main__":
  b = Blockchain()

  target_host = "127.0.0.1"
  target_port = int(sys.argv[1])
  b.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  b.client.connect((target_host, target_port))

  receive_handler = threading.Thread(target=b.handle_receive, args=())
  receive_handler.start()

  p1 = Process(target=b.start, args=())

  p1.start()

  # UI related
  root= tkinter.Tk()
  root.title("Blockchain App")
  canvas1 = tkinter.Canvas(root, width = 350, height = 200)
  canvas1.pack()

  AddressLabel = tkinter.Label(root, text="Address")
  AddressEntry = tkinter.Entry(root)
  canvas1.create_window(50, 50, window=AddressLabel)
  canvas1.create_window(200, 50, window=AddressEntry)

  def ui_get_balance():
    message = {
      "request": "get_balance"
    }
    address = AddressEntry.get()
    message['address'] = address
    b.client.send(pickle.dumps(message))

  GetBal_button = tkinter.Button(text='Get Balance', command=ui_get_balance)
  canvas1.create_window(270, 50, window=GetBal_button)
  
  root.mainloop()
  

  '''
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
  signed_transactions = b.sign_transaction(transactions,private)
  for tran in signed_transactions:
    sign = b.get_sign(tran, private)
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
  
  
  b.pow_mine(address)
  transactions = b.build_transaction(address, 'test', 10)
  signed_transactions = b.sign_transaction(transactions,private)
  for tran in signed_transactions:
    sign = b.get_sign(tran, private)
    b.add_transaction(tran, sign)

  for i in b.pending_transactions:
    print(i)
  
  b.pow_mine('123')
  print()
  for i in range(len(b.UTXO_list)):
    print(str(i) + ":")
    print(b.UTXO_list[i])
  '''
  
  
  
  
