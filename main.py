import hashlib
import json
import time
import rsa
import threading
import socket
import copy
import sys
import pickle
import tkinter
import math
from transaction import Transaction
from UTXO import UTXO
from LatestState import LatestState
from multiprocessing import Process
from mongoDB import get_latestblock_fromDB,insert_collection_RawData, find_document, get_latestblock_fromDB, count_rawdata, insert_collection_transactionPool, remove_from_transationPool, count_transactionPool
from redisDB import redisPush

from hashlib import sha256
import queue


"""
Reference List:
[1] https://www.youtube.com/watch?v=zVqczFZr124
[2] https://www.activestate.com/blog/how-to-build-a-blockchain-in-python/
[3] https://ithelp.ithome.com.tw/users/20119982/ironman/2255?page=1 <- more comprehensive tutorial, recommend refer this pls.
"""
client = ''
isReceiveBlock = False
bc_process = ''
q = queue.Queue()

global stop_threads
stop_threads = False

# Blockchain prototype - The basic content



class Node:

  def __init__(self, value):
    self.left = None
    self.right = None
    self.value = value
    self.hash = calculate_hash(self.value)

def calculate_hash(value):
  return hashlib.sha256(value.encode('utf-8')).hexdigest()


def build_merkle_tree(leaves):
  nodes = []

  for i in leaves:
    nodes.append(Node(i))

  #print(nodes)

  while len(nodes) != 1:
    temp = []
    for i in range(0, len(nodes), 2):
      node1 = nodes[i]
      node2 = nodes[i + 1]
      #print(f'left hash: {node1.hash}')
      #print(f'right hash: {node2.hash}')
      concat_hash = node1.hash + node2.hash
      parent = Node(concat_hash)
      parent.left = node1
      parent.right = node2
      #print(f'parent hash: {parent.hash}\n')
      temp.append(parent)
    nodes = temp
  return nodes[0]

def padding(leaves):
  size = len(leaves)
  if size == 0:
    return ['']
  reduced_size = int(math.pow(2, int(math.log2(size))))
  pad_size = 0
  if reduced_size != size:
    pad_size = 2 * reduced_size - size
  for i in range(pad_size):
    leaves.append('')
  return leaves

class Block:

  def __init__(self, index, difficulty, previous_hash='', current_hash=''):
    self.index = index
    self.timestamp = int(time.time())
    self.nonce = 0
    self.difficulty = difficulty
    self.merkle_root = ''
    self.previous_hash = previous_hash
    self.current_hash = current_hash
    self.time_consumed = 0
    self.transaction = []

  def __str__(self):
    return str(self.__class__) + ": " + str(self.__dict__)

  def hash_sha256(self):
    hash_data = str(self.index) + str(self.timestamp) + str(self.nonce) + str(
      self.difficulty) + str(self.merkle_root) + self.previous_hash
    return sha256(hash_data.encode()).hexdigest()

  def add_transaction(self, transaction):
    self.transaction.append(transaction)

  def latest_state(self):
    new_fullNodeList = []
    new_neighborList = []
    new_latest_state = LatestState(self.index, new_fullNodeList, new_neighborList)
    # redisPush(new_latest_state)
    return

  def cal_merkle_root(self):
    leaves = []
    for tran in self.transaction:
      hash_data = ''
      if tran.type == "Input":
        hash_data = str(tran.txID) + str(tran.txIndex) + str(tran.signature)
      else:
        hash_data = str(tran.address) + str(tran.amounts)

      leaves.append(sha256(hash_data.encode()).hexdigest())

    leaves = padding(leaves)
    return build_merkle_tree(leaves)

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
    
    self.isMineBlock = True

    # For P2P connection
    self.socket_host = "127.0.0.1"
    self.socket_port = int(sys.argv[1])
    self.node_address = {f"{self.socket_host}:{self.socket_port}"}
    self.connection_nodes = {}
    print("len(sys.argv): "+str(len(sys.argv)))
    if len(sys.argv) >= 3:
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
    print("assigning blockchain to local")

    self.adjust_difficulty_blocks = response.adjust_difficulty_blocks
    self.difficulty = response.difficulty
    self.block_time = response.block_time
    self.miner_rewards = response.mining_rewards
    self.block_limitation = response.block_limitation
    self.chain = response.chain
    self.pending_transactions = response.pending_transactions
    self.UTXO_list = response.UTXO_list
    self.node_address.update(response.node_address)

    print("response chain: " + str(len(response.chain)))
  
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
    print("last_block:")
    print(last_block)
    print("block_data:")
    print(block_data)
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
        isReceiveBlock = True
        if block_data.current_hash[0: self.difficulty] == '0' * self.difficulty:
          print("block_data.transaction: ")
          print(block_data.transaction)
          for each_transaction in block_data.transaction:
            try:
              self.pending_transactions.remove(each_transaction)
            except Exception:
              print("Transaction isn't existed.")

          self.receive_verified_block = True
          self.chain.append(block_data)
          isReceiveBlock = False
          print(f"[**] Received block successfully!")
          return True
        else:
          print(f"[**] Received block error: Hash not matched by diff!")
          isReceiveBlock = False
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
            if len(new_transaction) > 0:
              signatures = parsed_message["signature"]
              print(f"[*] loading transactions: {new_transaction}")
              print(f"[*] loading signatures: {signatures}")
              for i in range(len(new_transaction)):
                print("[*] broadcasting new message...")
                result, result_message = self.add_transaction(new_transaction[i], signatures[i])
                response = {
                  "result": result,
                  "result_message": result_message
                }
                if result:
                  self.broadcast_transaction(new_transaction[i-1])
          # 接收到同步區塊的請求
          elif parsed_message["request"] == "clone_blockchain":
            print(f"[*] Receive blockchain clone request by {address}...")
            message = {
              "request": "upload_blockchain",
              "blockchain_data": self
            }
            print(message)
            connection.sendall(pickle.dumps(message))
            continue
          # 接收到挖掘出的新區塊
          elif parsed_message["request"] == "broadcast_block":
            if len(sys.argv) == 4:
              print("[**] Slow mode on: sleeping 3 seconds when receiving blocks...")
              time.sleep(3)
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
    if (get_latestblock_fromDB()==None):
      genesis = Block(0, self.difficulty, "", "Group HCCW")
      genesis.current_hash = genesis.hash_sha256()
      self.chain.append(genesis)
      # Noted that the merkle root of the genesis block is equal to the hash of the transaction in it
      insert_collection_RawData([{
        "index": 0, 
        "timestamp": int(time.time()), 
        "previous_hash": "", 
        "current_hash": genesis.current_hash, 
        "difficulty": self.difficulty, 
        "nonce": 0, 
        "transaction": ["Genesis Transation"], 
        "merkle_root": sha256("Genesis Transation".encode()).hexdigest()
      }])
    else:
      genesis = Block(0, self.difficulty, "", "Group HCCW")
      genesis.timestamp = find_document("index",0,"rawdata")["timestamp"]
      genesis.current_hash = find_document("index",0,"rawdata")["current_hash"]
      genesis.nonce = find_document("index",0,"rawdata")["nonce"]
      genesis.transaction = find_document("index",0,"rawdata")["transaction"]
      genesis.merkle_root = find_document("index",0,"rawdata")["merkle_root"]
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
    return (self.chain[-1 * nth])

  def pow_mine(self, address):
      start = time.process_time()
      last_block = self.lastest_block()
      new_block = Block(last_block.index + 1, self.difficulty,
                        last_block.current_hash)

      # add coinbase transaction
      reward_tran = Transaction("Output", "COMP4142", '',address,
                                self.mining_rewards, '')
      new_block.add_transaction(reward_tran)

      # add pending transaction
      self.add_pending_transaction_to_block(new_block)

      # cal merkle root value
      new_block.merkle_root =new_block.cal_merkle_root().hash

      # mine block
      new_block.current_hash = new_block.hash_sha256()
      while new_block.current_hash[0:self.difficulty] != '0' * self.difficulty:
        new_block.nonce += 1
        new_block.current_hash = new_block.hash_sha256()

      time_consumed = round(time.process_time() - start, 5)

      # Update chain if it is not synchronized
      if (self.lastest_block().current_hash != get_latestblock_fromDB()["current_hash"]):
          self.get_chain_data()
          return

      print(
        f"Hash found: {new_block.current_hash} @ difficulty {self.difficulty}, time cost: {time_consumed}s"
      )

      if isReceiveBlock == False:
        if new_block.previous_hash == self.lastest_block().current_hash:
          
          self.broadcast_block(new_block)
          
          # add new mined block to blockchain
          self.chain.append(new_block)

          transation_array = []
          for i in new_block.transaction:
            transation_array.append({"type":i.type, "txID":i.txID, "txIndex":i.txIndex, "address":i.address, "amounts":i.amounts, "signature":i.signature})
          insert_collection_RawData([{
              "index":new_block.index, 
              "timestamp":new_block.timestamp, 
              "previous_hash":new_block.previous_hash, 
              "current_hash":new_block.current_hash, 
              "difficulty":new_block.difficulty, 
              "nonce":new_block.nonce, 
              "transaction":transation_array, 
              "merkle_root":new_block.merkle_root
          }])
      
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
        insert_collection_transactionPool({
          "txID":utxo.txID,
          "txIndex":utxo.txIndex,
          "address":utxo.address,
          "signature":utxo.signature,
          "amount":utxo.amount,
        })

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
          remove_from_transationPool({
            "txID":utxo.txID,
            "txIndex":utxo.txIndex,
            "address":utxo.address,
            "signature":utxo.signature,
            "amount":utxo.amount,
          })
    
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

    pri = str(private_key)
    pri = pri.replace("\\n", '',1)
    pri = pri[::-1].replace("n\\", '', 2)[::-1]
    
    pri = pri.replace(
      "b'-----BEGIN RSA PRIVATE KEY-----", '')
    pri = pri.replace(
      "-----END RSA PRIVATE KEY-----'", '')
    
    with open('address.txt','w') as f:
      f.write("Address: " + public_key_address)
      f.write("Private key: " + pri)

    return public_key_address, private_key

  # p2p transaction
  def build_transaction(self, sender, receiver, amount):
    if self.get_balance(sender) < amount:
      print("You do not have enough balance!")

    else:
      tran_list = []
      # build input transactions
      temp = amount
      i = 0
      while not(temp == 0):
        if self.UTXO_list[i].address == sender:
          if self.UTXO_list[i].amount >= temp:
            tran = Transaction("Input", self.UTXO_list[i].txID, self.UTXO_list[i].txIndex, sender, temp, '')
            tran_list.append(tran)
            break
          else:
            tran = Transaction("Input", self.UTXO_list[i].txID, self.UTXO_list[i].txIndex,sender, self.UTXO_list[i].amount, '')
            tran_list.append(tran)
            temp -= self.UTXO_list[i].amount

        i += 1

      # build output transactions
      tran = Transaction("Output", '', '', receiver, amount, '')
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
        return True, "Authorized successfully!"
      except Exception:
        print("Signature not verified!")
        return False, "RSA Verified wrong!"
        
    else:
      # add Output transaction to pending 
      self.pending_transactions.append(transaction)
      return True, "Authorized successfully!"
      
  
  def start(self):
    address, private = self.generate_address()
    global my_address
    global my_privateKey
    my_address = address
    my_privateKey = private
    print(f"Miner address: {address}")
    print(f"Miner private: {private}")
    if len(sys.argv) < 3:
      self.create_genesis_block()
      self.get_chain_data()
      self.get_utxoList_data()
  
  def run_miningBlock(self):
    
    for num in range(20):
      if len(sys.argv) == 4:
        print("[**] Slow mode on: sleeping 3 seconds when mining new block...")
        time.sleep(3)
      # Update chain if it is not synchronized
      if (self.lastest_block().current_hash != get_latestblock_fromDB()["current_hash"]):
          self.get_chain_data()
      if isReceiveBlock == False:
        self.pow_mine(my_address)
      
  def get_utxoList_data(self):
    # Update/Get utxoList data from mongo DB
    get_utxoList_index = 1
    print(f"[*] Need to load {count_transactionPool()} utxo.")
    while(get_utxoList_index < count_rawdata()):
      
      print(f"[*] Loading utxo {get_utxoList_index}")

      single_utxo = UTXO(
        find_document("txIndex",get_utxoList_index,"transactionPool")["txID"],
        find_document("txIndex",get_utxoList_index,"transactionPool")["txIndex"],
        find_document("txIndex",get_utxoList_index,"transactionPool")["address"],
        find_document("txIndex",get_utxoList_index,"transactionPool")["signature"],
        find_document("txIndex",get_utxoList_index,"transactionPool")["amount"],)
      self.UTXO_list.append(single_utxo)
      get_utxoList_index += 1
      
  
  def get_chain_data(self):
    # Update/Get chain data from mongo DB
    get_block_index = 1
    print(f"[*] Need to load {count_rawdata()} blocks.")
    while(get_block_index < count_rawdata()):
      
      print(f"[*] Loading Block {get_block_index}")

      single_block_data = Block(find_document("index",get_block_index,"rawdata")["index"], find_document("index",get_block_index,"rawdata")["difficulty"])
      single_block_data.index = find_document("index",get_block_index,"rawdata")["index"]
      single_block_data.timestamp = find_document("index",get_block_index,"rawdata")["timestamp"]
      single_block_data.previous_hash = find_document("index",get_block_index,"rawdata")["previous_hash"]
      single_block_data.current_hash = find_document("index",get_block_index,"rawdata")["current_hash"]
      single_block_data.difficulty = find_document("index",get_block_index,"rawdata")["difficulty"]
      single_block_data.nonce = find_document("index",get_block_index,"rawdata")["nonce"]
      # Update/Get every transation in that block
      for downloading_transation in find_document("index",get_block_index,"rawdata")["transaction"]:
        transation_record = Transaction(downloading_transation["type"], downloading_transation["txID"], downloading_transation["txIndex"], downloading_transation["address"], downloading_transation["amounts"], downloading_transation["signature"])
        single_block_data.add_transaction(transation_record)
      single_block_data.merkle_root = find_document("index",get_block_index,"rawdata")["merkle_root"]
      # Update that block and add back into local chain
      self.chain.append(single_block_data)
      get_block_index += 1
      

def handle_receive():
  while True:
      response = client.recv(4096)
      if response:
        print(f"[*] Message from node: {response}")

def user_interface(b):
  
  # UI related
  root= tkinter.Tk()
  root.title("Blockchain App")
  canvas1 = tkinter.Canvas(root, width = 400, height = 400)
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
    client.send(pickle.dumps(message))

  GetBal_button = tkinter.Button(text='Get Balance', command=ui_get_balance)
  canvas1.create_window(350, 50, window=GetBal_button)

  PaymentLabel = tkinter.Label(root, text='Payment')
  Payment_ReceiverLabel = tkinter.Label(root, text='Receiver address')
  Payment_AmountLabel = tkinter.Label(root, text='Amount')

  Payment_ReceiverEntry = tkinter.Entry(root)
  Payment_AmountEntry = tkinter.Entry(root)  

  canvas1.create_window(50, 150, window=PaymentLabel)
  canvas1.create_window(50, 175, window=Payment_ReceiverLabel)
  canvas1.create_window(50, 200, window=Payment_AmountLabel)
  canvas1.create_window(200, 175, window=Payment_ReceiverEntry)
  canvas1.create_window(200, 200, window=Payment_AmountEntry) 

  def ui_payment():
    message = {
      "request": "transaction"
    }
    address = my_address
    receiver = Payment_ReceiverEntry.get()
    amount = Payment_AmountEntry.get()

    private_key = my_privateKey

    print("Request Payment")
    print(f"Sender:\n{address}\nSender's key:\n{private_key}\nReceiver:\n{receiver}\nAmount: {amount}")
    new_transaction = b.build_transaction(
      address, receiver, int(amount)
    )
    print(f"[*] Create new payment transactions: {new_transaction}")
    signature = b.sign_transaction(new_transaction, private_key)
    message["data"] = new_transaction
    message["signature"] = signature

    print(f"[**] Created message: {message}")

    client.send(pickle.dumps(message))


  Pay_button = tkinter.Button(text='Pay Coin', command=ui_payment)
  canvas1.create_window(350, 200, window=Pay_button)

  def ui_mineblock(b, bc_process):
    print(f" [**] isMineBlock: {b.isMineBlock}")
    if b.isMineBlock == True:
      print("[*] Start Mining Block...")
      b.run_miningBlock()
    
  
  MineBlock_button = tkinter.Button(text='Mine Block', command= lambda: ui_mineblock(b, bc_process))
  canvas1.create_window(350, 250, window=MineBlock_button)

  root.mainloop()

        
if __name__ == "__main__":
  b = Blockchain()
  
  print("[*] Connecting client...")
  target_host = "127.0.0.1"
  target_port = int(sys.argv[1])
  client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  client.connect((target_host, target_port))

  print("[*] Adding receive handler...")
  receive_handler = threading.Thread(target=handle_receive, args=())
  receive_handler.start()

  print("[*] Starting Blockchain...")
  b.start()

  print("[*] Loading UI...")
  user_interface(b)
  

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
  
  
  
  
