class UTXO:

  def __init__(self, txID, txIndex, address, sig, amount):
    self.txID = txID
    self.txIndex = txIndex
    self.address = address
    self.signature = sig
    self.amount = amount

  def __str__(self):
    return str(self.__class__) + ": " + str(self.__dict__)