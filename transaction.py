class Transaction:

  def __init__(self, type, txID, address, amounts, signature):
    self.type = type
    self.txID = txID
    self.address = address
    self.amounts = amounts
    self.signature = signature

  def __str__(self):
    return str(self.__class__) + ": " + str(self.__dict__)