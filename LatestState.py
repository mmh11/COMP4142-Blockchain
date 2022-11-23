class LatestState:
    def __init__(self, height):
        self.height = height
        self.fullNodeList = []
        self.neighborList = []
    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)