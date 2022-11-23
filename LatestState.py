class LatestState:
    def __init__(self, height, fullNodeList, neighborList):
        self.height = height
        self.fullNodeList = fullNodeList
        self.neighborList = neighborList

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)