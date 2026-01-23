class Test:

    __number = -1

    def __init__(self, num=0):
        self.set_num(num)

    def get_num(self):
        return self.__number

    def set_num(self, num):
        self.__number = num

    def __str__(self):
        return str(self.get_num())
