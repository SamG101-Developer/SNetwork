class Signal:
    def __init__(self):
        self.__slots = []

    def connect(self, slot):
        self.__slots.append(slot)

    def disconnect(self, slot=None):
        self.__slots.remove(slot) if slot else self.__slots.clear()

    def emit(self, *args):
        for slot in self.__slots: slot(*args)


class TestClass1:
    def __init__(self):
        self._signal1 = Signal()
        self._signal2 = Signal()
