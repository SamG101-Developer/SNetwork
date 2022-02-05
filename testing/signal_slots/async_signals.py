from PyQt6.QtCore import QCoreApplication, QObject
import abc
import enum
import threading
import time
import sys


class connection_types(enum.Enum):
    """
    Enumeration of connection types for the custom signal class: re-uses all the previous qt connection types, and adds
    the new ASYNCHRONOUS_CONNECTION type, which allows the connected method to be executed in a separate thread
    """

    AUTO_CONNECTION = 0x01
    QUEUED_CONNECTION = 0x02
    DIRECT_CONNECTION = 0x04
    UNIQUE_CONNECTION = 0x08
    SINGLE_SHOT_CONNECTION = 0x10
    BLOCKING_QUEUED_CONNECTION = 0x20
    ASYNCHRONOUS_CONNECTION = 0x40


class signal:
    """
    Customized signal class that imitates the original pyqtSignal(...) class, with added support for asynchronous
    signals. Also contains the handler classes for synchronous / asynchronous method calls. Can be used as a drop in
    replacement for pyqtSignal(...); method names are conserved.
    """

    class _handler(abc.ABC):

        @abc.abstractmethod
        def slot(self, method, *args, **kwargs):
            ...

    class _asynchronous_handler(_handler):
        # TODO : change this class to use a consumer setup with a queue of methods to call to keep resources in check
        def __init__(self):
            signal._handler.__init__(self)
            self.__temp_threads = set()

        def slot(self, method, *args, **kwargs):
            thread = threading.Thread(target=method, args=args, kwargs=kwargs)
            thread.start()
            self.__temp_threads.add(thread)

    class _synchronous_handler(_handler):
        def __init__(self):
            signal._handler.__init__(self)

        def slot(self, method, *args, **kwargs):
            method(*args, **kwargs)

    def __init__(self):
        self.__methods = []
        self.__asynchronous_connection_handler = signal._asynchronous_handler()
        self.__synchronous_connection_handler = signal._synchronous_handler()

    def emit(self, *args, **kwargs):
        for method, connection_type in self.__methods:
            if connection_type == connection_types.ASYNCHRONOUS_CONNECTION:
                self.__asynchronous_connection_handler.slot(method, *args, **kwargs)
                continue
            self.__synchronous_connection_handler.slot(method, connection_type, *args, **kwargs)

    def connect(self, method, connection_type=connection_types.AUTO_CONNECTION):
        if method not in self.__methods: self.__methods.append([method, connection_type])

    def disconnect(self, method):
        if method in self.__methods: self.__methods.remove(method)

    def is_connected(self):
        return bool(self.__methods)

    def slots(self):
        return self.__methods

    def slots_asynchronous(self):
        return filter(lambda method_connection: method_connection[1] == connection_types.ASYNCHRONOUS_CONNECTION, self.__methods)

    def slots_synchronous(self):
        return filter(lambda method_connection: method_connection[1] != connection_types.ASYNCHRONOUS_CONNECTION, self.__methods)


if __name__ == "__main__":
    class Sender(QObject):
        test_signal_one = signal()

    class Receiver(QObject):
        def test_slot(self, *args, **kwargs):
            print("STARTED", args, kwargs)
            time.sleep(2)
            print("END")


    application = QCoreApplication(sys.argv)
    sender = Sender()
    receiver1 = Receiver()
    receiver2 = Receiver()

    sender.test_signal_one.connect(receiver1.test_slot, connection_types.ASYNCHRONOUS_CONNECTION)
    sender.test_signal_one.connect(receiver2.test_slot, connection_types.ASYNCHRONOUS_CONNECTION)
    sender.test_signal_one.emit(1, 2, retry=True, id="abc123")

    sys.exit(application.exec())
