from PyQt6.QtCore import QCoreApplication, QObject
from PyQt6.QtNetwork import QTcpSocket


class socket_handler(QObject):
    def __init__(self, host, port):
        QObject.__init__(self)

        print("[+] Created socket")

        self._socket = QTcpSocket()
        self._socket.connected.connect(self._check_availability)
        self._socket.connectToHost(host, port)

    def _check_availability(self) -> None:
        self._socket.readyRead.connect(self._handle_incoming_data)
        print("[+] Connected socket")

    def _handle_incoming_data(self) -> bytes:
        data = self._socket.readAll().data()
        print("[RECV] %s" % data.decode("utf8", "ignore")[:50] + "...")
        return data

    def _handle_outgoing_data(self, data: bytes) -> bytes:
        print("[SEND] %s" % data.decode("utf8"))
        self._socket.write(data)
        return data

    def recv(self) -> bytes:
        return self._handle_incoming_data()

    def send(self, data: bytes) -> bytes:
        return self._handle_outgoing_data(data)


if __name__ == "__main__":
    import sys

    application = QCoreApplication(sys.argv)
    s = socket_handler("www.google.com", 80)
    s.send(b"GET / HTTP/1.1\r\nHost:www.google.com\r\n\r\n")
    sys.exit(application.exec())
