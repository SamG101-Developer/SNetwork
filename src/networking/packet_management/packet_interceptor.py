from typing import Optional

from threading import Thread
from queue import Queue

from pydivert.windivert import WinDivert
from pydivert.packet import Packet


class packet_interceptor:
    def __init__(self):
        # create queue and interceptor object
        self._packet_queue = Queue()
        self._interceptor: Optional[WinDivert] = None

        # create the thread for interception
        self._interceptor_thread = Thread(target=self._enqueue_packets)
        self._interceptor_thread.start()

    def _enqueue_packets(self):
        # create the actual interceptor object (built in thread)
        self._interceptor = WinDivert(filter="tcp.DstPort == 443 or tcp.DstPort == 80 or tcp.DstPort == 8080")
        self._interceptor.open()

        # loop until there are no packets left to process
        while True:
            packet: Packet = self._interceptor.recv()
            if packet.payload:
                print("%s -> %s (%s)" % (packet.src_addr, packet.dst_addr, packet.payload[:30]))
            self._interceptor.send(packet)

            if packet.dst_port != 80:
                self._packet_queue.put(packet)


if __name__ == "__main__":
    from PyQt6.QtCore import QCoreApplication
    import sys

    application = QCoreApplication(sys.argv)
    p = packet_interceptor()
    sys.exit(application.exec())
