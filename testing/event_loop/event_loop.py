import socket
import select
import collections
import time
import heapq


class scheduler:
    def __init__(self):
        self._ready = collections.deque()
        self._sleeping = []
        self._read_waiting = {}
        self._write_waiting = {}

    def _call_soon(self, function):
        self._ready.append(function)

    def _call_later(self, sleep, function):
        deadline = time.time() + sleep
        heapq.heappush(self._sleeping, (deadline, function))

    def _read_wait(self):
