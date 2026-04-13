"""Thread-safe packet queue shared by the IDS pipeline."""

from queue import Queue


PACKET_QUEUE: Queue = Queue()
