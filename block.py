# block.py
import hashlib
import time
import json

class Block:
    def __init__(self, data):
        self.timestamp = time.time()
        self.data = data
        self.hash = self.compute_hash()

    def compute_hash(self):
        content = json.dumps({
            'timestamp': self.timestamp,
            'data': self.data
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def is_valid(self):
        return self.hash == self.compute_hash()
