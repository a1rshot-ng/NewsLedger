#  A simple BlockChain implementation for the project

import json
import hashlib
import requests

from time import time
from urllib.parse import urlparse

DIFFICULTY = 6


class BlockChain(object):
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = set()

        self.new_block(previous_hash=1, proof=100)

    def new_block(self, proof, previous_hash=None):
        #  Creates a new block: index, timestamp, transactions list, proof, prev hash

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        self.current_transactions = []
        self.chain.append(block)

        return block

    def new_transaction(self, site, text):
        #  Pushes new transaction to the blockchain
        self.current_transactions.append({
            'site': site,
            'text': text
        })
        return self.last_block['index'] + 1

    @staticmethod
    def hash(block):
        #  Hashes the block
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        # PoW algorithm looking for number N[i] such that sha256(N[i],N[i-1]) < M
        proof = 0
        while not self.valid_proof(proof, last_proof):
            proof += 1
        return proof

    @staticmethod
    def valid_proof(proof, last_proof):
        guess = f'{proof}:{last_proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:DIFFICULTY] == '0' * DIFFICULTY

    def register_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}\n{block}\n\n--------\n')

            if block['previous_hash'] != self.hash(last_block):
                return False

            if not self.valid_proof(block['proof'], last_block['proof']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None

        max_length = len(self.chain)

        for node in neighbours:
            try:
                response = requests.get(f'http://{node}/chain')

                if response.status_code == 200:
                    length = response.json()['length']  # TODO: do not trust 'length' parameter, check it yourself
                    chain = response.json()['chain']
                    print(f'node {node}/chain: got code 200')

                    if length > max_length and self.valid_chain(chain):
                        max_length = length
                        new_chain = chain
            except:
                continue

        if new_chain:
            self.chain = new_chain
            return True

        return False
