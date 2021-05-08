#  Client-side transactions API

from random import getrandbits
from ast import literal_eval

from base64 import b64encode
from Crypto.PublicKey import RSA

from blockchain import *


class ChainClient(BlockChain):
    def __init__(self, keyfile="rsa-id", nonce_file="nonces.txt"):
        logging.basicConfig(filename='client.log', filemode='w', level=logging.WARNING)
        super().__init__()
        self.nonce_file = nonce_file
        self.pubkey = None
        self.privkey = None
        self.nonces = None
        self.load_keys(keyfile)
        self.load_nonces(nonce_file)
        self.resolve_conflicts()

    def new_keys(self):
        self.privkey = RSA.generate(KEY_LEN)
        self.pubkey = self.privkey.publickey()

    def save_keys(self, keyfile):
        try:
            with open(keyfile, "wb") as f:
                f.write(self.privkey.export_key())
        except FileExistsError:
            logging.error("Could not save keys to file %r", keyfile)
            return 1

    def load_keys(self, keyfile):
        try:
            with open(keyfile, "rb") as f:
                self.privkey = RSA.importKey(f.read())
                self.pubkey = self.privkey.publickey()
        except FileNotFoundError:
            logging.warning("No key files are found at %r, generating new keys", keyfile)
            self.new_keys()
            self.save_keys(keyfile)

    def save_nonces(self):
        try:
            with open(self.nonce_file, 'w') as f:
                f.write(str(self.nonces))
        except FileExistsError:
            logging.error("Could not save nonces to %r", self.nonce_file)

    def load_nonces(self, nonce_file):
        try:
            with open(nonce_file) as f:
                self.nonces = literal_eval(f.read())
        except Exception as e:
            self.nonces = dict()
            logging.error("Could not load nonces from %r: %s", nonce_file, e)
            self.save_nonces()

    def create_transaction(self):
        transaction = {
            'sender': b64encode(int.to_bytes(self.pubkey.n, KEY_LEN//8, 'big')).decode('utf-8'),
            'timestamp': time()
        }
        return transaction

    def sign_transaction(self, transaction):
        key = rsa.PrivateKey(self.privkey.n, self.privkey.e, self.privkey.d, self.privkey.p, self.privkey.q)
        sign = rsa.sign(unhexlify(BlockChain.hash(transaction)), key, 'SHA-256')
        transaction['signature'] = b64encode(sign).decode('utf-8')
        return transaction

    @staticmethod
    def register_article(transaction, name, link, deposit):
        transaction['operation'] = "register_article"
        transaction['recipient'] = name
        transaction['link'] = link
        transaction['deposit'] = deposit
        return transaction

    def vote_for_article(self, transaction, name, vote):
        transaction['operation'] = "vote"
        transaction['recipient'] = name
        nonce = hex(getrandbits(256))[2:]
        self.nonces[name] = (vote, nonce)
        self.save_nonces()
        vote_hash = hashlib.sha256(bytes(vote + ':' + nonce, encoding='utf-8')).hexdigest()
        transaction['vote_hash'] = vote_hash
        return transaction

    def confirm_vote(self, transaction, name):
        transaction['operation'] = "vote_confirm"
        transaction['recipient'] = name
        vote_nonce = self.nonces.get(name)
        if not vote_nonce:
            logging.error("No matching nonce found for %r", name)
            return transaction
        transaction['vote'] = vote_nonce[0]
        transaction['vote_nonce'] = vote_nonce[1]
        return transaction

    @staticmethod
    def vote_for_newbie(transaction, pubkey):
        transaction['operation'] = "accept_newbie"
        transaction['recipient'] = pubkey
        return transaction

    def push_transaction(self, transaction):
        if TransactionsValidator.valid_transaction(self, transaction):
            self.new_transaction(transaction)
            for node in self.nodes:
                try:
                    response = requests.post(f'http://{node}/transactions/new', json=transaction)
                    if response.status_code != 200:
                        logging.warning("Node %r denied transaction, response code is %d", response.status_code)
                    else:
                        logging.info("Pushed transaction to node %r", node)
                except Exception as e:
                    logging.warning("Error pushing to node %r: %s", node, e)
        else:
            logging.warning("Trying to push invalid transaction")
