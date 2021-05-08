#  BlockChain logic implementation for the project

import os
import json
import hashlib
from binascii import unhexlify
from base64 import b64decode

import rsa
import requests
import logging

from time import time
from urllib.parse import urlparse


# CONFIG_FILE = "config.py"
# TODO: import settings from config file?

DIFFICULTY = 4              # approx. 1-2 seconds to mine a block
RSA_EXP = 65537             # exponent used in RSA algorithm
KEY_LEN = 2048              # 2048 bits RSA keys are used
TRANSACTIONS_TO_MINE = 1    # max transaction count to buffer before mining

TRANSACTION_TIME = 15       # 15 seconds

VOTES_FOR_NEWBIE = 20       # 20 votes required to accept a newbie
# TODO: consider accepting newbies based on votes percentage, instead of fixed count?
NEWBIE_COST = 20.0          # 20 tokens needed to accept a newbie (they are not spent when accepting)
INITIAL_BALANCE = 50.0

DEPOSIT_MIN = 20.0          # minimum deposit for new articles
VOTING_TIME = 3*60 # 60*60*24*7    # 7 days to vote
CONFIRM_TIME = 2*60 # 60*60*24     # 1 day to confirm
VOTE_COST = 1.0             # 1 token to vote
AUTHOR_PROFIT = 0.1         # 10 % of tokens for 'negative' go to author
POS_THRESHOLD = 0.7         # 70 % positive votes -> trustworthy article
NEG_THRESHOLD = 0.6         # 60 % negative votes -> fake article

with open('root-key.txt') as f:
    ROOT_PUBKEY = f.read().replace('\n', '')


class BlockChain(object):
    def __init__(self, chain_file="blocks.json", node_file="nodes.txt"):
        self.chain = []
        self.chain_file = chain_file
        self.node_file = node_file
        self.current_transactions = []
        self.nodes = set()
        self.users = {ROOT_PUBKEY, }
        self.balances = {ROOT_PUBKEY: INITIAL_BALANCE, }
        self.invites = {ROOT_PUBKEY: -1, }
        self.articles = dict()

        if os.path.exists(node_file):
            self.load_nodes(node_file)

        if os.path.exists(chain_file):
            self.load_chain(chain_file)
            assert self.valid_chain(self.chain)
            self.update_state()
        if not self.chain:
            self.new_block(previous_hash=1, proof=100)

    def new_block(self, proof, previous_hash=None):
        #  Creates a new block: index, timestamp, transactions list, proof, prev hash

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1])
        }

        self.current_transactions = []
        self.chain.append(block)
        self.update_state(-1)

        return block

    def new_transaction(self, transaction):
        #  Pushes new transaction to the blockchain
        self.current_transactions.append(dict(transaction))
        if len(self.current_transactions) == TRANSACTIONS_TO_MINE:
            last_block = self.last_block
            last_proof = last_block['proof']
            proof = self.proof_of_work(last_proof)
            self.new_block(proof)
        self.save_chain(self.chain_file)
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
        # PoW algorithm looking for number N[i] such that sha256(N[i] + ':' + N[i-1]) < M
        proof = 0
        while not self.valid_proof(proof, last_proof):
            proof += 1
        return proof

    def valid_proof(self, proof, last_block):
        guess = f'{proof}:{self.hash(last_block)}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:DIFFICULTY] == '0' * DIFFICULTY

    def register_node(self, address):
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)

    def save_nodes(self, filename):
        try:
            with open(filename, "w") as f:
                for node in self.nodes:
                    f.write(f"http://{node}/\n")
        except Exception as e:
            logging.error("Could not save nodes to %r: %s", filename, e)

    def load_nodes(self, filename):
        try:
            with open(filename) as f:
                for node in f.readlines():
                    self.register_node(node)
        except FileNotFoundError:
            logging.warning("Could not load nodes from %r", filename)
            
    def valid_chain(self, chain):
        if len(chain) == 0:
            return False

        last_block = chain[0]
        if last_block['transactions']:  # genesis block must not have any transactions
            return False

        for block in chain[1:]:
            if block['previous_hash'] != self.hash(last_block):
                return False

            if not self.valid_proof(block['proof'], last_block['proof']):
                # as we verify every transaction if it complies with the rules, do we actually need mining?
                # the answer is: no, we don't really need it. but let it be some sort of anti-flood mechanism.
                return False

            if not all(TransactionsValidator.valid_transaction(self, t) for t in block['transactions'][1:]):
                return False

            last_block = block

        return True

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None

        my_length = len(self.chain)

        for node in neighbours:
            try:
                response = requests.get(f'http://{node}/chain')

                if response.status_code == 200:
                    chain = response.json()['chain']
                    length = len(chain)
                    print(f'node {node}/chain: got code 200')

                    if length > my_length and self.valid_chain(chain):
                        my_length = length
                        new_chain = chain
            except Exception as e:
                logging.error(f"Could not sync with node {node}: {e}")
                continue

        if new_chain:
            # diff = len(new_chain) - len(self.chain)
            self.chain = new_chain
            self.save_chain(self.chain_file)
            self.update_state()
            return True

        return False

    def save_chain(self, filename):
        try:
            with open(filename, "w") as f:
                json.dump(self.chain, f, ensure_ascii=True, sort_keys=True)
        except Exception as e:
            logging.error("Could not save chain to %r: %s", filename, e)

    def load_chain(self, filename):
        try:
            with open(filename, "r") as f:
                self.chain = json.load(f)
                self.update_state()
        except Exception as e:
            logging.info("Failed to load chain from %r: %s", filename, e)

    def update_state(self, offset=0):
        # articles & users handling
        if offset == 0:
            self.users = {ROOT_PUBKEY, }
            self.balances = {ROOT_PUBKEY: INITIAL_BALANCE, }
            self.invites = {ROOT_PUBKEY: -1, }
            self.articles = dict()
        for block in self.chain[offset:]:
            block_stamp = block['timestamp']
            for t in block['transactions']:
                user = t['sender']
                recipient = t['recipient']
                # articles handling
                if t['operation'] == "register_article":
                    self.balances[user] -= t['deposit']
                    self.articles[recipient] = {'author': user, 'name': t['recipient'], 'link': t['link'],
                                                'deposit': t['deposit'], 'timestamp': block_stamp,
                                                'votes': {'pos': 0, 'neg': 0}}
                elif t['operation'] == "vote_confirm":
                    self.articles[recipient]['votes'][t['vote']] += 1
                # newbies handling
                elif t['operation'] == "accept_newbie":
                    if self.invites.get(recipient) and self.invites[recipient] < min(len(self.users), VOTES_FOR_NEWBIE): self.invites[recipient] += 1
                    else: self.invites[recipient] = 1
                    if self.invites[recipient] == min(len(self.users), VOTES_FOR_NEWBIE):
                        self.users.add(recipient)
                        self.balances[recipient] = INITIAL_BALANCE
        # votes handling
        for block in self.chain[offset:]:
            for t in block['transactions']:
                user = t['sender']
                recipient = t['recipient']
                if t['operation'] == "vote_confirm":
                    self.balances[user] -= VOTE_COST
                    vote = t['vote']
                    if time() - self.articles[recipient]['timestamp'] > VOTING_TIME + CONFIRM_TIME:
                        votes = self.articles[recipient]['votes']
                        pos, neg = votes['pos'], votes['neg']
                        if not pos or not neg:
                            self.balances[user] += VOTE_COST
                            self.balances[self.articles[recipient]['author']] += self.articles[recipient]['deposit'] / (neg + pos)

                        elif pos > (neg + pos) * POS_THRESHOLD and vote == "pos":
                            self.balances[user] += VOTE_COST * (neg / pos) * (1 - AUTHOR_PROFIT)
                            self.balances[self.articles[recipient]['author']] += self.articles[recipient]['deposit']/pos + VOTE_COST * neg/pos * AUTHOR_PROFIT

                        elif neg > (neg + pos) * NEG_THRESHOLD and vote == "neg":
                            self.balances[user] += (VOTE_COST * pos + self.articles[recipient]['deposit']) / neg

                        elif pos > (neg + pos) * (1 - NEG_THRESHOLD):  # neutral: money-back
                            self.balances[user] += VOTE_COST
                            self.balances[self.articles[recipient]['author']] += self.articles[recipient]['deposit']/(neg+pos)
                elif t['operation'] == "register_article" and \
                        sum(self.articles[t['recipient']]['votes'][i] for i in ('pos', 'neg')) == 0 and \
                        time() - self.articles[recipient]['timestamp'] > VOTING_TIME + CONFIRM_TIME:
                    self.balances[t['sender']] += self.articles[t['recipient']]['deposit']

    def get_balance(self, user):
        if self.balances.get(user) is not None:
            return self.balances[user]
        return -float('inf')


class TransactionsValidator:
    # noinspection PyUnreachableCode
    @staticmethod
    def valid_transaction(bchain, values):
        # return True
        # 1: all fields required are present and valid, transaction is signed properly
        if  (TransactionsValidator.base_fields_present(values) and
             TransactionsValidator.valid_signature(bchain, values)):
            operation = values.get('operation')
            # 2: special rules apply to different operations
            if operation == "vote":
                return TransactionsValidator.valid_vote(bchain, values)
            elif operation == "vote_confirm":
                return TransactionsValidator.valid_confirm(bchain, values)
            elif operation == "accept_newbie":
                return TransactionsValidator.valid_newbie(bchain, values)
            elif operation == "register_article":
                return TransactionsValidator.valid_article(bchain, values)
        return False

    @staticmethod
    def base_fields_present(values):
        if  (values.get('sender') and
             values.get('recipient') and
             values.get('operation') and
             values.get('timestamp') and
             values.get('signature')):
            return True
        logging.info(f"Transaction denied: base fields not present\n{values}")
        return False

    @staticmethod
    def valid_signature(bchain, values):
        # 1. valid sender - has been accepted once and now in users list
        if values['sender'] not in bchain.users:
            logging.info(f"Transaction denied: user is not in users list\n{values}")
            return False

        # valid signature
        values_wo_sign = values.copy()
        values_wo_sign.pop('signature')

        trans_time = time() - values['timestamp']
        if trans_time < 0 or trans_time > TRANSACTION_TIME:
            logging.info(f"Transaction denied: invalid or expired timestamp\n{values}")
            return False

        n = b64decode(bytes(values['sender'], encoding='utf-8'))
        n = int.from_bytes(n, 'big')
        pk = rsa.PublicKey(n, RSA_EXP)
        try:
            rsa.verify(unhexlify(BlockChain.hash(values_wo_sign)), b64decode(bytes(values['signature'], encoding='utf-8')), pk)
        except rsa.pkcs1.VerificationError:
            logging.info(f"Transaction denied: invalid RSA signature\n{values}")
            return False

        return True

    @staticmethod
    def valid_vote(bchain, values):
        # additional fields present
        if not values.get('vote_hash'):
            logging.info(f"Transaction denied: no vote hash provided\n{values}")
            return False

        # identify the article, get timestamp, check if user has voted before
        voter = values['sender']
        article = values['recipient']
        if not bchain.articles.get(article):
            logging.info(f"Transaction denied: unknown article to vote for\n{values}")
            return False

        for block in bchain.chain[::-1]:
            for t in block['transactions']:
                if t['operation'] == "vote" and t['sender'] == voter and t['recipient'] == article:
                    logging.info(f"Transaction denied: user has already voted\n{values}")
                    return False

        # checking timestamp to comply with voting time
        if values['timestamp'] - bchain.articles[article]['timestamp'] > VOTING_TIME:
            logging.info(f"Transaction denied: voting time has already passed\n{values}")
            return False

        return True

    @staticmethod
    def valid_confirm(bchain, values):
        # additional fields:
        if not values.get('vote') or not values.get('vote_nonce'):
            logging.info(f"Transaction denied: no vote or nonce provided to confirm the vote\n{values}")
            return False

        # identify the article, get timestamp, check if user has voted before
        voter = values['sender']
        article = values['recipient']

        if not bchain.articles.get(article):
            logging.info(f"Transaction denied: unknown article to confirm vote for\n{values}")
            return False

        for block in bchain.chain[::-1]:
            block_stamp = block['timestamp']
            for t in block['transactions']:
                if t['operation'] == "vote" and t['sender'] == voter and t['recipient'] == article:
                    vote_hash = t['vote_hash']
                    break
                elif t['operation'] == "vote_confirm" and t['sender'] == voter and t['recipient'] == article:
                    logging.info(f"Transaction denied: user has already confirmed their vote\n{values}")
                    return False
            else:
                continue
            break
        else:
            logging.info(f"Transaction denied: user hasn't voted for the article\n{values}")
            return False

        # checking timestamp to comply with confirm time
        if values['timestamp'] - block_stamp > VOTING_TIME:
            logging.info(f"Transaction denied: confirmation time has already passed\n{values}")
            return False

        # checking if voter has enough tokens in their wallet
        if bchain.get_balance(voter) < VOTE_COST:
            logging.info(f"Transaction denied: not enough tokens to confirm the vote\n{values}")
            return False

        # checking if vote hash matches hash of vote + nonce
        if vote_hash != hashlib.sha256(bytes(values['vote'] + ':' + values['vote_nonce'], encoding='utf-8')).hexdigest():
            logging.info(f"Transaction denied: vote hash does not match vote + nonce\n{values}")
            return False

        return True

    @staticmethod
    def valid_newbie(bchain, values):
        voter = values['sender']
        newbie = values['recipient']
        if newbie in bchain.users:
            logging.info(f"Transaction denied: user has already been accepted\n{values}")
            return False

        # TODO: we might want to check if users are from the same publisher

        # check if acceptor hasn't been "banned"
        if bchain.get_balance(voter) < NEWBIE_COST:
            logging.info(f"Transaction denied: user can't accept newbie due to low balance\n{values}")
            return False

        for block in bchain.chain[::-1]:
            for t in block['transactions']:
                if t['operation'] == "accept_newbie" and t['sender'] == voter and t['recipient'] == newbie:
                    logging.info(f"Transaction denied: user has already voted for this newbie\n{values}")
                    return False

        return True

    @staticmethod
    def valid_article(bchain, values):
        # additional fields:
        if not values.get('deposit') or not values.get('link'):
            logging.info(f"Transaction denied: no article info provided\n{values}")
            return False

        author = values['sender']
        article = values['recipient']
        deposit = values['deposit']

        # article hasn't been registered already
        if bchain.articles.get(article):
            logging.info(f"Transaction denied: article has already been registered\n{values}")
            return False

        # min deposit passed
        if deposit < DEPOSIT_MIN:
            logging.info(f"Transaction denied: invalid deposit value\n{values}")
            return False

        # enough tokens to deposit
        if bchain.balances[author] < deposit:
            logging.info(f"Transaction denied: not enough tokens for the deposit\n{values}")
            return False

        return True
