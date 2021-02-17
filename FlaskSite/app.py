#  A simple blockchain-based website project for archiving news
#  https://proglib.io/p/learn-blockchains-by-building-one/
#
#  TODO:
#   working with database
#   web app: frontend for every endpoint, and for /chain - some page wrapper with list and search option
#   node authentication? signature (pk,sk)?
#   trusted editors list? auto-parsing?
#      .
#   permissions:
#   - view chain:       everyone
#   - node register:    everyone
#   - node resolve:     everyone
#   - add transaction:  editors only (pk,sk) //OR// everyone, but parsing is server-side
#      .
#   auto-sync:
#   -  before /mine
#   -  every X minutes (if 'replaced', mining stops immediately)
#   -  remove any found texts from current_transactions
#      .
#   auto-mine:
#   -  after /transactions/new, remember site/text hash, then if interrupted, look for matching content in next blocks:
#    if it's found, remove that from current_transactions
#      .
#   transactions:
#   - broadcast automatically to all known nodes (except self!)
#      .
#   identify nodes by ID, not IP
#


import sys

from uuid import uuid4
from flask import Flask, jsonify, request

from blockchain import BlockChain

app = Flask(__name__)
node_id = str(uuid4()).replace('-', '')

bchain = BlockChain()


@app.route('/')
def main_page():
    return f'Node ID: {node_id}'


@app.route('/mine', methods=['GET'])
def mine():
    last_block = bchain.last_block
    last_proof = last_block['proof']
    proof = bchain.proof_of_work(last_proof)
    block = bchain.new_block(proof)

    response = {
        'message': "New Block has been mined",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    # request to put a new transaction, including:  site, text
    values = request.get_json()

    required = ['site', 'text']
    if not values or not all(i in values for i in required):
        return "Missing values", 400

    index = bchain.new_transaction(values['site'], values['text'])

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': bchain.chain,
        'length': len(bchain.chain),
    }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        bchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(bchain.nodes),
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = bchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'chain': bchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': bchain.chain
        }

    return jsonify(response), 200


@app.route('/nodes/id', methods=['GET'])
def node_id():
    response = {
        "id": node_id
    }
    return jsonify(response), 200


if __name__ == '__main__':
    app.run(port=int(sys.argv[1]) or 5000)
