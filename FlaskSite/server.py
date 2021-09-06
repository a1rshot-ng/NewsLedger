#!/usr/bin/python3

#   Blockchain-based project for archiving news
#
#   current permissions:
#   - view chain:       everyone
#   - node register:    everyone
#   - chain sync:       everyone
#   - add transaction:  editors only -- with RSA signature verification
#
#

import sys
from flask import Flask, jsonify, request

from blockchain import BlockChain, TransactionsValidator


app = Flask(__name__)

bchain = BlockChain()


@app.route('/')
def main_page():
    return 'Server online', 200


@app.route('/mine', methods=['GET'])
def mine():
    if not bchain.current_transactions:
        response = {
            'message': "Nothing to mine",
            'index': -1
        }
        return response, 401

    last_block = bchain.last_block
    last_proof = last_block['proof']
    proof = bchain.proof_of_work(last_proof)
    block = bchain.new_block(proof)

    response = {
        'message': "New Block has been mined",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash']
    }
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    # request to put a new transaction
    values = request.get_json()

    if TransactionsValidator.valid_transaction(bchain, values):
        index = bchain.new_transaction(values)
        response = {'message': f'Transaction will be added to Block {index}'}
    else:
        response = {'message': 'Sorry, transaction denied.'}
    return jsonify(response), 200


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


@app.route('/nodes/list', methods=['GET'])
def nodes_list():
    return jsonify(bchain.nodes), 200


if __name__ == '__main__':
    app.run(port=int(sys.argv[1]) if len(sys.argv) > 1 else 5000)
