#!/usr/bin/env python

import os
import sys
import json
import datetime
import argparse
from flask import Flask, jsonify, request, abort, make_response
from flask_pymongo import PyMongo, ObjectId
from bson.json_util import dumps

__version__ = '1.1.1'
__author__ = '@c3rb3ru5d3d53c'

# HTTP Status Codes
HTTP_SUCCESS_GET_OR_UPDATE          =   200
HTTP_SUCCESS_CREATED                =   201
HTTP_SUCCESS_DELETED                =   204
HTTP_SERVER_ERROR                   =   500
HTTP_NOT_FOUND                      =   404
HTTP_BAD_REQUEST                    =   400

class BLServer():

    """
    Binlex and MongoDB HTTP API Server
    """

    def __init__(self):
        self.app = Flask(__name__)

    def arguments(self):
        self.parser = argparse.ArgumentParser(
            prog=f'blserver v{__version__}',
            description='Binlex and MongoDB HTTP API Server',
            epilog=f'Author: {__author__}'
        )
        self.parser.add_argument(
            '--version',
            action='version',
            version=f'v{__version__}'
        )
        self.parser.add_argument(
            '-l',
            '--listen',
            type=str,
            default='127.0.0.1',
            help='Server Listen Address',
            required=False
        )
        self.parser.add_argument(
            '-c',
            '--connection',
            type=str,
            default='mongodb://127.0.0.1',
            help='MongoDB Connection String',
            required=False
        )
        self.parser.add_argument(
            '-p',
            '--port',
            type=int,
            default=8080,
            required=False,
            help='Server Port'
        )
        self.parser.add_argument(
            '-d',
            '--debug',
            action='store_true',
            required=False,
            default=False,
            help='Debug'
        )
        self.args = self.parser.parse_args()

    def routes(self, app):
        @app.route('/time', methods=['GET'])
        def server_time():
            """
            Get Server ISO Time
            """
            data = {"time": datetime.datetime.now().isoformat()}
            return self.send(data, HTTP_SUCCESS_GET_OR_UPDATE)
        @app.route('/<collection_name>/count', methods=['GET'])
        def collection_name_count(collection_name):
            """
            Count of number of documents in a collection.
            """
            collection = getattr(mongo.db, collection_name)
            results = collection.find()
            output = {
                "count": results.count()
            }
            return send(output, HTTP_SUCCESS_GET_OR_UPDATE)
        @app.route('/<collection_name>', methods=['GET'])
        def get_all_items(collection_name):
            """
            Documents in a collection.
            """
            collection = getattr(mongo.db, collection_name)
            output = []
            for q in collection.find():
                output.append(q)
            return send(output, HTTP_SUCCESS_GET_OR_UPDATE)
        @app.route('/<collection_name>/<id>', methods=['GET'])
        def get_one_item(collection_name, id):
            """
            Get one item from a collection.
            """
            collection = getattr(mongo.db, collection_name)
            r = collection.find_one({'_id': ObjectId(id)})
            if r:
                return send(r, HTTP_SUCCESS_GET_OR_UPDATE)
            else:
                return send({'error' : 'item not found'}, HTTP_NOT_FOUND)
        @app.route('/<collection_name>', methods=['POST'])
        def post_item(collection_name):
            """
                Post one item in collection.
            """
            collection = getattr(mongo.db, collection_name)
            formdata = request.json
            try:
                insert_id = str(collection.insert_one(formdata).inserted_id)
                output = {'message': 'new item created', "_id": insert_id}
                return send(output, HTTP_SUCCESS_CREATED)
            except Exception as e:
                output = {'error' : str(e)}
                return send(output, HTTP_BAD_REQUEST)
        @app.route('/<collection_name>/<id>', methods=['PUT'])
        def update_item(collection_name, id):
            """
            Update one item in collection.
            """
            collection = getattr(mongo.db, collection_name)
            r = collection.find_one({'_id': ObjectId(id)})
            if r:
                for key in request.json.keys():
                    r[key] = request.json[key]
                try:
                    collection.replace_one({"_id": ObjectId(id)}, r)
                    output = {'message' : 'item updated'}
                    return send(output, HTTP_SUCCESS_GET_OR_UPDATE)
                except Exception as e:
                    output = {'error' : str(e)}
                    return send(output, HTTP_BAD_REQUEST)
            else:
                output = {'error' : 'item not found'}
                return send(output, HTTP_NOT_FOUND)
        @app.route('/<collection_name>/<id>', methods=['DELETE'])
        def delete_item(collection_name, id):
            """
                Delete one item from collection.
            """
            collection = getattr(mongo.db, collection_name)
            r = collection.find_one({'_id': ObjectId(id)})
            if r:
                try:
                    collection.remove(r["_id"])
                    return send("", HTTP_SUCCESS_DELETED)
                except Exception as e:
                    output = {'error' : str(e)}
                    return send(output, HTTP_BAD_REQUEST)
            else:
                output = {'error' : 'item not found'}
                return send(output, HTTP_NOT_FOUND)
        @app.errorhandler(404)
        def not_found(error):
            return send({'error': 'Not found'}, HTTP_NOT_FOUND)
        @app.errorhandler(500)
        def internal_server_error(error):
            return send({'error': 'Internal Server Error'}, HTTP_SERVER_ERROR)
        @app.errorhandler(Exception)
        def unhandled_exception(error):
            try:
                return send({'error': str(error)}, HTTP_SERVER_ERROR)
            except:
                return send({'error': "Unknown error"}, HTTP_SERVER_ERROR)

    @staticmethod
    def send(data, status_code):
        return make_response(dumps(data), status_code)

    def main(self):
        self.arguments()
        self.app.config["MONGO_URI"] = self.args.connection
        self.mongo = PyMongo(self.app)
        self.routes(self.app)
        self.app.run(
            host=self.args.listen,
            port=self.args.port,
            debug=self.args.debug
        )


if __name__ in '__main__':
    blserver = BLServer()
    blserver.main()