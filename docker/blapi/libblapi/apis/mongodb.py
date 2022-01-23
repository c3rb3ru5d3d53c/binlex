#!/usr/bin/env python

import pymongo
from pprint import pprint
from bson.objectid import ObjectId
from flask import Blueprint
from flask import current_app as app
from flask import request
from flask_restx import Namespace, Resource, fields
from bson import json_util
import json

api = Namespace('mongodb', description='Binlex MongoDB API')

def jsonify(data):
    return json.loads(json.dumps(data, default=json_util.default))

@api.route('/version')
class mongodb_collection_count(Resource):
    def get(self):
        """Get MongoDB Version"""
        return {
            'version': pymongo.__version__
        }

@api.route('/<collection>/count')
class mongodb_collection_count(Resource):
    def get(self):
        """Get Collection Document Count"""
        return 'Placeholder'

@api.route('/<collection>/<id>')
class mongodb_collection_id(Resource):
    def get(self, collection, id):
        """Get Collection Document by ID"""
        collection = app.config['mongodb_db'][collection]
        result = collection.find_one({'_id': ObjectId(id)})
        return jsonify(result)

@api.route('/<collection>/find')
class mongodb_collection_find(Resource):
    def post(self, collection):
        """Find Documents in a Collection"""
        try:
            data = json.loads(request.data.decode('utf-8'))
            collection = app.config['mongodb_db'][collection]
            results = collection.find(dict(data))
            if results is None:
                return []
            return jsonify(results)
        except Exception as error:
            return {
                'error': str(error)
            }, 400
        return 'Placeholder'

@api.route('/<collection>/findOne')
class mongodb_collection_findOne(Resource):
    def post(self):
        """Find Single Document in Collection"""
        return 'Placeholder'

@api.route('/<collection>/aggregate')
class mongodb_collection_aggregate(Resource):
    def post(self):
        """Find Aggregate Data"""
        return 'Placeholder'