#!/usr/bin/env python

import pymongo
from pprint import pprint
from bson.objectid import ObjectId
from flask import Blueprint
from flask import current_app as app
from flask import request
from flask_restx import Namespace, Resource, fields
from bson import json_util
from bson.json_util import loads, dumps
from bson.raw_bson import RawBSONDocument
import json
import bsonjs

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

@api.route('/stats/<collection>/count')
class mongodb_collection_count(Resource):
    def get(self):
        """Get Collection Document Count"""
        return 'Placeholder'

@api.route('/docs/<collection>/<id>')
class mongodb_collection_id(Resource):
    def get(self, collection, id):
        """Get Collection Document by ID"""
        collection = app.config['mongodb_db'][collection]
        result = collection.find_one({'_id': ObjectId(id)})
        return jsonify(result)

@api.route('/traits/file/<string:collection>/<int:limit>/<int:page>')
class mongodb_traits_sha256(Resource):
    def post(self, collection, limit, page):
        """Get Traits via File Query"""
        if collection not in ['default', 'malware', 'goodware']:
                return {
                    'error': 'collection not supported'
                }, 400
        page = page - 1
        if page < 0:
            return {
                'error': 'page must be greater than 0'
            }, 400
        if limit <= 0:
            return {
                'error': 'limit must be greater than 0'
            }, 400
        data = json.loads(request.data)
        cursor = app.config['mongodb_db']['files']
        docs = cursor.aggregate(
           [
               {
                    "$match": data
                },
                {
                    "$lookup": {
                        "from": collection,
                        "localField": "trait_id",
                        "foreignField": "_id",
                        "as": "trait"
                    }
                },
                {
                    "$unwind": "$trait"
                },
                {
                    "$unset": ["_id", "trait._id", "trait_id"]
                },
                {
                    "$sort": {
                        "sha256" : 1
                    }
                },
                {
                    "$skip": page
                },
                {
                    "$limit": limit
                }
            ]
        )
        results = []
        for doc in docs:
            results.append(jsonify(doc))
        return results

@api.route('/traits/<collection>/<limit>/<page>')
class mongodb_traits(Resource):
    def post(self, collection, limit, page):
        """Get Traits by Trait String"""
        try:
            if collection not in ['default', 'malware', 'goodware']:
                return {
                    'error': 'collection not supported'
                }, 400
            data = json.loads(request.data)
            cursor = app.config['mongodb_db'][collection]
            docs = cursor.aggregate(
            [
                {
                        "$match": data
                    },
                    {
                        "$lookup": {
                            "from": 'files',
                            "localField": "_id",
                            "foreignField": "trait_id",
                            "as": "files"
                        }
                    }
                ]
            )
            results = []
            for doc in docs:
                results.append(jsonify(doc))
            return results
        except Exception as error:
            return {
                'error': str(error)
            }, 400
