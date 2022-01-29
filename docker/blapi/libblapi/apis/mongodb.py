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
from libblapi.auth import require_user, require_admin

api = Namespace('mongodb', description='Binlex MongoDB API')

def jsonify(data):
    return json.loads(json.dumps(data, default=json_util.default))

@api.route('/version')
class mongodb_collection_count(Resource):
    @require_user
    def get(self):
        """Get MongoDB Version"""
        return {
            'version': pymongo.__version__
        }

@api.route('/stats/<collection>/count')
class mongodb_collection_count(Resource):
    @require_user
    def get(self, collection):
        """Get Collection Document Count"""
        cursor = app.config['mongodb_db'][collection]
        count = cursor.count_documents({})
        return {
            'count': count
        }

@api.route('/docs/<collection>/<id>')
class mongodb_collection_id(Resource):
    @require_user
    def get(self, collection, id):
        """Get Collection Document by ID"""
        collection = app.config['mongodb_db'][collection]
        result = collection.find_one({'_id': ObjectId(id)})
        return jsonify(result)
