#!/usr/bin/env python

import pymongo
from flask import Blueprint
from flask import current_app as app
from flask_restx import Namespace, Resource, fields

api = Namespace('mongodb', description='Binlex MongoDB API')

@api.route('/version')
class mongodb_collection_count(Resource):
    def get(self):
        """Get MongoDB Version"""
        return {
            'version': pymongo.__version__
        }

@api.route('/<collection_name>/count')
class mongodb_collection_count(Resource):
    def get(self):
        """Get Collection Document Count"""
        return 'Placeholder'

@api.route('/<collection_name>/<id>')
class mongodb_collection_id(Resource):
    def get(self):
        """Get Collection Document by ID"""
        return 'Placeholder'

@api.route('/<collection_name>/find')
class mongodb_collection_find(Resource):
    def post(self):
        """Find Documents in a Collection"""
        return 'Placeholder'

@api.route('/<collection_name>/findOne')
class mongodb_collection_findOne(Resource):
    def post(self):
        """Find Single Document in Collection"""
        return 'Placeholder'

@api.route('/<collection_name>/aggregate')
class mongodb_collection_aggregate(Resource):
    def post(self):
        """Find Aggregate Data"""
        return 'Placeholder'