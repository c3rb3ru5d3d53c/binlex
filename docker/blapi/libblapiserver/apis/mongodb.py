#!/usr/bin/env python

import pymongo
from flask import Blueprint
from flask import current_app as app
from flask import request
from flask_restx import Namespace, Resource, fields
import json
from libblapiserver.auth import require_user, require_admin

api = Namespace('mongodb', description='Binlex MongoDB API')

@api.route('/version')
class mongodb_collection_count(Resource):
    @require_user
    def get(self):
        """Get MongoDB Version"""
        return {
            'version': pymongo.__version__
        }
