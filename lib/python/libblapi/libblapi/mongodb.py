#!/usr/bin/env python

import ssl
import json
import urllib3
import pymongo
from bson import json_util
from bson.objectid import ObjectId

class MongoDBHandler():

    """
    Binlex MongoDB Handler
    """

    def __init__(self, config):
        if config['mongodb'].getboolean('tls') is True:
            self.mongodb = pymongo.MongoClient(
                config['mongodb'].get('url'),
                tls=config['mongodb'].getboolean('tls'),
                tlsCAFile=config['mongodb'].get('ca'),
                tlsCertificateKeyFile=config['mongodb'].get('key'))
        else:
            self.mongodb = pymongo.MongoClient(config['mongodb'].get('url'))
        self.cursor = self.mongodb[config['mongodb'].get('db')]

    @staticmethod
    def jsonify(data):
        return json.loads(json.dumps(data, default=json_util.default))

    def query_files(self, query, corpus, limit, page):
        docs = self.cursor.aggregate(
           [
               {
                    "$match": query
                },
                {
                    "$lookup": {
                        "from": corpus,
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
            results.append(self.jsonify(doc))
        return results

    def query_doc_id(self, collection, id):
        cursor = self.cursor[collection]
        result = cursor.find_one({'_id': ObjectId(id)})
        return self.jsonify(result)

    def stats_collection_count(self, collection):
        cursor = self.cursor[collection]
        count = cursor.count_documents({})
        return count

    def upsert_trait(self, data, collection):
        cursor = self.cursor[collection]
        trait_id = cursor.update_one(
            filter={
                'architecture': data['architecture'],
                'bytes_sha256': data['bytes_sha256']
            },
            update={
                "$set": data
            },
            upsert=True
        ).upserted_id
        if trait_id is None:
            trait_id = cursor.find_one({
                'architecture': data['architecture'],
                'bytes_sha256': data['bytes_sha256']
            })['_id']
        return trait_id

    def upsert_file_trait(self, data, trait_id):
        cursor = self.cursor['files']
        files_id = cursor.update_one(
            filter={
                'collection': data['collection'],
                'sha256': data['sha256'],
                'mode': data['mode'],
                'trait_id': trait_id
            },
            update={
                "$set": data
            },
            upsert=True
        ).upserted_id
<<<<<<< HEAD
        return files_id
=======
        return files_id
>>>>>>> blserver
