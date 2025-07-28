#!/usr/bin/env python
# MIT License
#
# Copyright (c) [2025] [c3rb3ru5d3d53c]
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import json
import argparse
import tomllib
from flask import Flask, request, Response
from flask_restx import Resource, Api, fields
from libblserver import BinlexGNN, BinlexVectorEmbedding, BinlexMinio, BinlexMilvus

__author__ = 'c3rb3ru5d3d53c'
__version__ = '2.0.0'

def read_config(file_path: str) -> dict:
    try:
        with open(file_path, "rb") as file:
            return tomllib.load(file)
    except FileNotFoundError:
        raise FileNotFoundError(f"The file at {file_path} does not exist.")
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"Error decoding TOML: {e}")

def is_valid_data(data: dict) -> bool:
    if 'type' not in data: return False
    if 'architecture' not in data: return False
    if data['type'] not in ['function', 'block']: return False
    return True

def get_username_by_api_key(config: dict, api_key: str) -> str | None:
    for username, api_key in config['blserver']['authentication']['api_keys'].items():
        if api_key != api_key: continue
        return username

def create_app(config: str) -> Flask:
    server_config = read_config(config)

    app = Flask(__name__)

    minio_client = BinlexMinio(server_config)
    milvus_client = BinlexMilvus(server_config)

    def require_user_api_key(func):
        """Decorator to require an API key for endpoint access."""
        def wrapper(*args, **kwargs):
            api_key = request.headers.get('API-Key')
            if get_username_by_api_key(server_config, api_key) is None or api_key is None:
                return Response(
                    response=json.dumps({'error': 'Unauthorized'}),
                    status=401,
                    mimetype='application/json'
                )
            return func(*args, **kwargs)
        return wrapper

    api = Api(
        app,
        title='Binlex Server',
        version=f'v{__version__}',
        description='A Binlex Server',
        doc='/swagger'
    )

    embedding_input_model = api.model(
        'EmbeddingInput',
        {
            'type': fields.String(
                required=True,
                description='The type of data to process, must be "function"',
                example='function'
            )
        }
    )

    embedding_search_model = api.model(
        'EmbeddingSearchInput',
        {
            'vector': fields.List(
                fields.Float,
                required=True,
                description='A list of float values representing the embedding vector to search',
                example=[0.1, 0.2, 0.3, 0.4]
            ),
            'query': fields.String(
                description='Query to send to Milvus database to filter results',
                example="file_sha256 != '2d66d000874a77e4c81f5ab34674fbc0bf5e28aac86ce07e5fd99aee1b84d244'"
            )
        }
    )
    
    embedding_query_database = api.model(
        'EmbeddingQueryDatabase',
        {
            'query': fields.String(
                description='Query to send to Milvus database',
                example="file_sha256 == '2d66d000874a77e4c81f5ab34674fbc0bf5e28aac86ce07e5fd99aee1b84d244' and address == 4411523"
            )
        }
    )

    embedding_response_model = api.model(
        'EmbeddingResponse',
        {
            'vector': fields.List(
                fields.Float,
                description='The resulting embedding vector',
                example=[0.1, 0.2, 0.3]
            ),
            'data': fields.Raw(
                description='Original data associated with the embedding',
                example={"key": "value"}
            )
        }
    )

    error_response_model = api.model(
        'ErrorResponse',
        {
            'error': fields.String(
                description='Error message explaining the issue',
                example='Invalid input: Missing "type" field'
            )
        }
    )

    @api.route('/embeddings/<string:database>/<string:collection>/<string:partition>/index')
    class BinlexServerEmbeddingsInsert(Resource):
        @require_user_api_key
        @api.expect(embedding_input_model, validate=True)
        @api.response(200, 'Success', embedding_response_model)
        @api.response(400, 'Invalid Input', error_response_model)
        @api.response(415, 'Unsupported Media Type', error_response_model)
        @api.response(500, 'Internal Server Error', error_response_model)
        @api.doc(description='Insert Embeddings')
        def post(self, database, collection, partition):
            try:
                data = json.loads(request.data)

                if not is_valid_data(data):
                    return {'error': 'Invalid JSON data'}, 400

                if database not in milvus_client.list_databases():
                    return {'error': 'database does not exist'}, 404

                if collection not in milvus_client.get_collection_names(database=database):
                    return {'error': 'unsupported collection'}, 404

                if partition not in milvus_client.get_partition_names(database=database, collection_name=collection):
                    return {'error': 'invalid or unsupported architecture for partition'}, 404

                if partition != data['architecture']:
                    return {'error': 'the architecture does not match the partition'}, 400

                if data['type'] not in ['block', 'function']:
                    return {'error': 'currently unsupported type'}, 400

                username = get_username_by_api_key(server_config, request.headers.get('API-Key'))

                if username is None:
                    return {'error': 'missing username, unauthorized'}, 401

                gnn = BinlexGNN(
                    data,
                    block_pca_dim=server_config['blserver']['gnn']['input'],
                    gnn_hidden_dim=server_config['blserver']['gnn']['hidden'],
                    gnn_output_dim=server_config['blserver']['gnn']['output'],
                )

                gnn.train(epochs=server_config['blserver']['gnn']['epochs'])

                embedding = gnn.to_embedding()
                
                result = milvus_client.index_vector(
                    minio_client=minio_client,
                    database=database,
                    collection_name=collection,
                    partition_name=partition,
                    vector=embedding.vector,
                    data=embedding.data,
                    username=username
                )

                if result is None:
                    return {'error': 'failed to index data'}, 400

                return json.dumps(result), 200
            except Exception as e:
                return {'error': str(e)}, 500

    @api.route('/embeddings/<string:database>/<string:collection>/<string:partitions>/query/<int:offset>/<int:limit>')
    class BinlexServerEmbeddingsQuery(Resource):
        @require_user_api_key
        @api.expect(embedding_query_database, validate=True)
        @api.response(200, 'Success', fields.List(
            fields.Raw(
                description='List of search results from the query sent'
            )
        ))
        @api.response(400, 'Invalid Input', error_response_model)
        @api.response(500, 'Internal Server Error', error_response_model)
        @api.doc(description='Search Embeddings')
        def post(self, database, collection, partitions, offset, limit):
            try:

                partitions = partitions.split('||')

                request_data = json.loads(request.data)

                if not isinstance(request_data, str):
                    return json.dumps({'error': 'expected a string'}), 400
                
                if database not in milvus_client.list_databases():
                    return json.dumps({'error': 'database does not exist'}), 404

                if collection not in milvus_client.get_collection_names(database=database):
                    return json.dumps({'error': 'unsupported collection'}), 404
                
                for partition in partitions:
                    if partition not in milvus_client.get_partition_names(database=database, collection_name='function'):
                        return json.dumps({'error': f'{partition} is an unsupported partition or architecture'}), 404

                results = milvus_client.query(
                    minio_client=minio_client,
                    database=database,
                    collection_name=collection,
                    partition_names=partitions,
                    query=request_data,
                    offset=offset,
                    limit=limit
                )
                return json.dumps(results), 200
            except json.JSONDecodeError:
                return json.dumps({'error': 'Invalid JSON input'}), 400
            except Exception as e:
                return json.dumps({'error': str(e)}), 500

    @api.route('/embeddings/<string:database>/<string:collection>/<string:partitions>/search/<int:offset>/<int:limit>/<float:threshold>')
    class BinlexServerEmbeddingsSearch(Resource):
        @require_user_api_key
        @api.expect(embedding_search_model, validate=True)
        @api.response(200, 'Success', fields.List(
            fields.Raw(
                description='List of search results with similarity scores'
            )
        ))
        @api.response(400, 'Invalid Input', error_response_model)
        @api.response(500, 'Internal Server Error', error_response_model)
        @api.doc(description='Search Embeddings')
        def post(self, database, collection, partitions, offset, limit, threshold):
            try:

                partitions = partitions.split('||')

                request_data = json.loads(request.data)

                if not isinstance(request_data["vector"], list) or not all(isinstance(x, (int, float)) for x in request_data["vector"]):
                    return json.dumps({'error': 'expected a list of float values'}), 400

                if database not in milvus_client.list_databases():
                    return json.dumps({'error': 'database does not exist'}), 404

                if collection not in milvus_client.get_collection_names(database=database):
                    return json.dumps({'error': 'unsupported collection'}), 404

                for partition in partitions:
                    if partition not in milvus_client.get_partition_names(database=database, collection_name=collection):
                        return json.dumps({'error': f'{partition} is an unsupported partition or architecture'}), 404

                results = milvus_client.search_vector(
                    minio_client=minio_client,
                    database=database,
                    collection_name=collection,
                    partition_names=partitions,
                    threshold=threshold,
                    float_vector=request_data["vector"],
                    query=request_data["query"],
                    offset=offset,
                    limit=limit
                )

                return json.dumps(results), 200
            except json.JSONDecodeError:
                return json.dumps({'error': 'Invalid JSON input'}), 400
            except Exception as e:
                return json.dumps({'error': str(e)}), 500

    @api.route('/embeddings/inference')
    class BinlexServerEmbeddingsInference(Resource):
        @require_user_api_key
        @api.expect(embedding_input_model, validate=True)
        @api.response(200, 'Success', embedding_response_model)
        @api.response(400, 'Invalid Input', error_response_model)
        @api.response(415, 'Unsupported Media Type', error_response_model)
        @api.response(500, 'Internal Server Error', error_response_model)
        @api.doc(description='Embedding Inference')
        def post(self):
            try:
                request_data = json.loads(request.data)

                if not is_valid_data(request_data):
                    return {'error': 'invalid or unsupported input data'}, 400

                gnn = BinlexGNN(
                    request_data,
                    block_pca_dim=server_config['blserver']['gnn']['input'],
                    gnn_hidden_dim=server_config['blserver']['gnn']['hidden'],
                    gnn_output_dim=server_config['blserver']['gnn']['output'],
                )

                gnn.train(epochs=server_config['blserver']['gnn']['epochs'])

                embedding = gnn.to_embedding()

                return embedding.vector, 200
            except Exception as e:
                return {'error': str(e)}, 500

    @api.route('/embeddings/databases')
    class BinlexEmbeddingsDatabases(Resource):
        @require_user_api_key
        @api.doc(description='List Databases')
        def get(self):
            try:
                databases = milvus_client.list_databases()
                return databases, 200
            except Exception as e:
                return {'error': str(e)}, 500

    @api.route('/embeddings/dimensions')
    class BinlexEmbeddingsDimensions(Resource):
        @require_user_api_key
        @api.doc(description='Get Embedding Dimensions')
        def get(self):
            try:
                return {
                    'input': server_config['blserver']['gnn']['input'],
                    'hidden': server_config['blserver']['gnn']['hidden'],
                    'output': server_config['blserver']['gnn']['output']
                }, 200
            except Exception as e:
                return {'error': str(e)}, 500

    @api.route('/authentication/whoami')
    class BinlexAuthenticationWhoami(Resource):
        @require_user_api_key
        @api.doc(description='Get Username')
        def get(self):
            try:
                api_key = request.headers.get('API-Key')
                username = get_username_by_api_key(server_config, api_key)
                if username is None:
                    return {'error': 'username not found'}, 404
                return {'username': username}, 200
            except Exception as e:
                return {'error': str(e)}, 500


    @api.route('/embeddings/<string:database>/collections')
    class BinlexEmbeddingsDatabaseCollections(Resource):
        @require_user_api_key
        @api.doc(description='List Database Collections')
        def get(self, database):
            try:
                if database not in milvus_client.list_databases():
                    return {'error': 'database does not exist'}, 404
                collections = milvus_client.get_collection_names(database=database)
                return collections, 200
            except Exception as e:
                return {'error': str(e)}, 500

    @api.route('/embeddings/<string:database>/<string:collection>/partitions')
    class BinlexEmbeddingsDatabaseCollectionPartitions(Resource):
        @require_user_api_key
        @api.doc(description='List Database Collection Partitions')
        def get(self, database, collection):
            try:
                if database not in milvus_client.list_databases():
                    return {'error': 'database does not exist'}, 404

                if collection not in milvus_client.get_collection_names(database=database):
                    return {'error': 'unsupported collection'}, 404

                partitions = milvus_client.get_partition_names(database=database, collection_name=collection)

                return partitions, 200
            except Exception as e:
                return {'error': str(e)}, 500

    print('server started')

    return app

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Binlex Server')
    parser.add_argument('--config', required=True, help='Configuration File Path')

    args = parser.parse_args()

    app = create_app(args.config)

    config = read_config(args.config)

    app.run(
        host=config['blserver']['host'],
        port=config['blserver']['port'],
        debug=config['blserver']['debug']
    )
