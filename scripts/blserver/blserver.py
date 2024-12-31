#!/usr/bin/env python

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
    if data['type'] != 'function': return False
    return True

def create_app(config: str) -> Flask:
    server_config = read_config(config)

    app = Flask(__name__)

    print('connecting to minio...')
    minio_client = BinlexMinio(server_config)
    print('connecting to milvus...')
    milvus_client = BinlexMilvus(server_config)

    def require_api_key(func):
        """Decorator to require an API key for endpoint access."""
        def wrapper(*args, **kwargs):
            api_key = request.headers.get('API-Key')
            if api_key not in server_config['blserver']['authentication']['api_keys']:
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

    @api.route('/embeddings/index/<string:database>')
    class BinlexServerEmbeddingsInsert(Resource):
        @require_api_key
        @api.expect(embedding_input_model, validate=True)
        @api.response(200, 'Success', embedding_response_model)
        @api.response(400, 'Invalid Input', error_response_model)
        @api.response(415, 'Unsupported Media Type', error_response_model)
        @api.response(500, 'Internal Server Error', error_response_model)
        @api.doc(description='Insert Embeddings')
        def post(self, database):
            try:
                data = json.loads(request.data)

                if not is_valid_data(data):
                    return json.dumps({'error': 'Invalid JSON data'}), 400

                gnn = BinlexGNN(
                    json.dumps(data),
                    block_pca_dim=server_config['milvus']['dimensions']['input'],
                    gnn_hidden_dim=server_config['milvus']['dimensions']['hidden'],
                    gnn_output_dim=server_config['milvus']['dimensions']['output'],
                )

                embedding = gnn.to_embedding()

                milvus_client.index_vector(
                    minio_client=minio_client,
                    database=database,
                    collection_name='functions',
                    vector=embedding.vector,
                    data=embedding.data
                )

                return json.dumps(embedding.vector), 200
            except Exception as e:
                return json.dumps({'error': str(e)}), 500

    @api.route('/embeddings/search/<string:database>')
    class BinlexServerEmbeddingsSearch(Resource):
        @require_api_key
        @api.expect(embedding_search_model, validate=True)
        @api.response(200, 'Success', fields.List(
            fields.Raw(
                description='List of search results with similarity scores'
            )
        ))
        @api.response(400, 'Invalid Input', error_response_model)
        @api.response(500, 'Internal Server Error', error_response_model)
        @api.doc(description='Search Embeddings')
        def post(self, database):
            try:
                request_data = json.loads(request.data)

                if not isinstance(request_data, list) or not all(isinstance(x, (int, float)) for x in request_data):
                    return json.dumps({'error': 'expected a list of float values'}), 400

                top_k = server_config['blserver']['similarity']['top_k']
                similarity_threshold = server_config['blserver']['similarity']['threshold']

                results = milvus_client.search_vector(
                    minio_client=minio_client,
                    database=database,
                    collection_name='functions',
                    float_vector=request_data,
                    top_k=top_k,
                    similarity_threshold=similarity_threshold
                )

                return json.dumps(results), 200
            except json.JSONDecodeError:
                return json.dumps({'error': 'Invalid JSON input'}), 400
            except Exception as e:
                return json.dumps({'error': str(e)}), 500

    @api.route('/embeddings/inference')
    class BinlexServerEmbeddingsInference(Resource):
        @require_api_key
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
                    return json.dumps({'error': 'invalid or unsupported input data'}), 400

                gnn = BinlexGNN(
                    json.dumps(request_data),
                    block_pca_dim=server_config['milvus']['dimensions']['input'],
                    gnn_hidden_dim=server_config['milvus']['dimensions']['hidden'],
                    gnn_output_dim=server_config['milvus']['dimensions']['output'],
                )

                embedding = gnn.to_embedding()

                return json.dumps(embedding.vector), 200
            except Exception as e:
                return json.dumps({'error': str(e)}), 500

    @api.route('/embeddings/database/list')
    class BinlexServerEmbeddingsInference(Resource):
        @require_api_key
        @api.doc(description='List Databases')
        def get(self):
            try:
                databases = milvus_client.list_databases()
                return json.dumps(databases), 200
            except Exception as e:
                return json.dumps({'error': str(e)}), 500

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
