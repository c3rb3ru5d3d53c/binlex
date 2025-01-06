#!/usr/bin/env python

import re
import time
import json
import hashlib
import uuid
import struct
from typing import List, Optional, Dict, Any, Union
import sys

from pymilvus import (
    connections,
    FieldSchema,
    CollectionSchema,
    DataType,
    Collection,
    has_collection,
    utility,
    db,
)
from pymilvus.exceptions import MilvusException


class BinlexMilvus:
    """
    A class to manage vector embeddings in Milvus,
    integrated with MinIO for data storage.
    """

    def __init__(self, config: Dict[str, Any], database: Optional[str] = None):
        """
        Initialize the BinlexMilvus instance.

        Parameters:
            config (Dict[str, Any]): Configuration dictionary containing Milvus and MinIO settings.
            database (Optional[str]): Name of the Milvus database to connect to.
                Defaults to config['milvus']['database'].
        """
        self.config = config
        self.database = database or self.config['milvus']['database']
        self.connect(database=self.database)
        self._validate_config()
        self._init_collections()

    def list_databases(self) -> list:
        return db.list_database()

    def get_collection_names(self, database: str) -> list[str]:
        self.connect(database=database)
        collection_names = utility.list_collections()
        return collection_names

    def get_partition_names(self, database: str, collection_name: str) -> list:
        self.connect(database=database)
        collection = Collection(name=collection_name)
        partitions = collection.partitions
        return [partition.name for partition in partitions]

    def _validate_config(self):
        required_milvus_keys = [
            'database',
            'host',
            'port',
            'authentication',
            'databases',
            'partitions'
        ]
        missing_keys = [
            key for key in required_milvus_keys
            if key not in self.config.get('milvus', {})
        ]
        if missing_keys:
            raise KeyError(f"Missing Milvus configuration keys: {', '.join(missing_keys)}")

        required_auth_keys = ['username', 'password']
        missing_auth_keys = [
            key for key in required_auth_keys
            if key not in self.config['milvus']['authentication']
        ]
        if missing_auth_keys:
            raise KeyError(f"Missing Milvus authentication keys: {', '.join(missing_auth_keys)}")

        if 'bucket' not in self.config.get('minio', {}):
            raise KeyError("Missing MinIO configuration key: 'bucket'")

    def connect(self, database: Optional[str] = None):
        """
        Establish a connection to the Milvus server.

        Parameters:
            database (Optional[str]): Name of the database to connect to.
                Defaults to the instance's database.
        """
        database = database or self.database

        try:
            connections.connect(
                alias='default',
                db_name=database,
                host=self.config['milvus']['host'],
                port=str(self.config['milvus']['port']),
                token=(
                    f"{self.config['milvus']['authentication']['username']}:"
                    f"{self.config['milvus']['authentication']['password']}"
                ),
            )

            for db_name in self.config['milvus']['databases']:
                if db_name not in db.list_database():
                    db.create_database(db_name)
        except MilvusException as e:
            raise RuntimeError(f"Failed to connect to Milvus: {e}")

    def _init_collections(self):
        """
        Initialize collections by creating them if they don't exist.
        """
        primary_schema = self._create_primary_schema()

        for collection_name in self.config['milvus']['collections']:
            self._create_or_load_collection(collection_name, primary_schema)

    def _create_primary_schema(self) -> CollectionSchema:
        """
        Create the schema for the primary collections.

        Returns:
            CollectionSchema: The schema for the primary collections.
        """
        fields = [
            FieldSchema(name='id', dtype=DataType.VARCHAR, max_length=36, is_primary=True),
            FieldSchema(name='date', dtype=DataType.INT64),
            FieldSchema(name='username', dtype=DataType.VARCHAR, max_length=512),
            FieldSchema(name='object', dtype=DataType.VARCHAR, max_length=64),
            FieldSchema(name='sha256', dtype=DataType.VARCHAR, max_length=64),
            FieldSchema(
                name='vector',
                dtype=DataType.FLOAT_VECTOR,
                dim=self.config['blserver']['gnn']['output']
            ),
            FieldSchema(name='name', dtype=DataType.VARCHAR, max_length=512),
        ]
        return CollectionSchema(
            fields=fields,
            description='Primary collection schema'
        )

    def _create_or_load_collection(self, collection_name: str, schema: CollectionSchema) -> Collection:
        """
        Create a new collection with the given schema or load it if it already exists.

        Parameters:
            collection_name (str): Name of the collection.
            schema (CollectionSchema): Schema of the collection.

        Returns:
            Collection: The created or loaded collection.
        """
        if not has_collection(collection_name):
            collection = Collection(name=collection_name, schema=schema)
            self._create_indexes(collection)
            self._create_partitions(collection)
        else:
            collection = self.load_collection(collection_name)
        return collection

    def _create_indexes(self, collection: Collection):
        """
        Create indexes for the given collection.

        Parameters:
            collection (Collection): The Milvus collection.
        """
        index_params = {
            'index_type': 'IVF_PQ',
            'metric_type': 'COSINE',
            'params': {'nlist': 2048, 'm': 8, 'nbits': 8}
        }
        collection.create_index(field_name='vector', index_params=index_params)

    def _create_partitions(self, collection: Collection):
        """
        Create partitions within the given collection based on configuration.

        Parameters:
            collection (Collection): The Milvus collection.
        """
        for partition_name in self.config['milvus']['partitions']:
            if not collection.has_partition(partition_name):
                collection.create_partition(partition_name)

    def load_collection(self, collection_name: str) -> Collection:
        """
        Load an existing Milvus collection.

        Parameters:
            collection_name (str): Name of the collection to load.

        Returns:
            Collection: The loaded Milvus collection.
        """
        if not has_collection(collection_name):
            raise ValueError(f"Collection '{collection_name}' does not exist.")
        collection = Collection(name=collection_name)
        collection.load()
        return collection

    def _sha256_of_vector(self, float_list: List[float]) -> str:
        binary_data = b''.join(struct.pack('f', num) for num in float_list)
        hash_object = hashlib.sha256(binary_data)
        return hash_object.hexdigest()

    def _derive_uuid(self, strings: list) -> str:
        NAMESPACE_UUID = uuid.UUID('deadbeef-feed-face-feed-feedfacefeed')
        return str(uuid.uuid5(NAMESPACE_UUID, ''.join(strings)))

    def index_vector(
        self,
        minio_client,
        database: str,
        collection_name: str,
        partition_name: str,
        vector: List[float],
        data: Union[dict, bytes],
        username: str
    ) -> Optional[Dict[str, Any]]:
        """
        Insert a vector and its associated data into Milvus and MinIO.

        Parameters:
            minio_client: MinIO client instance.
            database (str): Name of the Milvus database.
            collection_name (str): Name of the Milvus collection.
            partition_name (str): Name of the partition in the collection.
            vector (List[float]): The vector to be inserted.
            data (Union[dict, bytes]): Related data to be stored in MinIO.
            username (str): Username responsible for the insert.

        Returns:
            Optional[Dict[str, Any]]: Inserted record(s) or None if failed.
        """
        self.connect(database=database)

        _object = self._sha256_of_vector(vector)
        if not _object:
            return None

        sha256 = self._get_file_sha256(data)
        if sha256 is None:
            return None

        names = self._get_symbol_names(data)

        primary_collection = self.load_collection(collection_name)

        existing_object = primary_collection.query(
            expr=f"object == '{_object}'",
            output_fields=["object"]
        )

        if not existing_object:
            minio_client.upload(
                self.config['minio']['bucket'],
                data,
                _object,
                content_type='application/json'
            )

        results = []

        if len(names) == 0:
            names.append('')

        for name in names:
            _uuid = self._derive_uuid([sha256, _object, name])

            existing_uuid = primary_collection.query(
                expr=f"id == '{_uuid}'",
                output_fields=["object"]
            )
            if existing_uuid:
                continue

            try:
                insert_data = {
                    "id": _uuid,
                    "date": int(time.time()),
                    "username": username,
                    "object": _object,
                    "sha256": sha256,
                    "vector": vector,
                    "name": name,
                }
                primary_collection.insert(insert_data, partition_name=partition_name)
                results.append(insert_data)
            except MilvusException as e:
                print(f"Failed to insert vector into collection '{collection_name}': {e}")
                return None

        return results

    def search_vector(
        self,
        minio_client,
        database: str,
        collection_name: str,
        partition_names: List[str],
        float_vector: List[float],
        threshold: float = 0.75,
        offset: int = 0,
        limit: int = 10,
    ) -> List[dict]:
        """
        Search vectors in a specified collection by COSINE similarity.

        Parameters:
            minio_client: MinIO client instance.
            database (str): Database name.
            collection_name (str): Collection to search in.
            partition_names (List[str]): List of partition names to search within.
            float_vector (List[float]): Query vector for similarity search.
            similarity_threshold (float): Minimum COSINE similarity in [-1, 1].
            offset (int): Offset for pagination.
            limit (int): Maximum number of results to return.

        Returns:
            List[dict]: Search results with raw COSINE scores from Milvus.
                        Each dictionary contains:
                            - uuid: Unique identifier of the hit (the "id" field).
                            - similarity: The COSINE similarity score [-1, 1].
                            - vector: The retrieved vector.
                            - data: The associated data from MinIO.
        """
        # Validate input
        self._validate_search_vector_params(partition_names, offset, limit)



        # Connect and load the collection
        self.connect(database=database)
        collection = self.load_collection(collection_name)

        # Use COSINE in the search parameters
        search_params = {
            "metric_type": "COSINE",
            "params": {"nprobe": 10}
        }

        top_k = offset + limit

        # Perform the search directly
        search_results = collection.search(
            data=[float_vector],
            anns_field="vector",
            param=search_params,
            limit=top_k,
            expr=None,
            output_fields=["id", "object", "vector"],
            partition_names=partition_names
        )

        # Handle empty or invalid results
        if not search_results or not search_results[0]:
            return []

        raw_hits = list(search_results[0])  # or .hits, depending on the PyMilvus version

        hits_above_threshold = [hit for hit in raw_hits if hit.score >= threshold]
        hits_slice = hits_above_threshold[offset:offset + limit]

        # 3) Download MinIO data and build output
        results = []
        for hit in hits_slice:
            # Retrieve fields we requested
            id_val = hit.entity.get("id")
            object_name = hit.entity.get("object")
            retrieved_vector = hit.entity.get("vector")

            # Basic sanity checks
            if not id_val or not object_name:
                continue

            # Download associated data from MinIO
            data = self._retrieve_data_from_minio(minio_client, object_name)
            if data is None:
                continue

            results.append({
                "id": id_val,
                "score": hit.score,
                "vector": retrieved_vector,
                "data": data
            })

        return results

    def _validate_search_vector_params(self, partition_names: List[str], offset: int, limit: int):
        """
        Validate parameters for the search_vector method.

        Raises:
            ValueError: If parameters do not meet the required criteria.
        """
        if not isinstance(partition_names, list):
            raise ValueError("'partition_names' must be a list of strings.")
        if not all(isinstance(p, str) for p in partition_names):
            raise ValueError("All elements in 'partition_names' must be strings.")

        if offset + limit > 128:
            raise ValueError(
                f"In a single search, offset + limit must be <= 128. "
                f"Got offset={offset}, limit={limit}, sum={offset + limit}."
            )

    def _retrieve_data_from_minio(self, minio_client, object_name: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve and parse data from MinIO.

        Parameters:
            minio_client: MinIO client instance.
            object_name (str): Name of the object to retrieve.

        Returns:
            Optional[Dict[str, Any]]: Parsed JSON data or None if retrieval failed.
        """
        try:
            object_bytes = minio_client.download(
                bucket_name=self.config["minio"]["bucket"],
                object_name=object_name
            )
            return json.loads(object_bytes.decode("utf-8"))
        except Exception as e:
            print(f"Failed to retrieve or decode object '{object_name}': {e}")
            return None

    def _get_data_sha256(self, data: Union[dict, bytes]) -> Optional[str]:
        """
        Compute the SHA-256 hash of data (bytes or dict).

        Parameters:
            data (Union[dict, bytes]): Data to hash.

        Returns:
            Optional[str]: The SHA-256 hex digest or None if data is invalid.
        """
        if isinstance(data, bytes):
            return hashlib.sha256(data).hexdigest()
        elif isinstance(data, dict):
            return hashlib.sha256(json.dumps(data).encode()).hexdigest()
        return None

    def _upload_to_minio(self, minio_client, data: Union[dict, bytes]) -> Optional[str]:
        """
        Upload data to MinIO and return the object name.

        Parameters:
            minio_client: MinIO client instance.
            data (Union[dict, bytes]): Data to be uploaded.

        Returns:
            Optional[str]: The name of the uploaded object or None if upload failed.
        """
        try:
            if isinstance(data, dict):
                data_bytes = json.dumps(data).encode('utf-8')
            else:
                data_bytes = data
            object_name = minio_client.upload(self.config['minio']['bucket'], data_bytes)
            return object_name
        except Exception as e:
            print(f"Failed to upload data to MinIO: {e}")
            return None

    def _get_symbol_names(self, data: dict) -> list:
        """
        Extract all symbol names from 'attributes' in the provided dict.

        Parameters:
            data (dict): The data containing attributes.

        Returns:
            list: A list of extracted symbol names.
        """
        names = []
        for attribute in data.get('attributes', []):
            if attribute.get('type') == 'symbol' and attribute.get('name'):
                # Skip Default Rizin, Binja, IDA an Ghidra Function Names
                if re.match(r'^(fcn\.|fun_|sub_)[0-9a-f]+$', attribute['name'], re.IGNORECASE): continue
                names.append(attribute['name'])
        return names

    def _get_file_sha256(self, data: dict) -> Optional[str]:
        """
        Extract the file SHA256 from 'attributes' in the provided dict.

        Parameters:
            data (dict): The data containing attributes.

        Returns:
            Optional[str]: The SHA256 string if found, else None.
        """
        if 'attributes' not in data:
            return None
        for attribute in data['attributes']:
            if attribute.get('type') == 'file':
                if 'sha256' in attribute:
                    return attribute['sha256']
        return None
