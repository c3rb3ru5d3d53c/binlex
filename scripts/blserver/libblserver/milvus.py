#!/usr/bin/env python

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
    A class to manage vector embeddings and their relationships in Milvus,
    integrated with MinIO for data storage.
    """

    def __init__(self, config: Dict[str, Any], database: Optional[str] = None):
        """
        Initialize the BinlexMilvus instance.

        Parameters:
            config (Dict[str, Any]): Configuration dictionary containing Milvus and MinIO settings.
            database (Optional[str]): Name of the Milvus database to connect to. Defaults to config['milvus']['database'].
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
            'dimensions',
            'databases',
            'partitions'
        ]
        missing_keys = [key for key in required_milvus_keys if key not in self.config.get('milvus', {})]
        if missing_keys:
            raise KeyError(f"Missing Milvus configuration keys: {', '.join(missing_keys)}")

        required_auth_keys = ['username', 'password']
        missing_auth_keys = [key for key in required_auth_keys if key not in self.config['milvus']['authentication']]
        if missing_auth_keys:
            raise KeyError(f"Missing Milvus authentication keys: {', '.join(missing_auth_keys)}")

        if 'bucket' not in self.config.get('minio', {}):
            raise KeyError("Missing MinIO configuration key: 'bucket'")

    def connect(self, database: Optional[str] = None):
        """
        Establish a connection to the Milvus server.

        Parameters:
            database (Optional[str]): Name of the database to connect to. Defaults to the instance's database.
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
        primary_schema = self._create_primary_schema()
        relationships_schema = self._create_relationships_schema()

        for collection_name in self.config['milvus']['collections']:
            self._create_or_load_collection(collection_name, primary_schema)
        # self._create_or_load_collection('function', primary_schema)
        # self._create_or_load_collection('block', primary_schema)
        self._create_or_load_collection('relationships', relationships_schema)

    def _create_primary_schema(self) -> CollectionSchema:
        """
        Create the schema for primary collections ('functions' and 'blocks').

        Returns:
            CollectionSchema: The schema for the primary collections.
        """
        fields = [
            FieldSchema(name='uuid', dtype=DataType.VARCHAR, max_length=36, is_primary=True),
            FieldSchema(name='object', dtype=DataType.VARCHAR, max_length=64),
            FieldSchema(name='vector', dtype=DataType.FLOAT_VECTOR, dim=self.config['milvus']['dimensions']['output']),
        ]
        return CollectionSchema(fields=fields, description='Primary collection schema')

    def _create_relationships_schema(self) -> CollectionSchema:
        """
        Create the schema for the 'relationships' collection.

        Returns:
            CollectionSchema: The schema for the relationships collection.
        """
        fields = [
            FieldSchema(name='uuid', dtype=DataType.VARCHAR, max_length=36, is_primary=True),
            FieldSchema(name='sha256', dtype=DataType.VARCHAR, max_length=64),
            FieldSchema(name='vector', dtype=DataType.FLOAT_VECTOR, dim=self.config['milvus']['dimensions']['output']),
            FieldSchema(name='name', dtype=DataType.VARCHAR, max_length=512),
        ]
        return CollectionSchema(fields=fields, description='Relationships collection schema')

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
            self._create_indexes(collection, collection_name)
            self._create_partitions(collection)
        else:
            collection = self.load_collection(collection_name)
        return collection

    def _create_indexes(self, collection: Collection, collection_name: str):
        """
        Create indexes for the given collection based on its type.

        Parameters:
            collection (Collection): The Milvus collection.
            collection_name (str): Name of the collection.
        """
        if collection_name != 'relationships':
            index_params = {
                'index_type': 'IVF_PQ',
                'metric_type': 'IP',  # Inner Product for cosine similarity
                'params': {'nlist': 2048, 'm': 8, 'nbits': 8}
            }
            collection.create_index(field_name='vector', index_params=index_params)
        else:
            # Relationships collection
            float_index_params = {
                'index_type': 'IVF_PQ',
                'metric_type': 'IP',  # Inner Product for cosine similarity
                'params': {'nlist': 2048, 'm': 8, 'nbits': 8}
            }
            collection.create_index(field_name='vector', index_params=float_index_params)
            # No index needed for VARCHAR fields

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
        """
        Compute the SHA256 hash of a vector.

        Parameters:
            float_list (List[float]): The vector to hash.

        Returns:
            str: The SHA256 hash as a hexadecimal string.
        """
        binary_data = b''.join(struct.pack('f', num) for num in float_list)
        hash_object = hashlib.sha256(binary_data)
        return hash_object.hexdigest()

    def _derive_uuid(self, vector_sha256: str) -> str:
        """
        Derive a UUID based on the SHA256 hash of a vector.

        Parameters:
            vector_sha256 (str): SHA256 hash of the vector.

        Returns:
            str: The derived UUID.
        """
        NAMESPACE_UUID = uuid.UUID('12345678-1234-5678-1234-567812345678')
        return str(uuid.uuid5(NAMESPACE_UUID, vector_sha256))

    def _derive_combined_uuid(self, sha256: str, vector: List[float], name: str) -> str:
        """
        Derive a combined UUID based on SHA256, vector, and name.

        Parameters:
            sha256 (str): SHA256 hash.
            vector (List[float]): The vector.
            name (str): The name.

        Returns:
            str: The combined UUID.
        """
        NAMESPACE_UUID = uuid.UUID('87654321-4321-6789-4321-678987654321')
        vector_bytes = b''.join(struct.pack('f', num) for num in vector)
        vector_hash = hashlib.sha256(vector_bytes).hexdigest()
        name_combined = f'{sha256}:{vector_hash}:{name}'
        return str(uuid.uuid5(NAMESPACE_UUID, name_combined))

    def index_vector(
        self,
        minio_client,
        database: str,
        collection_name: str,
        partition_name: str,
        vector: List[float],
        data: Union[dict, bytes],
    ) -> Optional[Dict[str, Any]]:
        """
        Index a vector into the specified Milvus collection.

        Parameters:
            minio_client: MinIO client instance.
            database (str): Database name.
            collection_name (str): Collection to insert into.
            partition_name (str): Name of the partition within the collection.
            vector (List[float]): The vector to be indexed (assumed to be normalized).
            data (Union[dict, bytes]): Associated data to be stored in MinIO.

        Returns:
            Optional[Dict[str, Any]]: Inserted data dictionary or None if insertion failed.
        """

        self.connect(database=database)

        sha256 = self._get_sha256(data)
        if not sha256:
            print("SHA256 computation failed or returned None.")
            return None

        if collection_name == 'relationships':
            print("Invalid collection_name: 'relationships' is not allowed for indexing.")
            return None

        uuid_str = self._derive_uuid(self._sha256_of_vector(vector))

        primary_collection = self.load_collection(collection_name)

        existing_entry = primary_collection.query(
            expr=f"uuid == '{uuid_str}'",
            output_fields=["object"]
        )

        object_name = None
        if existing_entry:
            old_object_name = existing_entry[0]["object"]

            if old_object_name != object_name:
                object_name = self._upload_to_minio(minio_client, data)
                if not object_name:
                    print("Failed to upload new object to MinIO.")
                    return None

                try:
                    minio_client.delete(bucket_name=self.config['minio']['bucket'], object_name=old_object_name)
                except Exception as minio_err:
                    print(f"Failed to delete old object from MinIO: {minio_err}")
                    return None

                primary_collection.delete(expr=f"uuid == '{uuid_str}'")
            else:
                print("UUID conflict with identical object name. No action needed.")
                return None
        else:
            object_name = self._upload_to_minio(minio_client, data)
            if not object_name:
                print("Failed to upload object to MinIO.")
                return None

        try:
            insert_data = {
                "uuid": uuid_str,
                "object": object_name,
                "vector": vector
            }
            primary_collection.insert(insert_data, partition_name=partition_name)
        except MilvusException as e:
            print(f"Failed to insert vector into collection '{collection_name}': {e}")
            return None

        symbols_names = self._get_symbol_names(data)
        if len(symbols_names) > 0:
            relationships_collection = self.load_collection('relationships')
            relationships_insert_data = self._prepare_relationships_insert_data(sha256, vector, symbols_names)
            try:
                relationships_collection.insert(relationships_insert_data, partition_name=partition_name)
            except MilvusException as e:
                print(f"Failed to insert into relationships collection: {e}")
                return None

        return insert_data


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

    def _prepare_relationships_insert_data(self, sha256: str, vector: List[float], symbols_names: List[str]) -> Dict[str, List[Any]]:
        """
        Prepare data for inserting into the relationships collection.

        Parameters:
            sha256 (str): SHA256 hash for exact matching.
            vector (List[float]): The normalized vector.
            symbols_names (List[str]): List of symbol names associated with the vector.

        Returns:
            Dict[str, List[Any]]: Data dictionary ready for insertion into Milvus.
        """
        combined_uuids = [self._derive_combined_uuid(sha256, vector, name) for name in symbols_names]
        return {
            "uuid": combined_uuids,
            "sha256": [sha256] * len(symbols_names),
            "vector": [vector] * len(symbols_names),
            "name": symbols_names
        }

    def search_relationships(
        self,
        minio_client,
        database: str,
        partition_names: List[str],
        sha256: Optional[str] = None,
        name: Optional[str] = None,
        float_vector: Optional[List[float]] = None,
        similarity_threshold: float = 0.75,
        offset: int = 0,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Search relationships by vector similarity, sha256, and/or name within specified partitions.

        Parameters:
            minio_client: MinIO client instance.
            database (str): Database name.
            partition_names (List[str]): List of partition names to search within.
            sha256 (Optional[str]): SHA256 hash for exact matching.
            name (Optional[str]): Name for exact matching.
            float_vector (Optional[List[float]]): Vector for similarity search (assumed to be normalized).
            similarity_threshold (float): Minimum similarity (0.0 - 1.0).
            offset (int): Offset for pagination.
            limit (int): Maximum number of results to return.

        Returns:
            List[Dict[str, Any]]: Search results with similarity scores ranging from 0 to 1.
        """
        self.connect(database=database)

        relationships_collection = self.load_collection('relationships')
        filter_expr = self._build_relationships_filter(sha256, name)

        if float_vector:
            search_params = {
                "metric_type": "IP",
                "params": {"nprobe": 10}
            }
            search_results = self._perform_search(
                collection=relationships_collection,
                query_vectors=[float_vector],
                anns_field="vector",
                search_params=search_params,
                limit=limit,
                filter_expr=filter_expr,
                output_fields=['uuid', 'sha256', 'vector', 'name'],
                partition_names=partition_names  # Handle multiple partitions
            )
            return self._process_search_results(search_results, similarity_threshold)
        else:
            return self._query_relationships(
                collection=relationships_collection,
                filter_expr=filter_expr,
                limit=limit,
                offset=offset,
                partition_names=partition_names  # Handle multiple partitions
            )


    def search_vector(
        self,
        minio_client,
        database: str,
        collection_name: str,
        partition_names: List[str],
        float_vector: List[float],
        similarity_threshold: float = 0.75,
        offset: int = 0,
        limit: int = 10,
    ) -> List[dict]:
        """
        Search vectors in a specified collection by vector similarity.

        Parameters:
            minio_client: MinIO client instance.
            database (str): Database name.
            collection_name (str): Collection to search in.
            partition_names (List[str]): List of partition names to search within.
            float_vector (List[float]): Query vector for similarity search (assumed to be normalized).
            similarity_threshold (float): Minimum similarity (0.0 - 1.0).
            offset (int): Offset for pagination.
            limit (int): Maximum number of results to return.

        Returns:
            List[dict]: Search results with similarity scores ranging from 0 to 1.
                        Each dictionary contains:
                            - uuid: Unique identifier of the hit.
                            - similarity: Similarity score between 0 and 1.
                            - vector: The retrieved vector.
                            - data: The associated data retrieved from MinIO.
        """
        self._validate_search_vector_params(partition_names, offset, limit)
        collection = self.load_collection(collection_name)

        search_params = {
            "metric_type": "IP",
            "params": {"nprobe": 10}
        }
        search_kwargs = {
            "data": [float_vector],
            "anns_field": "vector",
            "param": search_params,
            "limit": limit,
            "output_fields": ["uuid", "object", "vector"]
        }
        if partition_names:
            search_kwargs["partition_names"] = partition_names

        search_results = self._perform_search(
            collection=collection,
            query_vectors=[float_vector],
            anns_field="vector",
            search_params=search_params,
            limit=limit,
            filter_expr=None,
            output_fields=["uuid", "object", "vector"],
            partition_names=partition_names
        )
        return self._process_search_vector_results(search_results, minio_client, similarity_threshold, offset, limit)

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

    def _perform_search(
        self,
        collection: Collection,
        query_vectors: List[List[float]],
        anns_field: str,
        search_params: Dict[str, Any],
        limit: int,
        filter_expr: Optional[str],
        output_fields: List[str],
        partition_names: Optional[List[str]] = None
    ) -> Optional[List[List[Any]]]:
        """
        Perform a search on the given collection with specified parameters.

        Parameters:
            collection (Collection): Milvus collection to search in.
            query_vectors (List[List[float]]): List of query vectors.
            anns_field (str): Field name for approximate nearest neighbors.
            search_params (Dict[str, Any]): Search parameters.
            limit (int): Number of results to return.
            filter_expr (Optional[str]): Filter expression for the search.
            output_fields (List[str]): Fields to return in the search results.
            partition_names (Optional[List[str]]): Specific partitions to search within.

        Returns:
            Optional[List[List[Any]]]: Nested list of search hits or None if search failed.
        """
        try:
            return collection.search(
                data=query_vectors,
                anns_field=anns_field,
                param=search_params,
                limit=limit,
                expr=filter_expr,
                output_fields=output_fields,
                partition_names=partition_names
            )
        except MilvusException as e:
            print(f"Search failed: {e}")
            return None

    def _process_search_results(self, search_results: Optional[List[List[Any]]], similarity_threshold: float) -> List[Dict[str, Any]]:
        """
        Process search results for the search_relationships method.

        Parameters:
            search_results (Optional[List[List[Any]]]): Raw search results from Milvus.
            similarity_threshold (float): Minimum similarity to include in results.

        Returns:
            List[Dict[str, Any]]: Processed search results.
        """
        if not search_results or not search_results[0]:
            return []

        results = []
        for hits in search_results:
            for hit in hits:
                similarity = self._map_similarity(hit.score)
                if similarity >= similarity_threshold:
                    results.append({
                        "uuid": hit.entity.get("uuid"),
                        "sha256": hit.entity.get("sha256"),
                        "vector": hit.entity.get("vector"),
                        "name": hit.entity.get("name"),
                        "similarity": similarity
                    })
        return results

    def _process_search_vector_results(
        self,
        search_results: Optional[List[List[Any]]],
        minio_client,
        similarity_threshold: float,
        offset: int,
        limit: int
    ) -> List[dict]:
        """
        Process search results for the search_vector method.

        Parameters:
            search_results (Optional[List[List[Any]]]): Raw search results from Milvus.
            minio_client: MinIO client instance.
            similarity_threshold (float): Minimum similarity to include in results.
            offset (int): Offset for pagination.
            limit (int): Maximum number of results to return.

        Returns:
            List[dict]: Processed search results.
        """
        if not search_results or not search_results[0]:
            return []

        hits_above_threshold = []
        for hits in search_results:
            for hit in hits:
                similarity = self._map_similarity(hit.score)
                if similarity < similarity_threshold:
                    continue

                uuid = hit.entity.get("uuid")
                retrieved_vector = hit.entity.get("vector")
                object_name = hit.entity.get("object")

                data = self._retrieve_data_from_minio(minio_client, object_name)
                if data is None:
                    continue

                hits_above_threshold.append({
                    "uuid": uuid,
                    "similarity": similarity,
                    "vector": retrieved_vector,
                    "data": data
                })

        return hits_above_threshold[offset:offset + limit]

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

    def _map_similarity(self, score: float) -> float:
        """
        Map cosine similarity from [-1, 1] to [0, 1].

        Parameters:
            score (float): Raw similarity score.

        Returns:
            float: Mapped similarity score.
        """
        return (score + 1) / 2

    def _query_relationships(
        self,
        collection: Collection,
        filter_expr: Optional[str],
        limit: int,
        offset: int,
        partition_names: Optional[List[str]] = None,  # New parameter
    ) -> List[Dict[str, Any]]:
        """
        Perform a simple query on the relationships collection without vector similarity, within specified partitions.

        Parameters:
            collection (Collection): Milvus relationships collection.
            filter_expr (Optional[str]): Filter expression for the query.
            limit (int): Number of results to return.
            offset (int): Offset for pagination.
            partition_names (Optional[List[str]]): List of partition names to restrict the query.

        Returns:
            List[Dict[str, Any]]: Query results with similarity set to None.
        """
        try:
            query_kwargs = {
                "expr": filter_expr,
                "output_fields": ['uuid', 'sha256', 'vector', 'name'],
                "limit": limit,
                "offset": offset
            }
            if partition_names:
                query_kwargs["partition_names"] = partition_names

            query_results = collection.query(**query_kwargs)
            return [
                {
                    "uuid": result.get("uuid"),
                    "sha256": result.get("sha256"),
                    "vector": result.get("vector"),
                    "name": result.get("name"),
                    "similarity": None
                }
                for result in query_results
            ]
        except MilvusException as e:
            print(f"Query failed: {e}")
            return []


    def _build_relationships_filter(self, sha256: Optional[str], name: Optional[str]) -> Optional[str]:
        """
        Build a filter expression for querying relationships.

        Parameters:
            sha256 (Optional[str]): SHA256 hash for exact matching.
            name (Optional[str]): Name for exact matching.

        Returns:
            Optional[str]: Filter expression or None if no filters are applied.
        """
        expressions = []
        if sha256:
            expressions.append(f"sha256 == '{sha256}'")
        if name:
            safe_name = name.replace("'", "\\'")
            expressions.append(f"name == '{safe_name}'")
        return ' AND '.join(expressions) if expressions else None

    def _get_sha256(self, data: Union[dict, bytes]) -> Optional[str]:
        """
        Extract or compute the SHA256 hash from the provided data.

        Parameters:
            data (Union[dict, bytes]): Data from which to extract the SHA256 hash.

        Returns:
            Optional[str]: SHA256 hash string or None if extraction failed.
        """

        if isinstance(data, bytes):
            return hashlib.sha256(data).hexdigest()
        elif isinstance(data, dict) and 'sha256' in data:
            return hashlib.sha256(json.dumps(data).encode()).hexdigest()
        return None

    def _get_symbol_names(self, data: dict) -> list:
        """
        Extract symbol names from the provided data.

        Parameters:
            data (Union[dict, bytes]): Data from which to extract symbol names.

        Returns:
            Optional[List[str]]: List of symbol names or None if extraction failed.
        """
        names = []
        for attribute in data['attributes']:
            if 'type' not in attribute: continue
            if attribute['type'] != 'symbol': continue
            if 'name' not in attribute: continue
            if attribute['name'] is None: continue
            names.append(attribute['name'])
        return names
