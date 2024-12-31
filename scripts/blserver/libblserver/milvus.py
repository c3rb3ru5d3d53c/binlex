#!/usr/bin/env python

import json
import hashlib
from libblserver import BinlexVectorEmbedding
import struct
from torch import tensor
from torch import float32
from torch.nn import CosineSimilarity
from typing import List
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
from torch.nn import functional

class BinlexMilvus:
    def __init__(self, config: dict, database=None):
        """
        Initialize a Milvus connection and ensure our collection
        (with proper fields & indexes) is ready to use.
        """
        self.config = config
        self.connect(database=database)
        #self._init_collection()

    def connect(self, database=None):
        """
        Establish a connection to the Milvus server.
        """
        if database is None:
            database = self.config['milvus']['database']

        connections.connect(
            alias='default',
            db_name=database,
            host=self.config['milvus']['host'],
            port=str(self.config['milvus']['port']),
            token=f'{self.config["milvus"]["authentication"]["username"]}:{self.config["milvus"]["authentication"]["password"]}',
        )

        for database in self.config['milvus']['databases']:
            if database not in db.list_database():
                db.create_database(database)

        self._init_collection()

    def list_databases(self) -> list:
        return db.list_database()

    def load_collection(self, collection_name: str) -> Collection:
        if not has_collection(collection_name):
            raise ValueError(f"Collection '{collection_name}' does not exist.")
        collection =  Collection(name=collection_name)
        collection.load()
        return collection

    # def _init_collection(self) -> Collection:
    #     """
    #     Create or retrieve the Milvus collection with the appropriate schema and indexes.
    #     """
    #     # Define schema
    #     fields = [
    #         FieldSchema(
    #             name='id',
    #             dtype=DataType.VARCHAR,
    #             max_length=64,
    #             is_primary=True
    #         ),
    #         FieldSchema(
    #             name='sample_sha256',
    #             dtype=DataType.BINARY_VECTOR,
    #             dim=256,
    #         ),
    #         FieldSchema(
    #             name='vector_sha256',
    #             dtype=DataType.BINARY_VECTOR,
    #             dim=256,
    #         ),
    #         FieldSchema(
    #             name='uuid',
    #             dtype=DataType.BINARY_VECTOR,
    #             dim=512,
    #         ),
    #         FieldSchema(
    #             name='vector',
    #             dtype=DataType.FLOAT_VECTOR,
    #             dim=self.config['milvus']['dimensions']['output']
    #         ),
    #     ]

    #     schema = CollectionSchema(
    #         fields,
    #         description="Collection with vector, JSON, and SHA256 ID"
    #     )

    #     collection_name = 'functions'
    #     if not has_collection(collection_name):
    #         collection = Collection(name=collection_name, schema=schema)

    #         # Create indexes
    #         index_params = {
    #             "index_type": "IVF_PQ",
    #             "metric_type": "L2",
    #             "params": {"nlist": 2048, "m": 8, "nbits": 8}
    #         }
    #         collection.create_index(field_name="vector", index_params=index_params)

    #         collection.create_index(
    #             field_name="sample_sha256",
    #             index_params={
    #                 "index_type": "BIN_IVF_FLAT",
    #                 "metric_type": "HAMMING",
    #                 "params": {"nlist": 128}
    #             }
    #         )

    #         collection.create_index(
    #             field_name="vector_sha256",
    #             index_params={
    #                 "index_type": "BIN_IVF_FLAT",
    #                 "metric_type": "HAMMING",
    #                 "params": {"nlist": 128}
    #             }
    #         )

    #         collection.create_index(
    #             field_name="uuid",
    #             index_params={
    #                 "index_type": "BIN_IVF_FLAT",
    #                 "metric_type": "HAMMING",
    #                 "params": {"nlist": 128}
    #             }
    #         )

    #     else:
    #         collection = Collection(name=collection_name)

    #     collection_name = 'blocks'
    #     if not has_collection(collection_name):
    #         collection = Collection(name=collection_name, schema=schema)

    #         index_params = {
    #             "index_type": "IVF_PQ",
    #             "metric_type": "L2",
    #             "params": {"nlist": 2048, "m": 8, "nbits": 8}
    #         }
    #         collection.create_index(field_name="vector", index_params=index_params)

    #         collection.create_index(
    #             field_name="sample_sha256",
    #             index_params={
    #                 "index_type": "BIN_IVF_FLAT",
    #                 "metric_type": "HAMMING",
    #                 "params": {"nlist": 128}
    #             }
    #         )

    #         collection.create_index(
    #             field_name="vector_sha256",
    #             index_params={
    #                 "index_type": "BIN_IVF_FLAT",
    #                 "metric_type": "HAMMING",
    #                 "params": {"nlist": 128}
    #             }
    #         )

    #         collection.create_index(
    #             field_name="uuid",
    #             index_params={
    #                 "index_type": "BIN_IVF_FLAT",
    #                 "metric_type": "HAMMING",
    #                 "params": {"nlist": 128}
    #             }
    #         )

    #     else:
    #         collection = Collection(name=collection_name)

    #     return True

    def _init_collection(self) -> Collection:
        """
        Create or retrieve the Milvus collection with the appropriate schema and indexes,
        and add partitions 'amd64' and 'i386' to each.
        """
        # Define schema
        fields = [
            FieldSchema(
                name='id',
                dtype=DataType.VARCHAR,
                max_length=64,
                is_primary=True
            ),
            FieldSchema(
                name='sample_sha256',
                dtype=DataType.BINARY_VECTOR,
                dim=256,
            ),
            FieldSchema(
                name='vector_sha256',
                dtype=DataType.BINARY_VECTOR,
                dim=256,
            ),
            FieldSchema(
                name='uuid',
                dtype=DataType.BINARY_VECTOR,
                dim=512,
            ),
            FieldSchema(
                name='vector',
                dtype=DataType.FLOAT_VECTOR,
                dim=self.config['milvus']['dimensions']['output']
            ),
        ]

        schema = CollectionSchema(
            fields,
            description="Collection with vector, JSON, and SHA256 ID"
        )

        # Helper function to create or load a collection,
        # then create partitions "amd64" and "i386" if they do not exist.
        def create_or_load_collection_with_partitions(collection_name: str):
            if not has_collection(collection_name):
                collection = Collection(name=collection_name, schema=schema)

                # Create indexes
                index_params = {
                    "index_type": "IVF_PQ",
                    "metric_type": "L2",
                    "params": {"nlist": 2048, "m": 8, "nbits": 8}
                }
                collection.create_index(field_name="vector", index_params=index_params)

                collection.create_index(
                    field_name="sample_sha256",
                    index_params={
                        "index_type": "BIN_IVF_FLAT",
                        "metric_type": "HAMMING",
                        "params": {"nlist": 128}
                    }
                )

                collection.create_index(
                    field_name="vector_sha256",
                    index_params={
                        "index_type": "BIN_IVF_FLAT",
                        "metric_type": "HAMMING",
                        "params": {"nlist": 128}
                    }
                )

                collection.create_index(
                    field_name="uuid",
                    index_params={
                        "index_type": "BIN_IVF_FLAT",
                        "metric_type": "HAMMING",
                        "params": {"nlist": 128}
                    }
                )

            else:
                # If the collection already exists, just load it
                collection = Collection(name=collection_name)

            # Create the partitions if they don't already exist
            for partition_name in self.config['milvus']['partitions']:
                if not collection.has_partition(partition_name):
                    collection.create_partition(partition_name)

            return collection

        # Create or load `functions` collection and its partitions
        create_or_load_collection_with_partitions("functions")
        # Create or load `blocks` collection and its partitions
        create_or_load_collection_with_partitions("blocks")

        return True

    @staticmethod
    def _sha256_of_vector(float_list):
        """
        Given a list of floats (the GNN vector), compute its SHA256 hash in hex.
        """
        binary_data = b''.join(struct.pack('f', num) for num in float_list)
        hash_object = hashlib.sha256(binary_data)
        return hash_object.hexdigest()

    @staticmethod
    def _sha256_to_vector(hash_hex):
        """
        Convert a hex SHA256 digest into a 256-bit (32-byte) binary vector
        for insertion into a BINARY_VECTOR field in Milvus.
        """
        # Convert hex string -> binary string -> bytes(32)
        binary_string = bin(int(hash_hex, 16))[2:].zfill(256)
        binary_bytes = int(binary_string, 2).to_bytes(32, byteorder='big')
        return binary_bytes

    @staticmethod
    def _get_sample_sha256(data: dict) -> str | None:
        """
        Retrieve the file-type attribute's sha256 from the data, if it exists.
        """
        if data['attributes'] is None:
            return None
        for attribute in data['attributes']:
            if attribute['type'] != 'file':
                continue
            if attribute['sha256'] is None:
                continue
            return attribute['sha256']
        return None

    def get_partition_names(self, database: str, collection_name: str) -> list:
        self.connect(database=database)
        collection = Collection(name=collection_name)
        partitions = collection.partitions
        return [partition.name for partition in partitions]

    def get_collection_names(self, database: str) -> list[str]:
        self.connect(database=database)
        collection_names = utility.list_collections()
        return collection_names

    def index_vector(
        self,
        minio_client,
        database: str,
        collection_name: str,
        partition_name: str,
        vector: list[float],
        data: dict | bytes,
    ):
        if not partition_name or not isinstance(partition_name, str):
            raise ValueError("A valid 'partition_name' (string) must be provided.")

        self.connect(database=database)

        collection = self.load_collection(collection_name=collection_name)

        sample_sha256 = self._get_sample_sha256(data)
        if sample_sha256 is None:
            print('Missing sample sha256')
            return None

        # Upload the JSON data to Minio, returns the object SHA256
        id_sha256 = minio_client.upload(self.config['minio']['bucket'], data)

        # Check if there's already a record with this object ID in the specified partition
        expr = f"id == '{id_sha256}'"
        query_kwargs = {
            "expr": expr,
            "output_fields": ["id"],
            "partition_names": [partition_name],  # Query within the specified partition
        }
        results = collection.query(**query_kwargs)
        if results:
            print(f"Duplicate found for ID: {id_sha256}, Skipping insertion.")
            return None

        # Compute vector SHA256 and convert to BINARY_VECTOR
        vector_sha256 = self._sha256_of_vector(vector)
        sample_sha256_vector = self._sha256_to_vector(sample_sha256)
        vector_sha256_vector = self._sha256_to_vector(vector_sha256)

        # Combine sample_sha256_vector and vector_sha256_vector for the "uuid" field
        uuid = sample_sha256_vector + vector_sha256_vector

        # Check for duplicates by the combined "uuid" field in the specified partition
        search_kwargs = {
            "data": [uuid],
            "anns_field": "uuid",
            "param": {"metric_type": "HAMMING", "params": {"nprobe": 10}},
            "limit": 1,
            "output_fields": ["id"],
            "partition_names": [partition_name],  # Search within the specified partition
        }
        uuid_results = collection.search(**search_kwargs)

        # If distance == 0, that means it’s an exact match -> skip
        if uuid_results and uuid_results[0] and uuid_results[0][0].distance == 0:
            print("Duplicate found for UUID, Skipping insertion.")
            return None

        # Insert the data into the specified partition
        insert_data = [
            [id_sha256],
            [sample_sha256_vector],
            [vector_sha256_vector],
            [uuid],
            [vector],
        ]
        insert_result = collection.insert(insert_data, partition_name=partition_name)
        print(f"Inserted data with ID: {id_sha256} into partition: {partition_name}")
        return insert_result

    # def index_vector(
    #     self,
    #     minio_client,
    #     database: str,
    #     collection_name: str,
    #     vector: list[float],
    #     data: dict):
    #     self.connect(database=database)

    #     collection = self.load_collection(collection_name=collection_name)

    #     sample_sha256 = self._get_sample_sha256(data)
    #     if sample_sha256 is None:
    #         print('Missing sample sha256')
    #         return None

    #     # Upload the JSON data to Minio, returns the object SHA256
    #     id_sha256 = minio_client.upload(self.config['minio']['bucket'], data)

    #     # Check if there's already a record with this object ID
    #     expr = f"id == '{id_sha256}'"
    #     results = collection.query(expr=expr, output_fields=['id'])
    #     if results:
    #         print(f"Duplicate found for ID: {id_sha256}, Skipping insertion.")
    #         return None

    #     # Compute vector SHA256 and convert to BINARY_VECTOR
    #     vector_sha256 = self._sha256_of_vector(vector)
    #     sample_sha256_vector = self._sha256_to_vector(sample_sha256)
    #     vector_sha256_vector = self._sha256_to_vector(vector_sha256)

    #     # Combine sample_sha256_vector and vector_sha256_vector for the "uuid" field
    #     uuid = sample_sha256_vector + vector_sha256_vector

    #     # Check for duplicates by the combined "uuid" field
    #     uuid_results = collection.search(
    #         data=[uuid],
    #         anns_field='uuid',
    #         param={"metric_type": "HAMMING", "params": {"nprobe": 10}},
    #         limit=1,
    #         output_fields=["id"]
    #     )

    #     # If distance == 0, that means it’s an exact match -> skip
    #     if uuid_results and uuid_results[0] and uuid_results[0][0].distance == 0:
    #         print("Duplicate found for UUID, Skipping insertion.")
    #         return None

    #     # Insert the data
    #     insert_data = [
    #         [id_sha256],
    #         [sample_sha256_vector],
    #         [vector_sha256_vector],
    #         [uuid],
    #         [vector],
    #     ]
    #     insert_result = collection.insert(insert_data)
    #     print(f"Inserted data with ID: {id_sha256}")
    #     return insert_result

    def search_vector(
        self,
        minio_client,
        database: str,
        collection_name: str,
        partition_names: List[str],
        float_vector: list[float],
        top_k: int = 3,
        similarity_threshold: float = 0.75,
    ) -> List[BinlexVectorEmbedding]:
        if not isinstance(partition_names, list):
            raise ValueError("'partition_names' must be a list of strings.")
        if not all(isinstance(p, str) for p in partition_names):
            raise ValueError("All elements in 'partition_names' must be strings.")

        self.connect(database=database)

        collection = self.load_collection(collection_name=collection_name)

        # Prepare search parameters
        search_kwargs = {
            "data": [float_vector],
            "anns_field": "vector",
            "param": {"metric_type": "L2", "params": {"nprobe": 10}},
            "limit": top_k,
            "output_fields": ["vector", "id"]
        }
        if partition_names:  # If list is not empty, restrict search to specified partitions
            search_kwargs["partition_names"] = partition_names

        results = collection.search(**search_kwargs)

        if not results or not results[0]:
            return []

        query_tensor = tensor(float_vector, dtype=float32)
        embeddings = []
        for hit in results[0]:
            retrieved_vector = hit.entity.get("vector")
            retrieved_tensor = tensor(retrieved_vector, dtype=float32)
            similarity = functional.cosine_similarity(query_tensor, retrieved_tensor, dim=0).item()

            # Skip if similarity is below threshold
            if similarity < similarity_threshold:
                continue

            # The Milvus 'id' field is the object name in Minio
            object_name = hit.entity.get("id")

            # Download bytes from Minio and parse as JSON
            object_bytes = minio_client.download("binlex", object_name)
            try:
                object_data = json.loads(object_bytes.decode("utf-8"))
            except json.JSONDecodeError as e:
                print(f"Failed to decode JSON for object '{object_name}': {e}")
                continue

            embedding = BinlexVectorEmbedding(
                vector=retrieved_vector,
                data=object_data
            )

            embeddings.append({
                'similarity': similarity,
                'embedding': embedding.to_dict(),
            })

        return embeddings


    # def search_vector(
    #     self,
    #     minio_client,
    #     database: str,
    #     collection_name: str,
    #     float_vector: list[float],
    #     top_k: int = 3,
    #     similarity_threshold: float = 0.75
    # ) -> List[BinlexVectorEmbedding]:
    #     self.connect(database=database)

    #     collection = self.load_collection(collection_name=collection_name)

    #     # Perform the search
    #     results = collection.search(
    #         data=[float_vector],
    #         anns_field='vector',
    #         param={"metric_type": "L2", "params": {"nprobe": 10}},
    #         limit=top_k,
    #         output_fields=["vector", "id"]  # We use 'id' to fetch data from Minio.
    #     )

    #     # Because we queried with one vector, results is a list of lists.
    #     # We want the first sub-list (the top_k results for our single query).
    #     if not results or not results[0]:
    #         return []

    #     # Convert the query vector to a PyTorch tensor
    #     query_tensor = tensor(float_vector, dtype=float32)

    #     # Initialize CosineSimilarity function
    #     #cosine_similarity = CosineSimilarity(dim=0)

    #     embeddings = []
    #     for hit in results[0]:
    #         # Get the vector from Milvus and convert it to a PyTorch tensor
    #         retrieved_vector = hit.entity.get("vector")
    #         retrieved_tensor = tensor(retrieved_vector, dtype=float32)

    #         # Compute cosine similarity
    #         #similarity = cosine_similarity(query_tensor, retrieved_tensor).item()
    #         similarity = functional.cosine_similarity(query_tensor, retrieved_tensor, dim=0).item()

    #         # Skip this result if it doesn't meet the similarity threshold
    #         if similarity < similarity_threshold:
    #             continue

    #         # The Milvus 'id' field is the object name in Minio
    #         object_name = hit.entity.get("id")

    #         # Download bytes from Minio
    #         object_bytes = minio_client.download("binlex", object_name)

    #         # Convert bytes -> str -> JSON
    #         try:
    #             object_data = json.loads(object_bytes.decode("utf-8"))
    #         except json.JSONDecodeError as e:
    #             print(f"failed to decode JSON for object '{object_name}': {e}")
    #             continue

    #         # Create a new BinlexVectorEmbedding object
    #         embedding = BinlexVectorEmbedding(
    #             vector=retrieved_vector,
    #             data=object_data
    #         )

    #         embeddings.append({
    #             'similarity': similarity,
    #             'embedding': embedding.to_dict(),
    #         })
    #         #embeddings.append(embedding)
    #     return embeddings
