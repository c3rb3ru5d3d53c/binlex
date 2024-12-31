#!/usr/bin/env python

import json
import hashlib
from minio import Minio
from io import BytesIO

class BinlexMinio():
    def __init__(self, config: dict):
        self.client = Minio(
            f'{config["minio"]["host"]}:{config["minio"]["port"]}',
            config['minio']['keys']['access'],
            config['minio']['keys']['secret'],
            secure=config['minio']['secure'],
        )

    def create_bucket(self, bucket_name: str):
        if self.client.bucket_exists(bucket_name):
            return
        self.client.make_bucket(bucket_name)

    def upload(self, bucket_name: str, data: bytes | dict, content_type='application/octet-stream') -> str:
        if not isinstance(data, bytes) and not isinstance(data, dict):
            raise ValueError('data must be of type bytes or dict')

        if isinstance(data, dict):
            data = json.dumps(data).encode()

        self.create_bucket(bucket_name)
        object_name = hashlib.sha256(data).hexdigest()

        self.client.put_object(
            bucket_name,
            object_name,
            BytesIO(data),
            length=len(data),
            content_type=content_type,
        )

        return object_name

    def download(self, bucket_name: str, object_name: str) -> bytes:
        response = self.client.get_object(bucket_name, object_name)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()
