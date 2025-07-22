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

    def upload(self, bucket_name: str, data: bytes | dict, object_name: str, content_type='application/octet-stream') -> str:
        if not isinstance(data, bytes) and not isinstance(data, dict):
            raise ValueError('data must be of type bytes or dict')

        if isinstance(data, dict):
            data = json.dumps(data).encode()

        self.create_bucket(bucket_name)

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

    def delete(self, bucket_name: str, object_name: str):
        self.client.remove_object(bucket_name, object_name)
