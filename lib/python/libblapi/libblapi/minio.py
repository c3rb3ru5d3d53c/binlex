#!/usr/bin/env python

import io
import urllib3
from minio import Minio
from hashlib import sha256

class MinIOHandler():

    """
    Binlex MinIO Handler
    """

    def __init__(self, config):
        self.buckets = ['default', 'malware', 'goodware', 'bldecomp']
        if config['minio'].getboolean('tls') is True:
            http_client = urllib3.PoolManager(
                    cert_reqs='CERT_REQUIRED',
                    ca_certs=config['minio'].get('ca'))
            self.cursor = Minio(
                config['minio'].get('host') + ':' + config['minio'].get('port'),
                access_key=config['minio'].get('user'),
                secret_key=config['minio'].get('pass'),
                secure=True,
                http_client=http_client)
        else:
            self.cursor = Minio(
                config['minio'].get('host') + ':' + config['minio'].get('port'),
                access_key=config['minio'].get('user'),
                secret_key=config['minio'].get('pass'))
        for bucket in self.buckets:
            if self.cursor.bucket_exists(bucket_name=bucket) is False:
                self.cursor.make_bucket(bucket_name=bucket)

    def validate_bucket(self, bucket_name):
        if bucket_name not in self.buckets:
            return False
        if self.cursor.bucket_exists(bucket_name=bucket_name) is False:
            return False
        return True

    def upload(self, bucket_name, data):
        if self.validate_bucket(bucket_name) is False:
            return False
        file_hash = sha256(data).hexdigest()
        if self.cursor.bucket_exists(bucket_name=bucket_name) is False:
            self.cursor.make_bucket(bucket_name=bucket_name)
        self.cursor.put_object(
            bucket_name=bucket_name,
            object_name=file_hash,
            data=io.BytesIO(data),
            length=len(data))

    def download(self, bucket_name, object_name):
        if self.validate_bucket(bucket_name) is False:
            return False
        data = self.cursor.get_object(
            bucket_name=bucket_name,
            object_name=object_name)
        return data

    def delete(self, bucket_name, object_name):
        if self.validate_bucket(bucket_name) is False:
            return False
        self.cursor.remove_object(
            bucket_name=bucket_name,
            object_name=object_name)
        return True