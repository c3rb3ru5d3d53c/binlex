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
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class BLClient():
    def __init__(self, url: str, api_key: str, verify=False):
        self.url = url
        self.api_key = api_key
        self.verify = verify

    def databases(self):
        r = requests.get(
            url=f'{self.url}/embeddings/databases',
            headers={
                'API-Key': self.api_key
            },
            verify=self.verify,
        )
        return r.status_code, json.loads(r.content)

    def inference(self, data: dict):
        r = requests.post(
            url=f'{self.url}/embeddings/inference',
            headers={
                'API-Key': self.api_key
            },
            json=data,
            verify=self.verify,
        )
        return r.status_code, json.loads(r.content)

    def collections(self, database: str):
        r = requests.get(
            url=f'{self.url}/embeddings/{database}/collections',
            headers={
                'API-Key', self.api_key
            },
            verify=self.verify,
        )
        return r.status_code, json.loads(r.content)

    def partitions(self, database: str, collection: str):
        r = requests.get(
            url=f'{self.url}/embeddings/{database}/{collection}/partitions',
            headers={
                'API-Key': self.api_key
            },
            verify=self.verify,
        )
        return r.status_code, json.loads(r.content)

    def index(self, database: str, collection: str, partition: str, data: dict):
        r = requests.post(
            url=f'{self.url}/embeddings/{database}/{collection}/{partition}/index',
            headers={
                'API-Key': self.api_key
            },
            json=data,
            verify=self.verify,
        )
        return r.status_code, json.loads(r.content)

    def search(
        self,
        database: str,
        collection: str,
        partition: str,
        offset: int,
        limit: int,
        threshold: float,
        vector: dict):
        r = requests.post(
            url=f'{self.url}/embeddings/{database}/{collection}/{partition}/search/{offset}/{limit}/{threshold}',
            headers={
                'API-Key': self.api_key
            },
            json=vector,
            verify=self.verify,
        )
        return r.status_code, json.loads(r.json())
