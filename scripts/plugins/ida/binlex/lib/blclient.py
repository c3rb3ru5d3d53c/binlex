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
