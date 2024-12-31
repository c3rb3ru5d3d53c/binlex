import requests

class BinlexHTTPClient():
    def __init__(self, url: str, api_key: str, verify=False):
        self.url = url
        self.api_key = api_key
        self.verify = verify

    def get_embeddings_databases(self):
        r = requests.get(
            url=f'{self.url}/embeddings/databases',
            headers={
                'API-Key', self.api_key
            },
            verify=self.verify,
        )
        r.status_code, r.json()

    def get_embeddings_database_collections(self, dataase: str):
        r = requests.get(
            url=f'{self.url}/embeddings/{database}/collections',
            headers={
                'API-Key', self.api_key
            },
            verify=self.verify,
        )
        r.status_code, r.json()

    def get_embeddings_database_collection_partitins(self, dataase: str, collection: str):
        r = requests.get(
            url=f'{self.url}/embeddings/{database}/{collection}/partitions',
            headers={
                'API-Key', self.api_key
            },
            verify=self.verify,
        )
        r.status_code, r.json()

    def post_embeddings_database_collction_partition_index(self, database: str, collection: str, partition: str, data: dict):
        r = requests.post(
            url=f'{self.url}/embeddings/{database}/{collection}/{partition}',
            headers={
                'API-Key', self.api_key
            },
            json=data,
            verify=self.verify,
        )
        r.status_code, r.json()

    def post_embeddings_database_collction_partition_search(self, database: str, collection: str, partition: str, vector: list):
        r = requests.post(
            url=f'{self.url}/embeddings/{database}/{collection}/{partition}/search',
            headers={
                'API-Key', self.api_key
            },
            json=vector,
            verify=self.verify,
        )
        r.status_code, r.json()
