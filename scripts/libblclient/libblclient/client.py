import requests

class BinlexHTTPClient():
    def __init__(self, url: str, api_key: str, verify=False):
        self.url = url
        self.api_key = api_key
        self.verify = verify

    def get_embeddings_database_list(self):
        r = requests.get(
            url=f'{self.url}/embeddings/database/list',
            headers={
                'API-Key', self.api_key
            },
            verify=self.verify,
        )
        r.status_code, r.json()

    def post_embeddings_index(self, database: str, data: dict):
        r = requests.post(
            url=f'{self.url}/embeddings/index/{database}',
            headers={
                'API-Key', self.api_key
            },
            json=data,
            verify=self.verify,
        )
        r.status_code, r.json()

    def get_embeddings_search(self, database: str, vector: list):
        r = requests.post(
            url=f'{self.url}/embeddings/search/{database}',
            headers={
                'API-Key', self.api_key
            },
            json=data,
            verify=self.verify,
        )
        r.status_code, r.json()
