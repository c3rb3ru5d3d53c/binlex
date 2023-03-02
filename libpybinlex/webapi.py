#!/usr/bin/env python

import json
import requests

class WebAPIv1():
    def __init__(self, url: str, verify=True):
        self.url = url + '/api/v1'
        self.verify = verify
    def get_modes(self):
        return requests.get(
            url=self.url + '/modes',
            verify=self.verify
        )
    def is_mode(self, mode):
        r = self.get_modes()
        if r.status_code != 200: return False
        if mode in json.loads(r.content): return True
        return False
    def get_traits(self, data: bytes, mode: str, corpus='default', tags=[]):
        tags = ','.join(tags)
        return requests.post(
            url=self.url + f'/{corpus}/{mode}/{tags}',
            data=data,
            verify=self.verify
        )
