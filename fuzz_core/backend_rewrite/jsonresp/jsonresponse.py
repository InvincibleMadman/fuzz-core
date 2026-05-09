from __future__ import annotations

from decimal import Decimal
import json


class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)
        return super().default(obj)


class JsonResp:
    """FastAPI-friendly rewrite of backend/jsonresp/jsonresponse.py."""

    def __init__(self):
        self.code = 200
        self.is_success = True
        self.msg = ''
        self.data = {}

    def _dump(self):
        return json.loads(json.dumps(self.__dict__, cls=DecimalEncoder, ensure_ascii=False))

    def get_success(self, data=None):
        self.code = 200
        self.is_success = True
        self.msg = ''
        self.data = {} if data is None else data
        payload = self._dump()
        payload['success'] = True
        return payload

    def get_error(self, code=400, msg=''):
        self.msg = msg
        self.code = code
        self.is_success = False
        self.data = {}
        payload = self._dump()
        payload['success'] = False
        return payload
