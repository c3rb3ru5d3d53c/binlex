#!/usr/bin/env python

from flask import request, abort
from functools import wraps
from flask import current_app as app

def require_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key in app.config['user_keys'] or api_key in app.config['admin_keys']:
            return f(*args, **kwargs)
        return {
            'error': 'user or admin api key incorrect or not provided'
        }, 401
    return decorated_function


def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key in app.config['admin_keys']:
            return f(*args, **kwargs)
        return {
            'error': 'user or admin api key incorrect or not provided'
        }, 401
    return decorated_function
