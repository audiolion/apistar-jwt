import logging
import os
from typing import Dict, Union

from apistar import http
from apistar.exceptions import ConfigurationError
from apistar.server.components import Component

import jwt as PyJWT

from .exceptions import AuthenticationFailed
from .utils import get_token_from_header

log = logging.getLogger(__name__)


class JWTUser:
    slots = ('id', 'username', 'token')

    def __init__(self, id, username, token):
        self.id = id
        self.username = username
        self.token = token


class _JWT:
    slots = ('ID', 'USERNAME', 'algorithms', 'options', 'secret')

    def __init__(self, settings: Dict):
        self.ID = settings.get('JWT_USER_ID')
        self.USERNAME = settings.get('JWT_USER_NAME')
        self.algorithms = settings.get('JWT_ALGORITHMS')
        self.options = settings.get('options')
        self.secret = settings.get('JWT_SECRET')

    def encode(payload, algorithm=None, **kwargs):
        algorithm = algorithm if algorithm else self.algorithms[0]
        try:
            token = jwt.encode(
                payload, secret, algorithm=algorithm, **self.options).decode(encoding='UTF-8')
        except Exception as exc:
            log.warn(exc.__class__.__name__)
            return None
        return token

    def decode(token):
        try:
            payload = PyJWT.decode(token, self.secret, algorithms=self.algorithms, **self.options)
            if payload == {}:
                return None
        except PyJWT.MissingRequiredClaimError as ex:
            log.warning('JWT Missing claim: %s', ex.claim)
            return None
        except PyJWT.InvalidTokenError as ex:
            log.exception('JWT Invalid Token: %s', ex.__class__.__name__)
            return None
        except Exception as exc:
            log.exception('JWT Exception: %s', ex.__class__.__name__)
            return None
        id = payload.get(self.ID)
        username = payload.get(self.USERNAME)
        return JWTUser(id=id, username=username, token=payload)


class JWT(Component):
    slots = ('settings')

    def __init__(self, settings: Dict=None):
        def get(setting, default=None):
            return settings.get(setting, os.environ.get(setting, default))
        self.settings = {
            'USER_ID': get('JWT_USER_ID', 'id'),
            'USER_NAME': get('JWT_USER_NAME', 'username'),
            'options': get('JWT_OPTIONS'),
            'secret': get('JWT_SECRET'),
        }
        if self.settings['secret'] is None:
            self._raise_setup_error()
        if not hasattr(self.settings['options'], 'JWT_ALGORITHMS'):
            self.settings['options']['JWT_ALGORITHMS'] = ['HS256']

    def _raise_setup_error(self):
        msg = ('JWT_SECRET must be defined as an environment variable or passed as part of'
               ' settings on instantiation.'
               ' See https://github.com/audiolion/apistar-jwt#Setup')
        raise ConfigurationError(msg)

    def resolve(self, authorization: http.Header) -> Union[_JWT, JWTUser]:
        jwt = _JWT(self.settings)
        if authorization is None:
            return jwt
        token = get_token_from_header(authorization)
        jwt_user = jwt.decode(token)
        if jwt_user is None:
            raise AuthenticationFailed()
        return jwt_user

    def can_handle_parameter(self, parameter: inspect.Parameter):
        return parameter.annotation is JWT or parameter.annotation is JWTUser
