import inspect
import logging
import os
from typing import Dict, Union, Optional

from apistar import http, Route
from apistar.exceptions import ConfigurationError
from apistar.server.components import Component

import jwt as PyJWT

from .exceptions import AuthenticationFailed
from .utils import get_token_from_header

log = logging.getLogger(__name__)


class JWTUser:
    slots = ('id', 'username', 'token')

    def __init__(self, id, username, token) -> None:
        self.id = id
        self.username = username
        self.token = token


class _JWT:
    slots = ('ID', 'USERNAME', 'algorithms', 'options', 'secret')

    def __init__(self, settings: Dict) -> None:
        self.ID = settings.get('user_id')
        self.USERNAME = settings.get('user_name')
        self.algorithms = settings.get('algorithms')
        self.options = settings.get('options')
        self.secret = settings.get('secret')

    def encode(self, payload, algorithm=None, **kwargs) -> str:
        algorithm = algorithm if algorithm else self.algorithms[0]
        try:
            token = PyJWT.encode(
                payload, self.secret, algorithm=algorithm).decode(encoding='UTF-8')
        except Exception as exc:
            log.warn(exc.__class__.__name__)
            return None
        return token

    def decode(self, token) -> Optional[JWTUser]:
        try:
            payload = PyJWT.decode(token, self.secret, algorithms=self.algorithms, **self.options)
            if payload == {}:
                return None
        except PyJWT.MissingRequiredClaimError as exc:
            log.warning('JWT Missing claim: %s', exc.claim)
            return None
        except PyJWT.InvalidTokenError as exc:
            log.exception('JWT Invalid Token: %s', exc.__class__.__name__)
            return None
        except Exception as exc:
            log.exception('JWT Exception: %s', exc.__class__.__name__)
            return None
        _id = payload.get(self.ID)
        username = payload.get(self.USERNAME)
        return JWTUser(id=_id, username=username, token=payload)


class JWT(Component):
    slots = ('settings')

    def __init__(self, settings: Dict=None) -> None:
        def get(setting, default=None):
            return settings.get(setting, os.environ.get(setting, default))
        settings = settings if settings else {}
        self.settings = {
            'user_id': get('JWT_USER_ID', 'id'),
            'user_name': get('JWT_USER_NAME', 'username'),
            'algorithms': get('JWT_ALGORITHMS', ['HS256']),
            'options': get('JWT_OPTIONS', {}),
            'secret': get('JWT_SECRET'),
            "white_list": get("JWT_WHITE_LIST", []),
        }
        if self.settings['secret'] is None:
            self._raise_setup_error()

    def _raise_setup_error(self):
        msg = ('JWT_SECRET must be defined as an environment variable or passed as part of'
               ' settings on instantiation.'
               ' See https://github.com/audiolion/apistar-jwt#Setup')
        raise ConfigurationError(msg)

    def resolve(self, authorization: http.Header, route: Route, parameter: inspect.Parameter
                ) -> Union[_JWT, JWTUser, None]:
        authentication_required = getattr(route.handler, 'authenticated', True)
        jwt = _JWT(self.settings)
        if parameter.annotation is JWT:
            return jwt
        if route.handler.__name__ in self.settings["white_list"]:
            return None
        if authorization is None and not authentication_required:
            return None
        token = get_token_from_header(authorization)
        jwt_user = jwt.decode(token)
        if jwt_user is None:
            raise AuthenticationFailed()
        return jwt_user

    def can_handle_parameter(self, parameter: inspect.Parameter) -> bool:
        return parameter.annotation is JWT or parameter.annotation is JWTUser
