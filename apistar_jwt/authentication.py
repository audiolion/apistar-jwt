from apistar import http
from apistar.authentication import Authenticated
from apistar.types import Settings

from .exceptions import AuthenticationFailed
from .token import JWT


def get_jwt(authorization: http.Header, settings: Settings):
    if authorization is None:
        raise AuthenticationFailed('Authorization header is missing.') from None
    try:
        scheme, token = authorization.split()
    except ValueError:
        raise AuthenticationFailed('Could not seperate Authorization scheme and token.') from None
    if scheme.lower() != 'bearer':
        raise AuthenticationFailed('Authorization scheme not supported, try Bearer') from None
    return JWT(token=token, settings=settings)


class JWTAuthentication():
    def authenticate(self, authorization: http.Header, settings: Settings):
        jwt = get_jwt(authorization, settings)
        if jwt.payload == {}:
            raise AuthenticationFailed()
        jwt_settings = settings.get('JWT', {})
        uid = jwt.payload.get(jwt_settings.get('ID', 'id'), '')
        username = jwt.payload.get(jwt_settings.get('USERNAME', 'username'), '')
        return Authenticated(username, user={'id': uid, 'name': username}, token=jwt.token)
