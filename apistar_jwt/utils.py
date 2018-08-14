from apistar import http

from .exceptions import AuthenticationFailed


def get_token_from_header(authorization: http.Header, authorization_prefix: str):
    if authorization is None:
        raise AuthenticationFailed('Authorization header is missing.')
    try:
        scheme, token = authorization.split()
    except ValueError:
        raise AuthenticationFailed('Could not seperate Authorization scheme and token.')
    if scheme.lower() != authorization_prefix:
        raise AuthenticationFailed('Authorization scheme not supported, try Bearer')
    return token
