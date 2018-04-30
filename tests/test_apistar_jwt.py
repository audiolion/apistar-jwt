#!/usr/bin/env python
"""Tests for `apistar_jwt` package."""

import jwt
import pytest
from datetime import datetime, timedelta

from apistar import Route, exceptions, http
from apistar.test import TestClient
from apistar.server.app import App, ASyncApp
from apistar_jwt.token import JWT, JWTUser
from apistar_jwt.decorators import authentication_required, anonymous_allowed


@authentication_required
def auth_required(request: http.Request, user: JWTUser):
    return user.__dict__


@anonymous_allowed
def anon_allowed(request: http.Request, user: JWTUser):
    if user:
        return user.__dict__
    return None


def test_configuration_error() -> None:
    with pytest.raises(exceptions.ConfigurationError):
        JWT()


@pytest.mark.parametrize('app_class', [App, ASyncApp])
def test_jwt_auth_required(app_class) -> None:
    secret = 'jwt-secret'
    routes = [
        Route('/auth-required', 'GET', auth_required),
    ]

    components = [JWT({'JWT_SECRET': secret})]
    app = app_class(routes=routes, components=components)
    client = TestClient(app)

    response = client.get('/auth-required')
    assert response.status_code == 401

    response = client.get('/auth-required', headers={
        'Authorization': 'Bearer',
    })
    assert response.status_code == 401

    response = client.get('/auth-required', headers={
        'Authorization': 'Basic username',
    })
    assert response.status_code == 401

    payload = {'id': 1, 'username': 'bailey'}

    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')

    response = client.get('/auth-required', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })

    assert response.status_code == 200
    data = response.json()
    assert data['id'] == payload['id']
    assert data['username'] == payload['username']
    assert data['token'] == payload

    # wrong secret
    encoded_jwt = jwt.encode(payload, 'wrong secret', algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401

    # wrong algorithm
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS512').decode(encoding='UTF-8')
    response = client.get('/auth-required', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401

    # empty payload causes auth to fail
    encoded_jwt = jwt.encode({}, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401


@pytest.mark.parametrize('app_class', [App, ASyncApp])
def test_jwt_anon_allowed(app_class) -> None:
    secret = 'jwt-secret'
    routes = [
        Route('/anonymous-allowed', 'GET', anon_allowed),
    ]

    components = [JWT({'JWT_SECRET': secret})]
    app = app_class(routes=routes, components=components)
    client = TestClient(app)

    response = client.get('/anonymous-allowed')
    assert response.status_code == 200
    assert response.json() is None

    # client is trying to authenticate, so not anonymous
    response = client.get('/anonymous-allowed', headers={
        'Authorization': 'Bearer',
    })
    assert response.status_code == 401

    # client is trying to authenticate, so not anonymous
    response = client.get('/anonymous-allowed', headers={
        'Authorization': 'Basic username',
    })
    assert response.status_code == 401

    payload = {'id': 1, 'username': 'bailey'}

    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')

    # authenticated is also allowed
    response = client.get('/anonymous-allowed', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })

    assert response.status_code == 200
    data = response.json()
    assert data['id'] == payload['id']
    assert data['username'] == payload['username']
    assert data['token'] == payload

    # wrong secret
    encoded_jwt = jwt.encode(payload, 'wrong secret', algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/anonymous-allowed', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401

    # wrong algorithm
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS512').decode(encoding='UTF-8')
    response = client.get('/anonymous-allowed', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401

    # empty payload causes auth to fail
    encoded_jwt = jwt.encode({}, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/anonymous-allowed', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401


@pytest.mark.parametrize('app_class', [App, ASyncApp])
def test_jwt_issuer_claim(app_class) -> None:
    secret = 'jwt-secret'

    routes = [
        Route('/auth-required', 'GET', auth_required),
    ]

    components = [
        JWT({
            'JWT_SECRET': secret,
            'JWT_OPTIONS': {
                'issuer': 'urn:foo',
            }
        })
    ]

    app = app_class(routes=routes, components=components)
    client = TestClient(app)

    payload = {'user': 1, 'username': 'bailey', 'iss': 'urn:foo'}

    # iss claim is correct
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200

    # iss claim is incorrect
    payload['iss'] = 'urn:not-foo'
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401

    # no iss claim included in jwt
    del payload['iss']
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401


@pytest.mark.parametrize('app_class', [App, ASyncApp])
def test_jwt_audience_claim(app_class) -> None:
    secret = 'jwt-secret'

    routes = [
        Route('/auth-required', 'GET', auth_required),
    ]

    components = [
        JWT({
            'JWT_SECRET': secret,
            'JWT_OPTIONS': {
                'audience': 'urn:foo',
            }
        })
    ]

    app = app_class(routes=routes, components=components)
    client = TestClient(app)

    payload = {'user': 1, 'username': 'bailey', 'aud': 'urn:foo'}

    # aud claim is single and correct
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200

    # aud claim is multiple and correct
    payload['aud'] = ['urn:bar', 'urn:baz', 'urn:foo']
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200

    # aud claim is incorrect and single
    payload['aud'] = 'urn:not-foo'
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401

    # aud claim is incorrect and multiple
    payload['aud'] = ['urn:bar', 'urn:baz', 'urn:not-foo']
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401

    # no aud claim included in jwt
    del payload['aud']
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401


@pytest.mark.parametrize('app_class', [App, ASyncApp])
def test_jwt_leeway_claim(app_class) -> None:
    secret = 'jwt-secret'

    routes = [
        Route('/auth-required', 'GET', auth_required),
    ]

    components = [
        JWT({
            'JWT_SECRET': secret,
            'JWT_OPTIONS': {
                'leeway': 3,
            }
        })
    ]

    app = app_class(routes=routes, components=components)
    client = TestClient(app)

    payload = {'user': 1, 'username': 'bailey', 'exp': datetime.utcnow() - timedelta(seconds=2)}

    # exp claim doesn't fail because of leeway
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200

    # exp claim fails because leeway is only 3 seconds
    payload['exp'] = datetime.utcnow() - timedelta(seconds=4)
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401

    # no exp claim included in jwt, leeway doesnt apply
    del payload['exp']
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200


@pytest.mark.parametrize("app_class", [App, ASyncApp])
def test_jwt_white_list(app_class) -> None:
    secret = "jwt-secret"

    class IsAuthenticated:

        def on_request(self, jwt_user: JWTUser) -> None:
            """ just force authentication for each request"""

    components = [JWT({"JWT_SECRET": secret})]

    app = app_class(routes=[], components=components, event_hooks=[IsAuthenticated()])
    client = TestClient(app)

    r = client.get("/schema/")
    assert r.json() == "Authorization header is missing."
    assert r.status_code == 401

    components = [JWT({"JWT_SECRET": secret, "JWT_WHITE_LIST": ["serve_schema"]})]

    app = app_class(routes=[], components=components, event_hooks=[IsAuthenticated()])
    client = TestClient(app)
    r = client.get("/schema/")
    assert r.status_code == 200
