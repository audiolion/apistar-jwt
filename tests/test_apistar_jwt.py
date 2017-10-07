#!/usr/bin/env python
"""Tests for `apistar_jwt` package."""

import jwt
import pytest

from apistar import Component, Route, Settings, TestClient, exceptions, http, annotate
from apistar.frameworks.asyncio import ASyncIOApp
from apistar.frameworks.wsgi import WSGIApp
from apistar_jwt.authentication import JWTAuthentication, get_jwt
from apistar_jwt.token import JWT


@annotate(authentication=[JWTAuthentication()])
def auth_required(request: http.Request, token: JWT):
    return token.payload

def injected_component(request: http.Request, token: JWT):
    return token.payload


@pytest.mark.parametrize('app_class', [WSGIApp, ASyncIOApp])
def test_decoded_jwt(app_class) -> None:
    routes = [
        Route('/auth-required-route', 'GET', auth_required),
        Route('/as-a-component-route', 'GET', injected_component),
    ]
    settings = {
        'JWT': {'SECRET': 'jwt-secret'}
    }
    components = [
        Component(JWT, init=get_jwt)
    ]

    app = app_class(routes=routes, settings=settings, components=components)
    client = TestClient(app)

    response = client.get('/auth-required-route')
    assert response.status_code == 401

    payload = {'user': 1}
    secret = settings['JWT']['SECRET']
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')

    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer',
    })
    assert response.status_code == 401

    response = client.get('/auth-required-route', headers={
        'Authorization': 'Basic username',
    })
    assert response.status_code == 401

    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200
    assert response.json() == payload

    encoded_jwt = jwt.encode(payload, 'wrong-secret').decode(encoding='UTF-8')
    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401


def test_encoded_jwt() -> None:
    payload = {'email': 'test@example.com'}
    token = jwt.encode(payload, 'jwt-secret', algorithm='HS256').decode(encoding='UTF-8')
    secret = 'jwt-secret'
    encoded_jwt = JWT.encode(payload=payload, secret=secret)
    assert encoded_jwt == token

    encoded_jwt = JWT.encode(payload=payload, secret=secret, algorithm='HS512')
    assert encoded_jwt != token
    token = jwt.encode(payload, 'jwt-secret', algorithm='HS512').decode(encoding='UTF-8')
    assert encoded_jwt == token


def test_misconfigured_jwt_settings() -> None:
    settings = Settings({
        'JWT': {},
    })
    token = 'abc'
    payload = {'some': 'payload'}

    with pytest.raises(exceptions.ConfigurationError):
        JWT(token=token, settings=settings)
    with pytest.raises(exceptions.ConfigurationError):
        JWT.encode(payload=payload, settings=settings)

    settings = Settings({
        'JWT': {'SECRET': 'jwt-secret', 'ALGORITHMS': ['unknown-algo']}
    })

    with pytest.raises(exceptions.ConfigurationError):
        JWT.encode(payload=payload, settings=settings)
