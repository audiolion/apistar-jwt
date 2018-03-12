#!/usr/bin/env python
"""Tests for `apistar_jwt` package."""

import jwt
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch

from apistar import Component, Route, Settings, TestClient, exceptions, http, annotate
from apistar.interfaces import Auth
from apistar.frameworks.asyncio import ASyncIOApp
from apistar.frameworks.wsgi import WSGIApp
from apistar.permissions import IsAuthenticated
from apistar_jwt.authentication import JWTAuthentication, get_jwt
from apistar_jwt.token import JWT


# Test Routes
@annotate(
    authentication=[JWTAuthentication()],
    permissions=[IsAuthenticated()],
)
def auth_required(request: http.Request, auth: Auth):
    return auth.user


def injected_component(request: http.Request, token: JWT):
    return token.payload


@pytest.mark.parametrize('app_class', [WSGIApp, ASyncIOApp])
def test_jwt_as_auth(app_class) -> None:
    routes = [
        Route('/auth-required-route', 'GET', auth_required),
    ]
    settings = {
        'JWT': {
            'SECRET': 'jwt-secret',
            'USERNAME': 'username',
            'ID': 'user',
        }
    }

    app = app_class(routes=routes, settings=settings)
    client = TestClient(app)

    response = client.get('/auth-required-route')
    assert response.status_code == 403

    payload = {'user': 1, 'username': 'bailey'}
    secret = settings['JWT']['SECRET']
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')

    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer',
    })
    assert response.status_code == 403

    response = client.get('/auth-required-route', headers={
        'Authorization': 'Basic username',
    })
    assert response.status_code == 403

    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200
    assert response.json() == {'id': payload[settings['JWT']['ID']], 'name': payload[settings['JWT']['USERNAME']]}  # noqa; E501

    encoded_jwt = jwt.encode(payload, 'wrong-secret').decode(encoding='UTF-8')
    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 403

    # wrong secret
    encoded_jwt = jwt.encode(payload, 'wrong secret', algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 403

    # wrong algorithm
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS512').decode(encoding='UTF-8')
    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 403

    # empty payload causes auth to fail
    encoded_jwt = jwt.encode({}, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 403

    # Missing SECRET causes configuration error to bubble up
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    with patch.dict(settings['JWT'], {'SECRET': None}), \
         pytest.raises(exceptions.ConfigurationError):
        client.get('/auth-required-route', headers={
            'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
        })


@pytest.mark.parametrize('app_class', [WSGIApp, ASyncIOApp])
def test_jwt_issuer_claim(app_class) -> None:
    routes = [
        Route('/as-a-component-route', 'GET', injected_component),
        Route('/auth-required-route', 'GET', auth_required),
    ]
    settings = {
        'JWT': {
            'SECRET': 'jwt-secret',
            'USERNAME': 'username',
            'ID': 'user',
            'ISSUER': 'urn:foo',
        }
    }
    components = [
        Component(JWT, init=get_jwt)
    ]

    app = app_class(routes=routes, settings=settings, components=components)
    client = TestClient(app)

    payload = {'user': 1, 'username': 'bailey', 'iss': 'urn:foo'}
    secret = settings['JWT']['SECRET']

    # iss claim is correct
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200
    assert response.json() == {'id': payload[settings['JWT']['ID']], 'name': payload[settings['JWT']['USERNAME']]}  # noqa; E501

    response = client.get('/as-a-component-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200
    assert response.json() == payload

    # iss claim is incorrect
    payload['iss'] = 'urn:not-foo'
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 403

    response = client.get('/as-a-component-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401

    # no iss claim included in jwt
    del payload['iss']
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 403

    response = client.get('/as-a-component-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401


@pytest.mark.parametrize('app_class', [WSGIApp, ASyncIOApp])
def test_jwt_audience_claim(app_class) -> None:
    routes = [
        Route('/as-a-component-route', 'GET', injected_component),
        Route('/auth-required-route', 'GET', auth_required),
    ]
    settings = {
        'JWT': {
            'SECRET': 'jwt-secret',
            'USERNAME': 'username',
            'ID': 'user',
            'AUDIENCE': 'urn:foo',
        }
    }
    components = [
        Component(JWT, init=get_jwt)
    ]

    app = app_class(routes=routes, settings=settings, components=components)
    client = TestClient(app)

    payload = {'user': 1, 'username': 'bailey', 'aud': 'urn:foo'}
    secret = settings['JWT']['SECRET']

    # aud claim is single and correct
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200
    assert response.json() == {'id': payload[settings['JWT']['ID']], 'name': payload[settings['JWT']['USERNAME']]}  # noqa; E501

    response = client.get('/as-a-component-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200
    assert response.json() == payload

    # aud claim is multiple and correct
    payload['aud'] = ['urn:bar', 'urn:baz', 'urn:foo']
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200
    assert response.json() == {'id': payload[settings['JWT']['ID']], 'name': payload[settings['JWT']['USERNAME']]}  # noqa; E501

    response = client.get('/as-a-component-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200
    assert response.json() == payload

    # aud claim is incorrect and single
    payload['aud'] = 'urn:not-foo'
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 403

    response = client.get('/as-a-component-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401

    # aud claim is incorrect and multiple
    payload['aud'] = ['urn:bar', 'urn:baz', 'urn:not-foo']
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 403

    response = client.get('/as-a-component-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401

    # no aud claim included in jwt
    del payload['aud']
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 403

    response = client.get('/as-a-component-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401


@pytest.mark.parametrize('app_class', [WSGIApp, ASyncIOApp])
def test_jwt_leeway_claim(app_class) -> None:
    routes = [
        Route('/as-a-component-route', 'GET', injected_component),
        Route('/auth-required-route', 'GET', auth_required),
    ]
    settings = {
        'JWT': {
            'SECRET': 'jwt-secret',
            'USERNAME': 'username',
            'ID': 'user',
            'LEEWAY': 3,
        }
    }
    components = [
        Component(JWT, init=get_jwt)
    ]

    app = app_class(routes=routes, settings=settings, components=components)
    client = TestClient(app)

    payload = {'user': 1, 'username': 'bailey', 'exp': datetime.utcnow() - timedelta(seconds=2)}
    secret = settings['JWT']['SECRET']

    # exp claim doesn't fail because of leeway
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200
    assert response.json() == {'id': payload[settings['JWT']['ID']], 'name': payload[settings['JWT']['USERNAME']]}  # noqa; E501

    response = client.get('/as-a-component-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200
    assert response.json() == payload

    # exp claim fails because leeway is only 3 seconds
    payload['exp'] = datetime.utcnow() - timedelta(seconds=4)
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 403

    response = client.get('/as-a-component-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401

    # no exp claim included in jwt, leeway doesnt apply
    del payload['exp']
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/auth-required-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200

    response = client.get('/as-a-component-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200


@pytest.mark.parametrize('app_class', [WSGIApp, ASyncIOApp])
def test_jwt_as_component(app_class) -> None:
    routes = [
        Route('/as-a-component-route', 'GET', injected_component),
    ]
    settings = {
        'JWT': {
            'SECRET': 'jwt-secret',
            'USERNAME': 'username',
            'ID': 'user',
        }
    }
    components = [
        Component(JWT, init=get_jwt)
    ]

    app = app_class(routes=routes, settings=settings, components=components)
    client = TestClient(app)

    payload = {'user': 1, 'username': 'bailey'}
    secret = settings['JWT']['SECRET']
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256').decode(encoding='UTF-8')

    response = client.get('/as-a-component-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 200
    assert response.json() == payload

    response = client.get('/as-a-component-route', headers={
        'Authorization': 'Bearer ',
    })
    assert response.status_code == 401

    # wrong secret
    encoded_jwt = jwt.encode(payload, 'wrong secret', algorithm='HS256').decode(encoding='UTF-8')
    response = client.get('/as-a-component-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401

    # wrong algorithm
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS512').decode(encoding='UTF-8')
    response = client.get('/as-a-component-route', headers={
        'Authorization': 'Bearer {token}'.format(token=encoded_jwt),
    })
    assert response.status_code == 401


def test_jwt_encode() -> None:
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

    with pytest.raises(exceptions.ConfigurationError):
        JWT(token=token, settings=settings)


def test_no_secret_passed_to_encode() -> None:
    payload = {'some': 'payload'}
    with pytest.raises(exceptions.ConfigurationError):
        JWT.encode(payload=payload)


def test_unknown_algorithm_passed_to_encode() -> None:
    payload = {'some': 'payload'}
    with pytest.raises(exceptions.ConfigurationError):
        JWT.encode(payload=payload, secret='jwt-secret', algorithm='unknown-algorithm')
