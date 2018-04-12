# apistar-jwt

[![pypi](https://img.shields.io/pypi/v/apistar_jwt.svg)](https://pypi.python.org/pypi/apistar-jwt) [![travis](https://img.shields.io/travis/audiolion/apistar-jwt.svg)](https://travis-ci.org/audiolion/apistar_jwt) [![codecov](https://codecov.io/gh/audiolion/apistar-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/audiolion/apistar-jwt)


JSON Web Token Component for use with API Star. Provides JWTAuthenticate class for JWT Authentication.

## WARNING!

This version of `apistar-jwt` is only compatible with `apistar<0.4`.


## Installation

We recommend [pipenv](https://pipenv.readthedocs.io/en/latest/) for dependency management.
```
$ pipenv install apistar-jwt
```

Alternatively, install through pip.

```
$ pip install apistar-jwt
```

## Usage

To encrypt and decrpyt tokens you must set the include the following setting under your apistar settings.

```python
settings = {
  'JWT': {
    # do not check your secret into version control!
    'SECRET': 'QXp4Z83.%2F@JBiaPZ8T9YDwoasn[dn)cZ=fE}KqHMJPNka3QyPNq^KnMqL$oCsU9BC?.f9,oF2.2t4oN?[g%iq89(+'
  }
}
```

The JWT Component provided can be used as an injected component in a function or through the API Star Authentication Interface. No matter which method you choose to use, the token must be passed as an `Authorization` header using the `Bearer` scheme in requests made to a resource.

```shell
$ curl -i -H "Accept: application/json" -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoxfQ.fCqeAJGHYwZ9y-hJ3CKUWPiENOM0xtGsMeUWmIq4o8Q" http://localhost:8080/some-resource-requiring-jwt
```


### Authentication

Annotate any routes where you want to use JWT Authentication.

```python
from apistar import annotate
from apistar.interfaces import Auth
from apistar_jwt.authentication import JWTAuthentication


@annotate(authentication=[JWTAuthentication()])
def auth_route(auth: Auth):
    # user is authenticated if it reaches here

    # get user data
    auth.user

    # get token
    auth.token

    # always returns true
    auth.is_authenticated()

    # get username from either
    auth.get_user_id()
    auth.get_display_name()
```

If you need to access the tokens payload you can decrypt the token inside the route.

```python
from apistar import annotate
from apistar.interfaces import Auth
from apistar.types import Settings
from apistar_jwt.authentication import JWTAuthentication
from apistar_jwt.token import JWT


@annotate(authentication=[JWTAuthentication()])
def access_jwt_payload_route(auth: Auth, settings: Settings):
    # get payload from token
    token = JWT(token=auth.token, settings=settings)
    token.payload
```

Alternatively, we can [configure the authentication policy](https://github.com/encode/apistar#configuring-the-authentication-policy).

```python
from apistar_jwt.authentication import JWTAuthentication

settings = {
    'AUTHENTICATION': [JWTAuthentication()]
}
```

### As A Component

Register the JWT Component in your App:

```python
from apistar import Component
from apistar_jwt.authentication import get_jwt
from apistar_jwt.token import JWT

components = [
    Component(JWT, init=get_jwt)
]

app = App(
    routes=routes,
    components=components
)
```

Add the component to your function definition:

```python
from apistar import http
from apistar_jwt.token import JWT

def echo_jwt_payload(request: http.Request, token: JWT):
    return token.payload

```

Note that you have to do your own authentication check using this method. The payload will be returned as it was encoded and won't respect the `JWT` settings for `USERNAME` and `ID` as they correlate with the `Auth` interface which is not utilized when using `JWT` as an injected component.

```python
from apistar import http
from apistar import exceptions
from apistar_jwt.token import JWT

def auth_required_endpoint(request: http.Request, token: JWT):
    if token.payload is None:
      raise exceptions.Forbidden()
    username = token.payload.get('username', '')
    other_data_you_put_in_payload = token.payload.get('other_data', '')
    return {
      'username': username,
      'other_data': other_data_you_put_in_payload,
    }
```

### Settings

There are two settings this package uses to identify the `username` and `user_id` keys in the JWT payload, they are by default

```python
settings = {
  'JWT': {
    'USERNAME': 'username',
    'ID': 'id',
  }
}
```

If your JWT uses some other kind of key, copy these keys into your settings and set the correct key values.

`ID` is not required, but available if you would like to include a different id field in your JWT payload.

#### Other JWT Settings

`ALGORITHMS` is related to the algorithms used for decoding JWTs. By default we only use 'HS256' but JWT supports passing an array of [supported algorithms](https://pyjwt.readthedocs.io/en/latest/algorithms.html#digital-signature-algorithms) which it will sequentially try when attempting to decode.

```python
settings = {
  'JWT': {
    'ALGORITHMS': ['HS256', ],
  }
}
```

`SECRET` is a long, randomized, secret key that should never be checked into version control.

```python
settings = {
  'JWT': {
    'SECRET': 'QXp4Z83.%2F@JBiaPZ8T9YDwoasn[dn)cZ=fE}KqHMJPNka3QyPNq^KnMqL$oCsU9BC?.f9,oF2.2t4oN?[g%iq89(+'
  }
}
```

`ISSUER` is the urn for which JWT's should be accepted from. [Read more about issuer claim](https://pyjwt.readthedocs.io/en/latest/usage.html#issuer-claim-iss).

```python
settings = {
  'JWT': {
    'ISSUER': 'urn:foo'
  }
}
```

`AUDIENCE` is the urn for this applications audience, it must match a value in the `aud` key of the payload. [Read more about issueer claim](https://pyjwt.readthedocs.io/en/latest/usage.html#audience-claim-aud).

```python
settings = {
  'JWT': {
    'AUDIENCE': 'urn:bar'
  }
}
```

`LEEWAY` is the number of seconds of margin an expiration time claim in the past will still be valid for.

```python
settings = {
  'JWT': {
    'LEEWAY': 10
  }
}
```

### Encoding JWTs

As a convenience, we provide a simple `encode` method to create JWTs, if you need more advanced JWT encodings, please [visit the PyJWT docs](https://pyjwt.readthedocs.io/en/latest/usage.html#usage-examples).

```python
from apistar.types import Settings
from apistar_jwt.token import JWT


def encrypt_payload(request: http.Request, settings: Settings):
    SECRET = settings['JWT'].get('SECRET')
    payload = {'email': 'test@example.com'}

    # algorithm for encoding defaults to HS256
    token = JWT.encode(payload, secret=SECRET)

    # use the algorithm keyword to pass a specific algorithm
    token = JWT.encode(payload, secret=SECRET, algorithm='RS512')

    return {'token': token}
```

You may pass [valid claim names](https://pyjwt.readthedocs.io/en/latest/usage.html#registered-claim-names) or other valid kwargs to `JWT.encode()`. These claims help with your JWT's security. The following example demonstrates using all the claims, but they are all optional and the values provided for the claims in the example are arbitrary.

```python
from datetime import datetime, timedelta

from apistar.types import Settings
from apistar_jwt.token import JWT


def encrypt_payload(request: http.Request, settings: Settings):
    SECRET = settings['JWT'].get('SECRET')
    payload = {
        'email': 'test@example.com',
        'iss': 'urn:foo',  # only accept jwt from this issuer
        'aud': ['urn:foo', 'urn:bar', 'urn:baz']  # only these audiences can decrpyt
        'iat': datetime.utcnow()  # issued at to know time JWT was issued
        'exp': datetime.utcnow() + timedelta(seconds=30),  # expiration time
        'nbf': datetime.utcnow(),  # not before time
    }

    # you may also pass optional kwargs like headers to the encode method
    token = JWT.encode(
        payload,
        secret=SECRET,
        algorithm='RS512',
        headers={'kid': '230498151c214b788dd97f22b85410a5'},
    )

    return {'token': token}
```

## Developing

This project uses [`pipenv`](https://docs.pipenv.org) to manage its development environment, and [`pytest`](https://docs.pytest.org) as its tests runner.  To install development dependencies:

```
pipenv install --dev
```

To run tests:

```
pipenv shell
pytest
```

This project uses [Codecov](https://codecov.io/gh/audiolion/apistar-jwt) to enforce code coverage on all pull requests.  To run tests locally and output a code coverage report, run:

```
pipenv shell
pytest --cov=apistar_test/
```
