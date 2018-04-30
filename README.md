# apistar-jwt

[![pypi](https://img.shields.io/pypi/v/apistar_jwt.svg)](https://pypi.org/project/apistar-jwt) [![travis](https://img.shields.io/travis/audiolion/apistar-jwt.svg)](https://travis-ci.org/audiolion/apistar_jwt) [![codecov](https://codecov.io/gh/audiolion/apistar-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/audiolion/apistar-jwt)


JSON Web Token Component for use with *API Star >= 0.4*.

## Installation

```
$ pip install apistar-jwt
```

Alternatively, install through [pipenv](https://pipenv.readthedocs.io/en/latest/).

```
$ pipenv install apistar-jwt
```

## Usage


Register the `JWT` Component with your APIStar app.

```python
from apistar import App
from apistar_jwt.token import JWT

routes = [
  # ...
]

components = [
    JWT({
        'JWT_SECRET': 'BZz4bHXYQD?g9YN2UksRn7*r3P(eo]P,Rt8NCWKs6VP34qmTL#8f&ruD^TtG',
    }),
]

app = App(routes=routes, components=components)
```

Inject the `JWT` component in your login function and use it to encode the JWT.

```python
from apistar import exceptions, types, validators
from apistar_jwt.token import JWT

class UserData(types.Type):
    email = validators.String()
    password = validators.String()


def login(data: UserData, jwt: JWT) -> dict:
    # do some check with your database here to see if the user is authenticated
    user = db_login(data)
    if not user:
        raise exceptions.Forbidden('Incorrect username or password.')
    payload = {
        'id': user.id,
        'username': user.email,
        'random_data': '102310',
    }
    token = jwt.encode(payload)
    if token is None:
        # encoding failed, handle error
        raise exceptions.BadRequest()
    return {'token': token}
```

Inject the `JWTUser` component in any resource where you want authentication with the provided JWT.

```python
from apistar_jwt.token import JWTUser

def welcome(user: JWTUser) -> dict:
    message = f'Welcome {user.username}#{user.id}, here is your random data: {user.token["random_data"]}'
    return {'message': message}
```

**Note**

Requests made with JWT The token must be passed as an `Authorization` header using the `Bearer` scheme in requests made to a resource.

```shell
$ curl -i -H "Accept: application/json" -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoxfQ.fCqeAJGHYwZ9y-hJ3CKUWPiENOM0xtGsMeUWmIq4o8Q" http://localhost:8080/some-resource-requiring-jwt-auth
```

### Decorators

We provide two decorators for convenience to enforce authentication required or allow anonymous users for a route:

```python
from apistar_jwt.token import JWTUser
from apistar_jwt.decorators import anonymous_allowed, authentication_required


@authentication_required
def auth_required(request: http.Request, user: JWTUser):
    return user.__dict__


@anonymous_allowed
def anon_allowed(request: http.Request, user: JWTUser):
    if user:
        return user.__dict__
    return None
```

The `@authentication_required` decorator will enforce the user to be logged in for that route. Meanwhile the `@anonymous_allowed` will set `user: JWTUser=None` and allow anonymous users to hit the route. The default behavior is `@authentication_required` so you do not need to annotate with this decorator, it is just to help your code be explicit.

## Settings

There are two settings this package uses to identify the `username` and `user_id` keys in the JWT payload, they are by default:

```python
{
  'JWT_USER_ID': 'id',
  'JWT_USER_NAME': 'username',
}
```

If your JWT uses some other kind of key, override these keys when you instantiate your component:

```python
from apistar_jwt.token import JWT

components = [
  JWT({
    'JWT_USER_ID': 'pk',
    'JWT_USER_NAME': 'email',
  })
]
```

`JWT_WHITE_LIST` allows you to specify a list of route functions that will not require JWT authentication. This is useful if you have setup a default authentication policy but want to open up certain routes, especially ones that might be in third party packages or in apistar itself like the schema docs.

```python
from apistar_jwt.token import JWT

components = [
  JWT({
    'JWT_WHITE_LIST': ['serve_schema', 'home'],
  })
]
```

In this instance, the `serve_schema` and `home` Routes will not require JWT authentication.

`JWT_ALGORITHMS` is related to the algorithms used for decoding JWTs. By default we only use 'HS256' but JWT supports passing an array of [supported algorithms](https://pyjwt.readthedocs.io/en/latest/algorithms.html#digital-signature-algorithms) which it will sequentially try when attempting to decode.

```python
from apistar_jwt.token import JWT

components = [
  JWT({
    'JWT_ALGORITHMS': ['HS256', 'RSA512'],
  })
]
```

`JWT_SECRET` is a long, randomized, secret key that should never be checked into version control.

```python
from apistar_jwt.token import JWT

components = [
  JWT({
    'JWT_SECRET': 'QXp4Z83.%2F@JBiaPZ8T9YDwoasn[dn)cZ=fE}KqHMJPNka3QyPNq^KnMqL$oCsU9BC?.f9,oF2.2t4oN?[g%iq89(+'
  })
]
```

For all other settings, use `JWT_OPTIONS` key which will pass them along to the underlying [PyJWT](https://pyjwt.readthedocs.io/en/latest/usage.html#registered-claim-names) library when decoding.

```python
from apistar_jwt.token import JWT

components = [
  JWT({
    'JWT_OPTIONS': {
      'issuer': 'urn:foo',
      'audience': 'urn:bar',
      'leeway': 10,
    },
  })
]
```

Quick rundown of the options:

`audience` is the urn for this applications audience, it must match a value in the `aud` key of the payload. [Read more about audience claim](https://pyjwt.readthedocs.io/en/latest/usage.html#audience-claim-aud).

`issuer` is the urn of the application that issues the token, it must match a value in the `iss` key of the payload. [Read more about the issuer claim](https://pyjwt.readthedocs.io/en/latest/usage.html#issuer-claim-iss)

`leeway` is the number of seconds of margin an expiration time claim in the past will still be valid for.

A fully customized `JWT` component would like like the following:

```python
from apistar_jwt.token import JWT

components = [
  JWT({
    'JWT_ALGORITHMS': ['HS256', 'RSA512'],
    'JWT_USER_ID': 'pk',
    'JWT_USER_NAME': 'email',
    'JWT_SECRET': 'QXp4Z83.%2F@JBiaPZ8T9YDwoasn[dn)cZ=fE}KqHMJPNka3QyPNq^KnMqL$oCsU9BC?.f9,oF2.2t4oN?[g%iq89(+',
    'JWT_OPTIONS': {
      'issuer': 'urn:foo',
      'audience': 'urn:bar',
      'leeway': 10,
    },
    'JWT_WHITE_LIST': ['serve_schema'],
  })
]
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
