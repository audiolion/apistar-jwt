# apistar-jwt

[![pypi](https://img.shields.io/pypi/v/apistar_jwt.svg)](https://pypi.python.org/pypi/apistar_jwt)

[![travis](https://img.shields.io/travis/audiolion/apistar_jwt.svg)](https://travis-ci.org/audiolion/apistar_jwt)


JSON Web Token Component for use with API Star. Provides JWTAuthenticate class for JWT Authentication.


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

The JWT Component provided can be used as an injected component in a function or through the API Star Authentication Interface.

### Authentication

Annotate any routes where you want to use JWT Authentication.

```python
from apistar import annotate
from apistar.interfaces import Auth
from apistar.types import Settings
from apistar_jwt.authentication import JWTAuthentication
from apistar_jwt.token import JWT


@annotate(authentication=[JWTAuthentication()])
def display_user(auth: Auth, settings: Settings):
    # There are no required permissions set on this handler, so all requests
    # will be allowed.
    # Requests that have successfully authenticated using jwt authentication
    # will include user credentials in `auth`.

    # get user data
    auth.user

    # get token
    auth.token

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

Note that you have to do your own authentication check using this method.

```python
from apistar import http
from apistar import exceptions
from apistar_jwt.token import JWT

def auth_required_endpoint(request: http.Request, token: JWT):
    if token is None:
      raise exceptions.Forbidden()
    username = token.payload.get('username', '')
    other_data_you_put_in_payload = token.payload.get('other_data', '')
    return {
      'username': username,
      'other_data': other_data_you_put_in_payload,
    }
```
