import os

from apistar import App, Route, exceptions, http
from apistar.frameworks.wsgi import WSGIApp as App

from apistar_jwt.token import JWT JWTUser

import datetime


# Fake user database
USERS_DB = {'id': 1, 'email': 'user@example.com', 'password': 'password'}


class UserData(types.Type):
    email = validators.String()
    password = validators.String()


def welcome(user: JWTUser) -> dict:
    return {
        'message': f'Welcome {user.username}#{user.id}, your login expires at {user.token['exp']}',
    }


# we override the default Authentication and Permissions policy to allow login
@annotate(authentication=[], permissions=[])
def login(user: UserData, jwt: JWT) -> dict:
    # do some check with your database here to see if the user is authenticated
    if user.email != USERS_DB['email'] or user.password != USERS_DB['password']:
        raise exceptions.Forbidden('Incorrect username or password.')
    payload = {
        'id': user.id,
        'username': user.email,
        'iat': datetime.datetime.utcnow(),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)  # ends in 60 minutes
    }
    token = jwt.encode(payload)
    if token is None:
        # encoding failed, handle error
        raise exceptions.BadRequest()
    return {'token': token}


routes = [
    Route('/', method='GET', handler=welcome),
    Route('/login', method='POST', handler=login),
]

components = [
    JWT({
        'JWT_USER_ID': 'id',
        'JWT_USER_NAME': 'email',
        'JWT_ALGORITHMS': ['HS256'],
        'JWT_SECRET': 'BZz4bHXYQD?g9YN2UksRn7*r3P(eo]P,Rt8NCWKs6VP34qmTL#8f&ruD^TtG',
        'JWT_OPTIONS': {
            'issuer': 'urn:foo',
            'audience': 'urn:bar',
            'leeway': 10,
        },
    }),
]

app = App(routes=routes, components=components)

if __name__ == '__main__':
    app.main()
