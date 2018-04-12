import os

from apistar import App, Route, exceptions, http, types, validators
from apistar_jwt.token import JWT, JWTUser


# Fake user database
USERS_DB = {'id': 1, 'email': 'user@example.com', 'password': 'password'}


class UserData(types.Type):
    email = validators.String()
    password = validators.String()


def welcome(user: JWTUser) -> dict:
    message = f'Welcome {user.username}#{user.id}, your login expires at {user.token["exp"]}'
    return {'message': message}


def login(data: UserData, jwt: JWT) -> dict:
    # do some check with your database here to see if the user is authenticated
    if data.email != USERS_DB['email'] or data.password != USERS_DB['password']:
        raise exceptions.Forbidden('Incorrect username or password.')
    payload = {
        'id': USERS_DB['id'],
        'username': USERS_DB['email'],
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
        'JWT_SECRET': 'BZz4bHXYQD?g9YN2UksRn7*r3P(eo]P,Rt8NCWKs6VP34qmTL#8f&ruD^TtG',
    }),
]

app = App(routes=routes, components=components)

if __name__ == '__main__':
    app.serve('127.0.0.1', 8080, use_debugger=True, use_reloader=True)
