from apistar import annotate, Include, Route
from apistar.exceptions import Forbidden
from apistar.frameworks.wsgi import WSGIApp as App
from apistar.handlers import docs_urls, static_urls
from apistar.permissions import IsAuthenticated
from apistar.types import Settings

from apistar_jwt.authentication import JWTAuthentication
from apistar_jwt.token import JWT

import datetime


def welcome(name=None):
    if name is None:
        return {'message': 'Welcome to API Star!'}
    return {'message': 'Welcome to API Star, %s!' % name}


# Fake user database
USER = {'user': 'test', 'pwd': 'pwd'}


# we override the default Authentication and Permissions policy to allow login
@annotate(authentication=[], permissions=[])
def login(user: str, pwd: str, settings: Settings) -> dict:
    # do some check with your database here to see if the user is authenticated
    if user != USER['user'] or pwd != USER['pwd']:
        raise Forbidden('invalid credentials')
    SECRET = settings['JWT'].get('SECRET')
    payload = {
        'username': user,
        'iat': datetime.datetime.utcnow(),
        'exp': datetime.datetime.utcnow() +
        datetime.timedelta(minutes=60)  #  ends in 60 minutes
    }
    token = JWT.encode(payload, secret=SECRET)
    return {'token': token}


routes = [
    Route('/', 'GET', welcome),
    Route('/login/', 'GET', login),
    Include('/docs', docs_urls),
    Include('/static', static_urls)
]

settings = {
    'AUTHENTICATION': [
        JWTAuthentication(),
    ],
    'PERMISSIONS': [
        IsAuthenticated,
    ],
    'JWT': {
        'SECRET':
        'QXp4Z83.%2F@JBiaPZ8T9YDwoasn[dn)cZ=fE}KqHMJPNka3QyPNq^KnMqL$oCsU9BC?.f9,oF2.2t4oN?[g%iq89(+'
    }
}

app = App(routes=routes, settings=settings)

if __name__ == '__main__':
    app.main()
