from apistar.exceptions import ConfigurationError
from apistar.types import Settings
import jwt

from .exceptions import AuthenticationFailed


class JWT():
    def __init__(self, settings: Settings, token=None, issuer=None, audience=None, leeway=None):
        jwt_settings = settings.get('JWT', {})
        self.secret = jwt_settings.get('SECRET', None)
        if self.secret is None:
            msg = 'The SECRET setting under JWT settings must be defined.'
            raise ConfigurationError(msg) from None
        self.algorithms = jwt_settings.get('ALGORITHMS', ['HS256'])
        self.token = token
        self.issuer = issuer if issuer is not None else jwt_settings.get('ISSUER', None)
        self.audience = audience if audience is not None else jwt_settings.get('AUDIENCE', None)
        self.leeway = leeway if leeway is not None else jwt_settings.get('LEEWAY', None)
        try:
            kwargs = {}
            if self.issuer:
                kwargs.update({'issuer': self.issuer})
            if self.audience:
                kwargs.update({'audience': self.audience})
            if self.leeway:
                kwargs.update({'leeway': self.leeway})
            self.payload = jwt.decode(
                self.token, self.secret, algorithms=self.algorithms, **kwargs)
        except Exception:
            self.payload = None
            raise AuthenticationFailed()

    @staticmethod
    def encode(payload, secret=None, algorithm=None, **kwargs):
        if secret is None:
            msg = 'The secret keyword argument must be defined.'
            raise ConfigurationError(msg) from None
        algorithm = 'HS256' if algorithm is None else algorithm
        try:
            token = jwt.encode(
                payload, secret, algorithm=algorithm, **kwargs).decode(encoding='UTF-8')
        except Exception as exc:
            raise ConfigurationError(exc.__class__.__name__) from None
        return token
