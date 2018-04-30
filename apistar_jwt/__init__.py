"""Top-level package for apistar-jwt."""

from apistar_jwt.token import JWTUser, JWT
from apistar_jwt.decorators import anonymous_allowed, authentication_required


__author__ = """Ryan Castner"""
__email__ = 'castner.rr@gmail.com'
__version__ = '0.5.0'

__all__ = ['JWTUser', 'JWT', 'anonymous_allowed', 'authentication_required']
