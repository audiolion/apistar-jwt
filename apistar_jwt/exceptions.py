from apistar.exceptions import HTTPException


class AuthenticationFailed(HTTPException):
    default_status_code = 401
    default_detail = 'Incorrect authentication credentials.'
