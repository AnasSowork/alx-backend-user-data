#!/usr/bin/env python3
"""Basic auth"""

from api.v1.auth.auth import Auth
from models.user import User
import base64
from typing import Tuple, TypeVar


class BasicAuth(Auth):
    """basic auth"""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """returns the Base64 part of the Authorization header
        for a Basic Authentication:"""
        if authorization_header is None or\
                type(authorization_header) is not str:
            return None

        arr = authorization_header.split(' ')
        if arr[0] != 'Basic':
            return None
        return arr[1]

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str) -> str:
        """decode base64 encoded string and return the string"""
        if base64_authorization_header is None or\
                type(base64_authorization_header) is not str:
            return None
        try:
            base64_str = base64.b64decode(
                base64_authorization_header).decode('utf-8')
            return base64_str
        except Exception:
            return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """extract user's credentials"""
        if decoded_base64_authorization_header is None or\
                type(decoded_base64_authorization_header) is not str:
            return None, None
        if decoded_base64_authorization_header.find(':') == -1:
            return None, None

        result = decoded_base64_authorization_header.split(':', maxsplit=1)
        return result[0], result[1]

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """Get user object based on the submitted credentials by the user"""
        if user_email is None or type(user_email) is not str or\
                user_pwd is None or type(user_pwd) is not str:
            return None

        try:
            auth_user = User.search({'email': user_email})
        except Exception:
            return None

        assert not len(auth_user) > 1
        if len(auth_user) == 0:
            return None

        auth_user = auth_user[0]
        if not auth_user.is_valid_password(user_pwd):
            return None
        return auth_user

    def current_user(self, request=None) -> TypeVar('User'):
        """Get the current authenticated user"""
        base64_credential = self.extract_base64_authorization_header(
            request.headers.get('Authorization'))
        credentials = self.decode_base64_authorization_header(
            base64_credential)
        email, password = self.extract_user_credentials(credentials)
        return self.user_object_from_credentials(user_email=email,
                                                 user_pwd=password)
