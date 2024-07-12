#!/usr/bin/env python3
"""AUTHORIZATION Class"""

from flask import request
from typing import TypeVar, List


def require_auth_for_dynamic_path(path: str,
                                  excluded_paths: List[str]) -> bool:
    """returns true if partial path requires authentication"""
    if len(excluded_paths) == 0:
        return True
    for item in excluded_paths:
        if path[:-1].startswith(item[:-1]):
            return False
    return True


class Auth():
    """AUTHORIZATION Class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """returns true if path requires authentication"""
        verify_dynamic_path = False
        verify_fixed_path = False

        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True

        if path[-1] != '/':
            path += '/'

        fixed_path = [
            path1 for path1 in excluded_paths if not path1.endswith('*')]
        # path like : ["/api/v1/stat*"]
        dynamic_path = [
            path1 for path1 in excluded_paths if path1.endswith('*')]

        if path not in fixed_path:
            verify_fixed_path = True
        if require_auth_for_dynamic_path(path, dynamic_path):
            verify_dynamic_path = True

        return verify_fixed_path and verify_dynamic_path

    def authorization_header(self, request=None) -> str:
        """get auth info from the authorization header"""
        if request is None or request.headers.get('Authorization') is None:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """get and return the current user"""
        return None
