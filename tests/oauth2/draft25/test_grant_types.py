# -*- coding: utf-8 -*-
from __future__ import absolute_import
from ...unittest import TestCase

import json
from oauthlib.common import Request
from oauthlib.oauth2.draft25.errors import UnsupportedGrantTypeError
from oauthlib.oauth2.draft25.errors import InvalidRequestError
from oauthlib.oauth2.draft25.errors import UnauthorizedClientError
from oauthlib.oauth2.draft25.errors import InvalidGrantError
from oauthlib.oauth2.draft25.grant_types import AuthorizationCodeGrant
from oauthlib.oauth2.draft25.grant_types import ImplicitGrant


class AuthorizationCodeGrantTest(TestCase):

    def setUp(self):
        self.request = Request(u'http://a.b/path')
        self.request.scopes = (u'hello', u'world')
        self.request.expires_in = 1800
        self.request.client = u'batman'
        self.request.client_id = u'abcdef'
        self.request.code = u'1234'
        self.request.response_type = u'code'
        self.request.grant_type = u'authorization_code'

        self.request_state = Request(u'http://a.b/path')
        self.request_state.state = u'abc'

        self.auth = AuthorizationCodeGrant()
        self.auth.save_authorization_code = lambda *args: None
        self.auth.save_authorization_token = lambda *args: None
        self.auth.validate_client = lambda *args: True
        self.auth.validate_code = lambda *args: True
        self.auth.validate_scopes = lambda *args: True
        self.auth.get_default_redirect_uri = lambda *args: u'http://a.b/path'
        self.auth.get_scopes = lambda *args: ('default',)

    def test_create_authorization_grant(self):
        grant = self.auth.create_authorization_code(self.request)
        self.assertIn(u'code', grant)

        grant = self.auth.create_authorization_code(self.request_state)
        self.assertIn(u'code', grant)
        self.assertIn(u'state', grant)

    def test_create_token(self):
        token = self.auth.create_authorization_token(self.request)
        self.assertIn(u'access_token', token)
        self.assertIn(u'refresh_token', token)
        self.assertIn(u'expires_in', token)
        self.assertEqual(token[u'expires_in'], self.request.expires_in)

    def test_create_authorization_response(self):
        uri = self.auth.create_authorization_response(self.request)
        self.assertIn('code', uri)

    def test_create_token_response(self):
        token = self.auth.create_token_response(self.request, lambda x: x)
        token = json.loads(token)
        self.assertIn('access_token', token)
        self.assertIn('refresh_token', token)
        self.assertIn('expires_in', token)
        self.assertIn('scope', token)

    def test_validate_token_request(self):
        auth = AuthorizationCodeGrant()
        request = Request(u'http://a.b/path')
        self.assertRaises(UnsupportedGrantTypeError,
                auth.validate_token_request, request)

        request.grant_type = u'authorization_code'
        self.assertRaises(InvalidRequestError,
                auth.validate_token_request, request)

        auth.validate_client = lambda *args: False
        request.code = u'waffles'
        request.client = u'batman'
        self.assertRaises(UnauthorizedClientError,
                auth.validate_token_request, request)

        auth.validate_client = lambda *args: True
        auth.validate_code = lambda *args: False
        self.assertRaises(InvalidGrantError,
                auth.validate_token_request, request)
