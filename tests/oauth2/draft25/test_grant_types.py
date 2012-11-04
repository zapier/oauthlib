# -*- coding: utf-8 -*-
from __future__ import absolute_import
from ...unittest import TestCase

import json
import mock
from oauthlib.common import Request
from oauthlib.oauth2.draft25.errors import UnsupportedGrantTypeError
from oauthlib.oauth2.draft25.errors import InvalidRequestError
from oauthlib.oauth2.draft25.errors import UnauthorizedClientError
from oauthlib.oauth2.draft25.errors import InvalidGrantError
from oauthlib.oauth2.draft25.grant_types import AuthorizationCodeGrant
from oauthlib.oauth2.draft25.grant_types import ImplicitGrant
from oauthlib.oauth2.draft25.grant_types import ResourceOwnerPasswordCredentialsGrant
from oauthlib.oauth2.draft25.tokens import BearerToken


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

        mock_validator = mock.MagicMock()
        self.auth = AuthorizationCodeGrant(request_validator=mock_validator)

    def test_create_authorization_grant(self):
        grant = self.auth.create_authorization_code(self.request)
        self.assertIn(u'code', grant)

        grant = self.auth.create_authorization_code(self.request_state)
        self.assertIn(u'code', grant)
        self.assertIn(u'state', grant)

    def test_create_token_response(self):
        bearer = BearerToken()
        bearer.save_token = mock.MagicMock()
        token = self.auth.create_token_response(self.request, bearer)
        token = json.loads(token)
        self.assertIn('access_token', token)
        self.assertIn('refresh_token', token)
        self.assertIn('expires_in', token)
        self.assertIn('scope', token)

    def test_validate_token_request(self):
        mock_validator = mock.MagicMock()
        auth = AuthorizationCodeGrant(request_validator=mock_validator)
        request = Request(u'http://a.b/path')
        self.assertRaises(UnsupportedGrantTypeError,
                auth.validate_token_request, request)

        request.grant_type = u'authorization_code'
        self.assertRaises(InvalidRequestError,
                auth.validate_token_request, request)

        mock_validator.validate_client = mock.MagicMock(return_value=False)
        request.code = u'waffles'
        request.client = u'batman'
        self.assertRaises(UnauthorizedClientError,
                auth.validate_token_request, request)

        mock_validator.validate_client = mock.MagicMock(return_value=True)
        mock_validator.validate_code = mock.MagicMock(return_value=False)
        self.assertRaises(InvalidGrantError,
                auth.validate_token_request, request)


class ImplicitGrantTest(TestCase):

    def setUp(self):
        # TODO: query params
        self.request = Request(u'http://a.b/path')
        self.mock_validator = mock.MagicMock()
        self.auth = ImplicitGrant(request_validator=self.mock_validator)

    def test_create_token_response(self):
        # ensure json parsable containing all we want
        pass

    def test_validate_token_response(self):
        # wrong grant type, user, pass, scope errors
        pass


class ResourceOwnerPasswordCredentialsGrantTest(TestCase):

    def setUp(self):
        self.request = Request('http://a.b/path')
        self.request.grant_type = 'password'
        self.request.username = 'john'
        self.request.password = 'doe'
        self.request.client = 'mock authenticated'
        self.request.scopes = ('mocked', 'scopes')
        self.mock_validator = mock.MagicMock()
        self.auth = ResourceOwnerPasswordCredentialsGrant(
                request_validator=self.mock_validator)

    def test_create_token_response(self):
        bearer = BearerToken()
        bearer.save_token = mock.MagicMock()
        uri, headers, body = self.auth.create_token_response(
                self.request, bearer)
        token = json.loads(body)
        self.assertIn('access_token', token)
        self.assertIn('token_type', token)
        self.assertIn('expires_in', token)
        self.assertIn('refresh_token', token)

    def test_invalid_arguments(self):
        pass

    def test_scopes(self):
        pass


class ClientCredentialsGrantTest(TestCase):

    def test_create_token_response(self):
        # ensure json parsable containing all we want
        pass

    def test_validate_token_response(self):
        # wrong grant type, scope
        pass
