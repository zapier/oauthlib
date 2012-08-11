# -*- coding: utf-8 -*-
from __future__ import absolute_import
from ...unittest import TestCase

from oauthlib.oauth2.draft25 import AuthorizationEndpoint


class AuthorizationEndpointTest(TestCase):

    client_id = u'abc'
    scopes = ['a%2f.-', 'space', 'sep%3da%2frat%2fed', 'list']
    scopes_decoded = ['a/.-', 'space', 'sep=a/rat/ed', 'list']
    state = u'abc'

    default_scope = [scopes[1]]
    default_redirect_uri = u'http%3A%2f%2fdefault.redirect%2Furi'
    default_redirect_uri_decoded = u'http://default.redirect/uri'

    base_uri = u'http://a.b/authorize?client_id=%s&state=%s&response_type=%s'

    uri = base_uri % (state, client_id, u'code')
    uri_scope = uri + u'&scope=%s' % u' '.join(default_scope)
    uri_scopes = uri + u'&scope=%s' % u' '.join(scopes)
    uri_redirect = uri + u'&redirect_uri=%s' % default_redirect_uri
    uri_redirect_extra = uri_redirect + u'%26extra%3Dparameter'
    uri_extra = uri_redirect + u'&extra=parameter'

    implicit_uri = base_uri % (state, client_id, u'token')
    implicit_uri_redirect = implicit_uri + u'&redirect_uri=%s' % default_redirect_uri
    implicit_uri_redirect_extra = implicit_uri_redirect + u'%26extra%3Dparameter'

    uri_missing = u'http%3A%2f%2fno.client.id'
    uri_unsupported = u'http://a.b/?client_id=a&response_type=invalid'
    uri_scope_invalid = uri + u'&scope=%s' % u'invalid scope'
    uri_redirect_invalid = uri_redirect + u'%23notabsolute'

    class SimpleAuthorizationEndpoint(AuthorizationEndpoint):

        def validate_client(self, client_id):
            return True

        def validate_redirect_uri(self, client_id, redirect_uri):
            return True

        def validate_scopes(self, client_id, scopes):
            return all(map(lambda scope: scope in self.valid_scopes, scopes))

        def get_default_scopes(self, client_id):
            return [self.valid_scopes[1]]

        def get_default_redirect_uri(self, client_id):
            return u'http://default.redirect/uri'

        def save_authorization_grant(self, client_id, grant, state=None):
            pass

        def save_implicit_grant(self, client_id, grant, state=None):
            pass

    def test_authorization_parameters(self):

        tests = ((self.uri, None, []),
                 (self.uri_scope, None, []),
                 (self.uri_scopes, self.scopes_decoded, []),
                 (self.uri_redirect, None, []),
                 (self.uri_extra, None, [('extra', 'parameter')]))

        for uri, scope, extras in tests:
            ae = self.SimpleAuthorizationEndpoint(valid_scopes=self.scopes_decoded)
            ae.parse_authorization_parameters(uri)
            self.assertEqual(ae.response_type, u'code')
            self.assertEqual(ae.client_id, self.client_id)
            self.assertEqual(ae.scopes, scope or self.default_scope)
            self.assertEqual(ae.redirect_uri, self.default_redirect_uri_decoded)
            self.assertEqual(ae.state, self.state)
            for attr, value in extras:
                self.assertEqual(ae.params.get(attr), value)

    def test_invalid_authorization_parameters(self):

        tests = ((self.uri_missing, AuthorizationEndpoint.InvalidRequestError),
                 (self.uri_unsupported, AuthorizationEndpoint.UnsupportedResponseTypeError),
                 (self.uri_scope_invalid, AuthorizationEndpoint.InvalidScopeError),
                 (self.uri_redirect_invalid, AuthorizationEndpoint.InvalidRequestError))

        for uri, error in tests:
            ae = self.SimpleAuthorizationEndpoint(valid_scopes=self.scopes_decoded)
            self.assertRaises(error, ae.parse_authorization_parameters, uri)

    def test_authorization_grant_response(self):

        tests = ((self.uri, []),
                 (self.uri_redirect_extra, ['extra']))

        for uri, extras in tests:
            ae = self.SimpleAuthorizationEndpoint(valid_scopes=self.scopes_decoded)
            ae.parse_authorization_parameters(uri)
            uri = ae.create_authorization_response(self.scopes_decoded)
            self.assertIn(u'state', uri)
            self.assertIn(u'code', uri)
            for value in extras:
                self.assertIn(value, uri)

    def test_implicit_grant_response(self):
        tests = ((self.implicit_uri, []),
                 (self.implicit_uri_redirect_extra, ['extra']))

        for uri, extras in tests:
            ae = self.SimpleAuthorizationEndpoint(valid_scopes=self.scopes_decoded)
            ae.parse_authorization_parameters(uri)
            uri = ae.create_authorization_response(self.scopes_decoded)
            self.assertIn(u'access_token', uri)
            self.assertIn(u'token_type', uri)
            self.assertIn(u'expires_in', uri)
            self.assertIn(u'scope', uri)
            for value in extras:
                self.assertIn(value, uri)

    def test_authorization_error_response(self):

        tests = ((u'client_id', None, u'invalid_request'),
                 (u'validate_client', lambda *x: False, u'unauthorized_client'),
                 (u'validate_scopes', lambda *x: False, u'invalid_scope'),
                 (u'validate_redirect_uri', lambda *x: False, u'access_denied'))

        for uri in (self.uri, self.implicit_uri):
            for name, attr, result in tests:
                ae = self.SimpleAuthorizationEndpoint(valid_scopes=self.scopes_decoded)
                ae.parse_authorization_parameters(uri)
                setattr(ae, name, attr)
                response_uri = ae.create_authorization_response(self.scopes_decoded)
                self.assertIn(u'error', response_uri)
                self.assertIn(result, response_uri)

    def test_not_implemented(self):
        ae = AuthorizationEndpoint()
        self.assertRaises(NotImplementedError, ae.validate_client, None)
        self.assertRaises(NotImplementedError, ae.validate_scopes, None, None)
        self.assertRaises(NotImplementedError, ae.validate_redirect_uri, None, None)
        self.assertRaises(NotImplementedError, ae.get_default_scopes, None)
        self.assertRaises(NotImplementedError, ae.get_default_redirect_uri, None)
        self.assertRaises(NotImplementedError, ae.save_authorization_grant, None, None)
        self.assertRaises(NotImplementedError, ae.save_implicit_grant, None, None)
