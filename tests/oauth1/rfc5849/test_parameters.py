# -*- coding: utf-8 -*-
from __future__ import absolute_import
from oauthlib.common import urlencode, Request
from oauthlib.oauth1.rfc5849.parameters import (_append_params, prepare_headers,
    prepare_form_encoded_body, prepare_request_uri_query)
from ...unittest import TestCase


class ParameterTests(TestCase):
    data_params = [
        (u'data_param_foo', u'foo'),
        (u'data_param_1', u'1'),
    ]
    auth_only_params = [
        (u'oauth_consumer_key', u"9djdj82h48djs9d2"),
        (u'oauth_token', u"kkk9d7dh3k39sjv7"),
        (u'oauth_signature_method', u"HMAC-SHA1"),
        (u'oauth_timestamp', u"137131201"),
        (u'oauth_nonce', u"7d8f3e4a"),
        (u'oauth_signature', u"bYT5CMsGcbgUdFHObYMEfcx6bsw=")
    ]
    auth_and_data = auth_only_params + data_params
    realm = u'testrealm'
    norealm_authorization_header = u' '.join((
        u'OAuth',
        u'oauth_consumer_key="9djdj82h48djs9d2",',
        u'oauth_token="kkk9d7dh3k39sjv7",',
        u'oauth_signature_method="HMAC-SHA1",',
        u'oauth_timestamp="137131201",',
        u'oauth_nonce="7d8f3e4a",',
        u'oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"',
    ))
    withrealm_authorization_header = u' '.join((
        u'OAuth',
        u'realm="testrealm",',
        u'oauth_consumer_key="9djdj82h48djs9d2",',
        u'oauth_token="kkk9d7dh3k39sjv7",',
        u'oauth_signature_method="HMAC-SHA1",',
        u'oauth_timestamp="137131201",',
        u'oauth_nonce="7d8f3e4a",',
        u'oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"',
    ))

    def test_append_params(self):
        unordered_1 = [
            ('oauth_foo', 'foo'),
            ('lala', 123),
            ('oauth_baz', 'baz'),
            ('oauth_bar', 'bar'), ]
        unordered_2 = [
            ('teehee', 456),
            ('oauth_quux', 'quux'), ]
        expected = [
            ('teehee', 456),
            ('lala', 123),
            ('oauth_quux', 'quux'),
            ('oauth_foo', 'foo'),
            ('oauth_baz', 'baz'),
            ('oauth_bar', 'bar'), ]
        self.assertEqual(_append_params(unordered_1, unordered_2), expected)

    def test_prepare_headers(self):
        request = Request(u'http://www.google.com/')
        request.oauth_params = self.auth_only_params
        self.assertEqual(
            prepare_headers(request).headers,
            {u'Authorization': self.norealm_authorization_header})

    def test_prepare_headers_with_realm(self):
        request = Request(u'http://www.google.com/')
        request.oauth_params = self.auth_only_params
        self.assertEqual(
            prepare_headers(request, realm=self.realm).headers,
            {u'Authorization': self.withrealm_authorization_header})

    def test_prepare_form_encoded_body(self):
        request = Request(u'http://www.google.com/', body=self.data_params)
        request.oauth_params = self.auth_only_params
        form_encoded_body = u'data_param_foo=foo&data_param_1=1&oauth_consumer_key=9djdj82h48djs9d2&oauth_token=kkk9d7dh3k39sjv7&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_nonce=7d8f3e4a&oauth_signature=bYT5CMsGcbgUdFHObYMEfcx6bsw%3D'
        self.assertEqual(
            urlencode(prepare_form_encoded_body(request).body),
            form_encoded_body)

    def test_prepare_request_uri_query(self):
        request = Request(u'http://notarealdomain.com/foo/bar/baz?some=args&go=here')
        request.oauth_params = self.auth_only_params
        request_uri_query = u'http://notarealdomain.com/foo/bar/baz?some=args&go=here&oauth_consumer_key=9djdj82h48djs9d2&oauth_token=kkk9d7dh3k39sjv7&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_nonce=7d8f3e4a&oauth_signature=bYT5CMsGcbgUdFHObYMEfcx6bsw%3D'
        self.assertEqual(
            prepare_request_uri_query(request).uri,
            request_uri_query)

