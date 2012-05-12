# -*- coding: utf-8 -*-
from __future__ import absolute_import

"""
oauthlib.parameters
~~~~~~~~~~~~~~~~~~~

This module contains methods related to `section 3.5`_ of the OAuth 1.0a spec.

.. _`section 3.5`: http://tools.ietf.org/html/rfc5849#section-3.5
"""

from urlparse import urlparse, urlunparse
from . import constants, utils
from oauthlib.common import extract_params, urlencode

def get_signature_type(request):
    """**Determine the signature type of a request**
    Per `section 3.5`_ of the spec.

    .. _`section 3.5`: http://tools.ietf.org/html/rfc5849#section-3.5
    """
    signature_types = []

    # When making an OAuth-authenticated request, protocol parameters as
    # well as any other parameter using the "oauth_" prefix SHALL be
    # included in the request using one and only one of the following
    # locations, listed in order of decreasing preference:

    # 1.  The HTTP "Authorization" header field as described in
    #     `Section 3.5.1`_.
    #
    # .. _`Section 3.5.1`: http://tools.ietf.org/html/rfc5849#section-3.5.1
    if request.headers:
        headers_lower = dict(
            (k.lower(), v) for k, v in request.headers.items())
        authorization_header = headers_lower.get(u'authorization')
        if authorization_header is not None:
            header_oauth_params = utils.filter_oauth_params(
                utils.parse_authorization_header(authorization_header))
            if header_oauth_params:
                signature_types.append(constants.SIGNATURE_TYPE_AUTH_HEADER)

    # 2.  The HTTP request entity-body as described in `Section 3.5.2`_.
    #
    # .. _`Section 3.5.2`: http://tools.ietf.org/html/rfc5849#section-3.5.2
    if utils.filter_oauth_params(extract_params(request.body) or []):
        signature_types.append(constants.SIGNATURE_TYPE_BODY)

    # 3.  The HTTP request URI query as described in `Section 3.5.3`_.
    #
    # .. _`Section 3.5.3`: http://tools.ietf.org/html/rfc5849#section-3.5.3
    if utils.filter_oauth_params(request.uri_query_params):
        signature_types.append(constants.SIGNATURE_TYPE_QUERY)

    if len(signature_types) > 1:
        raise ValueError('oauth_ params must come from only 1 signature type but were found in %s' % ', '.join(
            signature_types))
    try:
        return signature_types[0]
    except IndexError:
        raise ValueError('oauth_ params are missing. Could not determine signature type.')


def prepare_headers(request, realm=None):
    """**Prepare the Authorization header.**
    Per `section 3.5.1`_ of the spec.

    Protocol parameters can be transmitted using the HTTP "Authorization"
    header field as defined by `RFC2617`_ with the auth-scheme name set to
    "OAuth" (case insensitive).

    For example::

        Authorization: OAuth realm="Example",
            oauth_consumer_key="0685bd9184jfhq22",
            oauth_token="ad180jjd733klru7",
            oauth_signature_method="HMAC-SHA1",
            oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
            oauth_timestamp="137131200",
            oauth_nonce="4572616e48616d6d65724c61686176",
            oauth_version="1.0"


    .. _`section 3.5.1`: http://tools.ietf.org/html/rfc5849#section-3.5.1
    .. _`RFC2617`: http://tools.ietf.org/html/rfc2617
    """
    if not request.oauth_params:
        raise ValueError('request.oauth_params must be present.')
    new_request = request.clone()

    # Protocol parameters SHALL be included in the "Authorization" header
    # field as follows:
    authorization_header_parameters_parts = []
    for oauth_parameter_name, value in new_request.oauth_params:
        # 1.  Parameter names and values are encoded per Parameter Encoding
        #     (`Section 3.6`_)
        #
        # .. _`Section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6
        escaped_name = utils.escape(oauth_parameter_name)
        escaped_value = utils.escape(value)

        # 2.  Each parameter's name is immediately followed by an "=" character
        #     (ASCII code 61), a """ character (ASCII code 34), the parameter
        #     value (MAY be empty), and another """ character (ASCII code 34).
        part = u'{0}="{1}"'.format(escaped_name, escaped_value)

        authorization_header_parameters_parts.append(part)

    # 3.  Parameters are separated by a "," character (ASCII code 44) and
    #     OPTIONAL linear whitespace per `RFC2617`_.
    #
    # .. _`RFC2617`: http://tools.ietf.org/html/rfc2617
    authorization_header_parameters = ', '.join(
        authorization_header_parameters_parts)

    # 4.  The OPTIONAL "realm" parameter MAY be added and interpreted per
    #     `RFC2617 section 1.2`_.
    #
    # .. _`RFC2617 section 1.2`: http://tools.ietf.org/html/rfc2617#section-1.2
    if realm:
        # NOTE: realm should *not* be escaped
        authorization_header_parameters = (u'realm="%s", ' % realm +
            authorization_header_parameters)

    # the auth-scheme name set to "OAuth" (case insensitive).
    authorization_header = u'OAuth %s' % authorization_header_parameters

    # contribute the Authorization header to the given headers
    new_request.headers[u'Authorization'] = authorization_header
    return new_request


def _append_params(oauth_params, params):
    """Append OAuth params to an existing set of parameters.

    Both params and oauth_params is must be lists of 2-tuples.

    Per `section 3.5.2`_ and `3.5.3`_ of the spec.

    .. _`section 3.5.2`: http://tools.ietf.org/html/rfc5849#section-3.5.2
    .. _`3.5.3`: http://tools.ietf.org/html/rfc5849#section-3.5.3

    """
    merged = list(params)
    merged.extend(oauth_params)
    # The request URI / entity-body MAY include other request-specific
    # parameters, in which case, the protocol parameters SHOULD be appended
    # following the request-specific parameters, properly separated by an "&"
    # character (ASCII code 38)
    merged.sort(key=lambda i: i[0].startswith('oauth_'))
    return merged


def prepare_form_encoded_body(request):
    """Prepare the Form-Encoded Body.

    Per `section 3.5.2`_ of the spec.

    .. _`section 3.5.2`: http://tools.ietf.org/html/rfc5849#section-3.5.2

    """
    if not request.oauth_params:
        raise ValueError('request.oauth_params must be present.')

    # append OAuth params to the existing body
    new_request = request.clone()
    body = _append_params(new_request.oauth_params, new_request.body)
    new_request.body = body
    new_request.headers['Content-Type'] = u'application/x-www-form-urlencoded'
    return new_request


def prepare_request_uri_query(request):
    """Prepare the Request URI Query.

    Per `section 3.5.3`_ of the spec.

    .. _`section 3.5.3`: http://tools.ietf.org/html/rfc5849#section-3.5.3

    """
    new_request = request.clone()

    # append OAuth params to the existing set of query components
    sch, net, path, par, query, fra = urlparse(new_request.uri)
    query = urlencode(_append_params(new_request.oauth_params,
        extract_params(query) or []))
    new_request.uri = urlunparse((sch, net, path, par, query, fra))
    return new_request


PREPARE_BY_SIGNATURE_TYPE = {
    constants.SIGNATURE_TYPE_AUTH_HEADER: prepare_headers,
    constants.SIGNATURE_TYPE_QUERY: prepare_form_encoded_body,
    constants.SIGNATURE_TYPE_BODY: prepare_request_uri_query,
}


def prepare_request(request, signature_type):
    try:
        return PREPARE_BY_SIGNATURE_TYPE[signature_type](request)
    except KeyError:
        raise ValueError('Unknown signature type specified.')

