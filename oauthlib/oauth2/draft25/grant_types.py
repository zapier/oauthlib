"""
oauthlib.oauth2.draft_25.grant_types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from oauthlib.common import generate_token, add_params_to_uri
from oauthlib.uri_validate import is_absolute_uri
import json
import errors


class RequestValidator(object):

    @property
    def response_types(self):
        return (u'code', u'token')

    def validate_request(self, request, response_types=None):
        request.state = getattr(request, u'state', None)
        response_types = response_types or self.response_types or []

        if not request.client_id:
            raise errors.InvalidRequestError(state=request.state,
                    description=u'Missing client_id parameter.')

        if not request.response_type:
            raise errors.InvalidRequestError(state=request.state,
                    description=u'Missing response_type parameter.')

        if not self.validate_client(request.client_id):
            raise errors.UnauthorizedClientError(state=request.state)

        if not request.response_type in response_types:
            raise errors.UnsupportedResponseTypeError(state=request.state)

        self.validate_request_scopes(request)

        if getattr(request, u'redirect_uri', None):
            if not is_absolute_uri(request.redirect_uri):
                raise errors.InvalidRequestError(state=request.state,
                        description=u'Non absolute redirect URI. See RFC3986')

            if not self.validate_redirect_uri(request.client_id, request.redirect_uri):
                raise errors.AccessDeniedError(state=request.state)
        else:
            request.redirect_uri = self.get_default_redirect_uri(request.client_id)
            if not request.redirect_uri:
                raise errors.AccessDeniedError(state=request.state)

        return True

    def validate_request_scopes(self, request):
        if request.scopes:
            if not self.validate_scopes(request.client_id, request.scopes):
                raise errors.InvalidScopeError(state=request.state)
        else:
            request.scopes = self.get_default_scopes(request.client_id)

    def validate_client(self, client, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_scopes(self, client, scopes):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_user(self, username, password, client=None):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_redirect_uri(self, client, redirect_uri):
        raise NotImplementedError('Subclasses must implement this method.')

    def get_default_redirect_uri(self, client):
        raise NotImplementedError('Subclasses must implement this method.')

    def get_default_scopes(self, client):
        raise NotImplementedError('Subclasses must implement this method.')


class GrantTypeBase(object):

    def create_authorization_response(self, request):
        raise NotImplementedError('Subclasses must implement this method.')

    def create_token_response(self, request, token_handler):
        raise NotImplementedError('Subclasses must implement this method.')


class AuthorizationCodeGrant(GrantTypeBase):

    @property
    def scopes(self):
        return ('default',)

    @property
    def error_uri(self):
        return u'/oauth_error'

    def __init__(self, request_validator=None):
        self.request_validator = request_validator or RequestValidator()

    def create_authorization_code(self, request):
        """Generates an authorization grant represented as a dictionary."""
        grant = {u'code': generate_token()}
        if hasattr(request, 'state') and request.state:
            grant[u'state'] = request.state
        return grant

    def save_authorization_code(self, client_id, grant):
        """Saves authorization codes for later use by the token endpoint."""
        raise NotImplementedError('Subclasses must implement this method.')

    def create_authorization_response(self, request):
        try:
            self.request_validator.validate_request(request)

        except errors.OAuth2Error as e:
            request.redirect_uri = getattr(request, u'redirect_uri',
                    self.error_uri)
            return add_params_to_uri(request.redirect_uri, e.twotuples)

        grant = self.create_authorization_code(request)
        self.save_authorization_code(request.client_id, grant)
        return add_params_to_uri(request.redirect_uri, grant.items())

    def create_token_response(self, request, token_handler):
        """Validate the authorization code.

        The client MUST NOT use the authorization code more than once. If an
        authorization code is used more than once, the authorization server
        MUST deny the request and SHOULD revoke (when possible) all tokens
        previously issued based on that authorization code. The authorization
        code is bound to the client identifier and redirection URI.
        """
        try:
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            return e.json
        return json.dumps(token_handler(request, refresh_token=True))

    def validate_token_request(self, request):

        if getattr(request, u'grant_type', '') != u'authorization_code':
            raise errors.UnsupportedGrantTypeError()

        if not getattr(request, u'code', None):
            raise errors.InvalidRequestError(
                    description=u'Missing code parameter.')

        # TODO: document diff client & client_id, former is authenticated
        # outside spec, i.e. http basic
        if (not hasattr(request, 'client') or
            not self.request_validator.validate_client(request.client, request.grant_type)):
            raise errors.UnauthorizedClientError()

        if not self.request_validator.validate_code(request.client, request.code):
            raise errors.InvalidGrantError()

    # TODO: validate scopes


class ImplicitGrant(GrantTypeBase):

    def __init__(self, request_validator=None):
        self.request_validator = request_validator or RequestValidator()

    def create_token_response(self, request, token_handler):
        try:
            self.request_validator.validate_request(request)

        except errors.OAuth2Error as e:
            return add_params_to_uri(request.redirect_uri, e.twotuples,
                    fragment=True)

        token = token_handler(request, refresh_token=False)
        return add_params_to_uri(request.redirect_uri, token.items(),
                fragment=True)


class ResourceOwnerPasswordCredentialsGrant(GrantTypeBase):
    """`Resource Owner Password Credentials Grant`_

    .. _`Resource Owner Password Credentials Grant`: http://tools.ietf.org/html/rfc6749#section-4.3
    """

    def __init__(self, request_validator=None):
        self.request_validator = request_validator or RequestValidator()

    def create_token_response(self, request, token_handler,
            require_authentication=True):
        """Return token or error in json format.

        The client makes a request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format per Appendix B with a character encoding of UTF-8 in the HTTP
        request entity-body:

        grant_type
                REQUIRED.  Value MUST be set to "password".

        username
                REQUIRED.  The resource owner username.

        password
                REQUIRED.  The resource owner password.

        scope
                OPTIONAL.  The scope of the access request as described by
                `Section 3.3`_.

        If the client type is confidential or the client was issued client
        credentials (or assigned other authentication requirements), the
        client MUST authenticate with the authorization server as described
        in `Section 3.2.1`_.

        For example, the client makes the following HTTP request using
        transport-layer security (with extra line breaks for display purposes
        only):

            POST /token HTTP/1.1
            Host: server.example.com
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
            Content-Type: application/x-www-form-urlencoded

            grant_type=password&username=johndoe&password=A3ddj3w

        The authorization server MUST:

        o  require client authentication for confidential clients or for any
            client that was issued client credentials (or with other
            authentication requirements),

        o  authenticate the client if client authentication is included, and

        o  validate the resource owner password credentials using its
            existing password validation algorithm.

        Since this access token request utilizes the resource owner's
        password, the authorization server MUST protect the endpoint against
        brute force attacks (e.g., using rate-limitation or generating
        alerts).

        .. _`Section 3.3`: http://tools.ietf.org/html/rfc6749#section-3.3
        .. _`Section 3.2.1`: http://tools.ietf.org/html/rfc6749#section-3.2.1
        """
        try:
            if require_authentication:
                self.request_validator.authenticate_client(request)
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            return None, {}, e.json
        return None, {}, json.dumps(token_handler(request, refresh_token=True))

    def validate_token_request(self, request):
        for param in ('grant_type', 'username', 'password'):
            if not getattr(request, param):
                raise errors.InvalidRequestError(
                        'Request is missing %s parameter.' % param)

        # This error should rarely (if ever) occur if requests are routed to
        # grant type handlers based on the grant_type parameter.
        if not request.grant_type == 'password':
            raise errors.UnsupportedGrantTypeError()

        # request.client is populated during client authentication
        client = request.client if getattr(request, 'client') else None
        if not self.request_validator.validate_user(request.username,
                request.password, client=client):
            raise errors.InvalidGrantError('Invalid credentials given.')

        self.request_validator.validate_request_scopes(request)


class ClientCredentialsGrant(GrantTypeBase):
    """`Client Credentials Grant`_

    .. _`Client Credentials Grant`: http://tools.ietf.org/html/rfc6749#section-4.4
    """

    def __init__(self, request_validator=None):
        self.request_validator = request_validator or RequestValidator()

    def create_token_response(self, request, token_handler):
        """Return token or error in JSON format.

        The client can request an access token using only its client
        credentials (or other supported means of authentication) when the
        client is requesting access to the protected resources under its
        control, or those of another resource owner that have been previously
        arranged with the authorization server (the method of which is beyond
        the scope of this specification).

        The client credentials grant type MUST only be used by confidential
        clients.

            +---------+                                  +---------------+
            |         |                                  |               |
            |         |>--(A)- Client Authentication --->| Authorization |
            | Client  |                                  |     Server    |
            |         |<--(B)---- Access Token ---------<|               |
            |         |                                  |               |
            +---------+                                  +---------------+

                            Figure 6: Client Credentials Flow

        The flow illustrated in Figure 6 includes the following steps:

        (A)  The client authenticates with the authorization server and
                requests an access token from the token endpoint.

        (B)  The authorization server authenticates the client, and if valid,
                issues an access token.
        """
        try:
            self.request_validator.authenticate_client(request)
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            return e.json
        return json.dumps(token_handler(request, refresh_token=True))

    def validate_token_request(self, request):
        if not getattr(request, 'grant_type'):
            raise errors.InvalidRequestError('Request is issing grant type.')

        if not request.grant_type == 'client_credentials':
            raise errors.UnsupportedGrantTypeError()

        self.request_validator.validate_request_scopes(request)
