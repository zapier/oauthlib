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

        if request.scopes:
            if not self.validate_scopes(request.client_id, request.scopes):
                raise errors.InvalidScopeError(state=request.state)
        else:
            request.scopes = self.get_default_scopes(request.client_id)

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

    def validate_client(self, client, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_scopes(self, client, scopes):
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

        if not self.validate_code(request.client, request.code):
            raise errors.InvalidGrantError()

    # TODO: validate scopes

    def validate_code(self, client, code):
        raise NotImplementedError('Subclasses must implement this method.')


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

    def __init__(self, request_validator=None):
        self.request_validator = request_validator or RequestValidator()

    def create_token_response(self, request, token_handler):
        try:
            self.validate_token_request(request)

        except errors.OAuth2Error as e:
            return e.json

        return json.dumps(token_handler(request, refresh_token=True))

    def validate_token_request(self, request):
        # validate grant type, username, password, scope
        pass


class ClientCredentialsGrant(GrantTypeBase):

    def __init__(self, request_validator=None):
        self.request_validator = request_validator or RequestValidator()

    def create_token_response(self, request, token_handler):
        try:
            self.validate_token_request(request)

        except errors.OAuth2Error as e:
            return e.json

        return json.dumps(token_handler(request, refresh_token=True))

    def validate_token_request(self, request):
        # validate grant type, scope
        pass
