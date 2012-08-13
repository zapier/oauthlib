"""
oauthlib.oauth2.draft_25.errors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from oauthlib.common import generate_token
from errors import OAuth2Error
import json


class AuthorizationCodeGrantTokenHandler(object):

    @property
    def expires_in(self):
        return 3600

    def create_token(self):
        return {
            u'access_token': generate_token(),
            u'refresh_token': generate_token(),
            u'expires_in': self.expires_in,
            u'scope': ' '.join(self.scopes),
        }

    def validate_request(self, request):

        # This will likely already be checked but including anyway
        if not request.grant_type == u'authorization_code':
            raise self.endpoint.UnsupportedGrantTypeError()

        if not request.code:
            raise self.endpoint.InvalidRequestError(
                    description=u'Missing code parameter.')

        if not self.endpoint.client:
            raise self.endpoint.InvalidClientError(u'unrecognized client')

        if not self.validate_client(self.endpoint.client, request.grant_type):
            raise self.endpoint.UnauthorizedClientError()

        if not self.validate_code(self.endpoint.client, request.code):
            raise self.endpoint.InvalidGrantError()

    def validate_client(self, client, grant_type):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_code(self, client, code):
        raise NotImplementedError('Subclasses must implement this method.')

    def get_scopes(self, client, code):
        raise NotImplementedError('Subclasses must implement this method.')

    def __call__(self, endpoint):
        """Validate the authorization code.

        The client MUST NOT use the authorization code more than once. If an
        authorization code is used more than once, the authorization server
        MUST deny the request and SHOULD revoke (when possible) all tokens
        previously issued based on that authorization code. The authorization
        code is bound to the client identifier and redirection URI.
        """
        self.endpoint = endpoint
        self.endpoint.request.grant_type = self.endpoint.request.params.get(u'grant_type')
        self.endpoint.request.code = self.endpoint.request.params.get(u'code')
        self.endpoint.request.redirect_uri = self.endpoint.request.params.get(u'redirect_uri')

        try:
            self.validate_request(self.endpoint.request)

        except OAuth2Error as e:
            return e.json

        self.scopes = self.get_scopes(self.endpoint.client, self.endpoint.request.code)
        self.token = self.create_token()
        self.token = self.endpoint.token_handler(self, self.token)
        return json.dumps(self.token)
