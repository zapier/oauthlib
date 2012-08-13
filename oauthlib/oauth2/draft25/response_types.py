"""
oauthlib.oauth2.draft_25.response_types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from oauthlib.common import add_params_to_uri, generate_token
from errors import OAuth2Error


class AuthorizationCodeGrantCodeHandler(object):

    def __call__(self, endpoint):
        self.endpoint = endpoint
        try:
            self.endpoint.validate_request(self.endpoint.request)

        except OAuth2Error as e:
            return add_params_to_uri(self.endpoint.request.redirect_uri, e.twotuples)

        self.grant = self.create_authorization_grant()
        self.endpoint.save_authorization_grant(
                self.endpoint.request.client_id, self.grant, state=self.endpoint.request.state)
        return add_params_to_uri(self.endpoint.request.redirect_uri, self.grant.items())

    def create_authorization_grant(self):
        """Generates an authorization grant represented as a dictionary."""
        grant = {u'code': generate_token()}
        if self.endpoint.request.state:
            grant[u'state'] = self.endpoint.request.state
        return grant


class ImplicitGrantTokenHandler(object):

    @property
    def expires_in(self):
        return 3600

    def create_token(self):
        return {
            u'access_token': generate_token(),
            u'expires_in': self.expires_in,
            u'scope': ' '.join(self.endpoint.request.scopes),
            u'state': self.endpoint.request.state
        }

    def __call__(self, endpoint):
        self.endpoint = endpoint
        try:
            self.endpoint.validate_request(self.endpoint.request)

        except OAuth2Error as e:
            return add_params_to_uri(
                    self.endpoint.request.redirect_uri, e.twotuples, fragment=True)

        self.token = self.create_token()
        self.token = self.endpoint.token_handler(self, self.token)
        self.endpoint.save_implicit_grant(
                self.endpoint.request.client_id, self.token, state=self.endpoint.request.state)
        return add_params_to_uri(
                self.endpoint.request.redirect_uri, self.token.items(), fragment=True)
