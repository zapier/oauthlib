"""
oauthlib.oauth2.draft_25.errors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from oauthlib.common import urlencode
import json


class OAuth2Error(Exception):

    def __init__(self, description=None, uri=None, state=None):
        """
        description:    A human-readable ASCII [USASCII] text providing
                        additional information, used to assist the client
                        developer in understanding the error that occurred.
                        Values for the "error_description" parameter MUST NOT
                        include characters outside the set
                        %x20-21 / %x23-5B / %x5D-7E.

        uri:    A URI identifying a human-readable web page with information
                about the error, used to provide the client developer with
                additional information about the error.  Values for the
                "error_uri" parameter MUST conform to the URI- Reference
                syntax, and thus MUST NOT include characters outside the set
                %x21 / %x23-5B / %x5D-7E.

        state:  A CSRF protection value received from the client.
        """
        self.description = description
        self.uri = uri
        self.state = state

    @property
    def twotuples(self):
        error = [(u'error', self.error)]
        if self.description:
            error.append((u'error_description', self.description))
        if self.uri:
            error.append((u'error_uri', self.uri))
        if self.state:
            error.append((u'state', self.state))
        return error

    @property
    def urlencoded(self):
        return urlencode(self.twotuples)

    @property
    def json(self):
        return json.dumps(self.twotuples)
