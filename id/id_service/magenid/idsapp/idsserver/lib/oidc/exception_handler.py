try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"


class RedirectUriError(Exception):

    error = 'Redirect URI Error'
    description = 'The request fails due to a missing, invalid, or mismatching redirection URI (redirect_uri).'


class ClientIdException(Exception):

    error = 'Client ID Error'
    description = 'The client identifier (client_id) is missing or invalid.'


class AuthorizationException(Exception):

    _errors = {

        'invalid_request': 'The request is otherwise malformed',

        'unauthorized_client': 'The client is not authorized to request an '
                               'authorization code using this method',

        'access_denied': 'The resource owner or authorization server denied '
                         'the request',

        'unsupported_response_type': 'The authorization server does not '
                                     'support obtaining an authorization code '
                                     'using this method',

        'invalid_scope': 'The requested scope is invalid, unknown, or '
                         'malformed',

        'server_error': 'The authorization server encountered an error',

        'temporarily_unavailable': 'The authorization server is currently '
                                   'unable to handle the request due to a '
                                   'temporary overloading or maintenance of '
                                   'the server',

        
        'interaction_required': 'The Authorization Server requires End-User '
                                'interaction of some form to proceed',

        'login_required': 'The Authorization Server requires End-User '
                          'authentication',

        'account_selection_required': 'The End-User is required to select a '
                                      'session at the Authorization Server',

        'consent_required': 'The Authorization Server requires End-User'
                            'consent',

        'invalid_request_uri': 'The request_uri in the Authorization Request '
                               'returns an error or contains invalid data',

        'invalid_request_object': 'The request parameter contains an invalid '
                                  'Request Object',

        'request_not_supported': 'The provider does not support use of the '
                                 'request parameter',

        'request_uri_not_supported': 'The provider does not support use of the '
                                     'request_uri parameter',

        'registration_not_supported': 'The provider does not support use of '
                                      'the registration parameter',
    }

    def __init__(self, redirect_uri, error, grant_type):
        self.error = error
        self.description = self._errors.get(error)
        self.redirect_uri = redirect_uri
        self.grant_type = grant_type

    def create_uri(self, redirect_uri, state):
        description = quote(self.description)

        hash_or_question = '#' if self.grant_type == 'implicit' else '?'

        uri = '{0}{1}error={2}&error_description={3}'.format(
            redirect_uri,
            hash_or_question,
            self.error,
            description)

        uri = uri + ('&state={0}'.format(state) if state else '')

        return uri

class TokenException(Exception):

    _errors = {
        'invalid_request': 'The request is otherwise malformed',

        'invalid_client': 'Client authentication failed (e.g., unknown client, '
                          'no client authentication included, or unsupported '
                          'authentication method)',

        'invalid_grant': 'The provided authorization grant or refresh token is '
                         'invalid, expired, revoked, does not match the '
                         'redirection URI used in the authorization request, '
                         'or was issued to another client',

        'unauthorized_client': 'The authenticated client is not authorized to '
                               'use this authorization grant type',

        'unsupported_grant_type': 'The authorization grant type is not '
                                  'supported by the authorization server',

        'invalid_scope': 'The requested scope is invalid, unknown, malformed, '
                         'or exceeds the scope granted by the resource owner',
    }

    def __init__(self, error):
        self.error = error
        self.description = self._errors.get(error)

    def create_dict(self):
        dic = {
            'error': self.error,
            'error_description': self.description,
        }

        return dic


class BearerTokenException(Exception):


    _errors = {
        'invalid_request': (
            'The request is otherwise malformed', 400
        ),
        'invalid_token': (
            'The access token provided is expired, revoked, malformed, '
            'or invalid for other reasons', 401
        ),
        'insufficient_scope': (
            'The request requires higher privileges than provided by '
            'the access token', 403
        ),
    }

    def __init__(self, code):
        self.code = code
        error_tuple = self._errors.get(code, ('', ''))
        self.description = error_tuple[0]
        self.status = error_tuple[1]
