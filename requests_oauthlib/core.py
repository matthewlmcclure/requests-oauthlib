# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import urlparse

from oauthlib.common import extract_params
from oauthlib.oauth1 import (Client, SIGNATURE_HMAC, SIGNATURE_TYPE_AUTH_HEADER)

CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded'
CONTENT_TYPE_MULTI_PART = 'multipart/form-data'

import sys
if sys.version > "3":
    unicode = str

# OBS!: Correct signing of requests are conditional on invoking OAuth1
# as the last step of preparing a request, or at least having the
# content-type set properly.
class OAuth1(object):
    """Signs the request using OAuth 1 (RFC5849)"""
    def __init__(self, client_key,
            client_secret=None,
            resource_owner_key=None,
            resource_owner_secret=None,
            callback_uri=None,
            signature_method=SIGNATURE_HMAC,
            signature_type=SIGNATURE_TYPE_AUTH_HEADER,
            rsa_key=None, verifier=None,
            decoding='utf-8'):

        try:
            signature_type = signature_type.upper()
        except AttributeError:
            pass

        self.client = Client(client_key, client_secret, resource_owner_key,
            resource_owner_secret, callback_uri, signature_method,
            signature_type, rsa_key, verifier, decoding=decoding)

    def __call__(self, r):
        """Add OAuth parameters to the request.

        Parameters may be included from the body if the content-type is
        urlencoded, if no content type is set a guess is made.
        """
        # Overwriting url is safe here as request will not modify it past
        # this point.

        content_type = r.headers.get('Content-Type'.encode('utf-8'), '')
        if not isinstance(content_type, unicode):
            content_type = content_type.decode('utf-8')

        is_form_encoded = (CONTENT_TYPE_FORM_URLENCODED in content_type)

        # 3.4.1.2.  Base String URI
        #
        #    The scheme, authority, and path of the request resource URI [RFC3986]
        #    are included by constructing an "http" or "https" URI representing
        #    the request resource (without the query or fragment) as follows:
        #
        #    ...
        #
        #    2.  The host and port values MUST match the content of the HTTP
        #        request "Host" header field.
        parsed_request_url = urlparse.urlparse(r.url)
        parsed_host_header_url = parsed_request_url._replace(
            netloc=r.headers['Host'])
        signature_input_url = urlparse.urlunparse(parsed_host_header_url)

        if is_form_encoded or extract_params(r.body):
            r.headers['Content-Type'] = CONTENT_TYPE_FORM_URLENCODED
            r.url, r.headers, r.body = self.client.sign(
                unicode(signature_input_url), unicode(r.method), r.body or '',
                r.headers)
        else:
            # Omit body data in the signing of non form-encoded requests
            r.url, r.headers, _ = self.client.sign(
                unicode(signature_input_url), unicode(r.method), None, r.headers)

        parsed_signed_host_header_url = urlparse.urlparse(r.url)
        parsed_signed_request_url = parsed_signed_host_header_url._replace(
            netloc=parsed_request_url.netloc)
        r.url = urlparse.urlunparse(parsed_signed_request_url)

        # Having the authorization header, key or value, in unicode will
        # result in UnicodeDecodeErrors when the request is concatenated
        # by httplib. This can easily be seen when attaching files.
        # Note that simply encoding the value is not enough since Python
        # saves the type of first key set. Thus we remove and re-add.
        # >>> d = {u'a':u'foo'}
        # >>> d['a'] = 'foo'
        # >>> d
        # { u'a' : 'foo' }
        u_header = unicode('Authorization')
        if u_header in r.headers:
            auth_header = r.headers[u_header].encode('utf-8')
            del r.headers[u_header]
            r.headers['Authorization'] = auth_header

        return r
