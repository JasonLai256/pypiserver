# -*- coding: utf-8 -*-

import re
import hmac
import time
import base64
from hashlib import sha1 as sha

from bottle import HTTPError


class EasyHmacAuthHandler:
    """Implements the HMAC auth signing."""

    auth_header = 'pypiserver'
    default_expire_seconds = 300
    auth_file = '/etc/pypiauth.key'

    def __init__(self, access_key=None, secret_key=None):
        with open(self.auth_file) as f:
            akey, skey = f.read().strip().split(':')
        self.access_key = access_key if access_key else akey
        self.secret_key = secret_key if secret_key else skey
        self.auth_ip_pool = {}
        self.ma_ptn = re.compile(r'max-age=([0-9]+)')

    def _get_hmac(self):
        return hmac.new(self.secret_key, digestmod=sha)

    def sign_string(self, string_to_sign):
        new_hmac = self._get_hmac()
        new_hmac.update(string_to_sign)
        return base64.encodestring(new_hmac.digest()).strip()

    def check_ip_auth(self, request, **kwargs):
        rv = False
        now = int(time.time())
        ip = request.environ.get('REMOTE_ADDR', 0)
        if ip in self.auth_ip_pool and self.auth_ip_pool[ip] >= now:
            # ip is authenticated and not expires
            rv = True
        return rv

    def verify_auth(self, request, **kwargs):
        headers = request.headers
        request_token = headers['x-pypi-auth']
        ip = request.environ.get('REMOTE_ADDR', 0)
        if 'Date' not in headers:
            raise ValueError('Headers have not Date Filed.')

        string_to_sign, expire_t = self.canonical_string(request.method, headers)
        b64_hmac = self.sign_string(string_to_sign)
        auth = ("%s %s:%s" % (self.auth_header, self.access_key, b64_hmac))
        if auth == request_token:
            self.auth_ip_pool[ip] = expire_t
        else:
            raise HTTPError(403, output="Forbidden")

    def canonical_string(self, method, headers, expires=None):
        """
        Generates the gss canonical string for the given parameters

          StringToSign = (HTTP-Verb + "\n" + Content-MD5 + "\n" +
                          Content-Type + "\n" + Date)
        """
        interesting_headers, expire_t = self.figure_interesting_headers(headers)

        sorted_header_keys = sorted(interesting_headers.keys())

        buf = "%s\n" % method
        for key in sorted_header_keys:
            val = interesting_headers[key]
            if key == 'date':
                buf += val
            else:
                buf += "%s\n" % val

        return buf, expire_t

    def figure_interesting_headers(self, headers):
        interesting_headers = {}
        for key in headers.keys():
            lk = key.lower()
            if headers[key] != None and \
               (lk in ['content-md5', 'content-type', 'date', 'cache-control']):
                interesting_headers[lk] = str(headers[key]).strip()

        # these keys get empty strings if they don't exist
        if 'content-type' not in interesting_headers:
            interesting_headers['content-type'] = ''
        if 'content-md5' not in interesting_headers:
            interesting_headers['content-md5'] = ''

        # if using Cache-Control for auth, then use it to make expires timestamp.
        now = int(time.time())
        if 'cache-control' in interesting_headers:
            m = self.ma_ptn.search(interesting_headers['cache-control'])
            if m:
                max_age = m.group(1)
                expires = now + int(max_age)
            else:
                expires = now + self.default_expire_seconds
        else:
            expires = now + self.default_expire_seconds

        return interesting_headers, expires


AuthHandler = EasyHmacAuthHandler()
