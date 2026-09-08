"""Candidate backend client; stdlib cookie transport, no authentication engine or JWT forging."""
import http.cookiejar
import json
import urllib.error
import urllib.parse
import urllib.request


class CandidateClient:
    def __init__(self, origin):
        self.origin = origin.rstrip('/')
        self.cookies = http.cookiejar.CookieJar()
        self.http = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies))
        self.csrf = None
        self.challenge = None

    def request(self, path, body=None, *, csrf=True, origin=None, authorization=None):
        if not path.startswith('/') or path.startswith('//'):
            raise ValueError('Only paths on the configured backend origin are accepted')
        headers = {'Origin': origin or self.origin}
        if body is not None:
            headers['Content-Type'] = 'application/json'
            if csrf and self.csrf:
                headers['X-CSRF-Token'] = self.csrf
        if authorization:
            headers['Authorization'] = authorization
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.origin + path, data, headers, method='GET' if body is None else 'POST')
        try:
            response = self.http.open(request, timeout=20)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            result = json.load(response)
            status = response.status
        if result.get('csrfToken'):
            self.csrf = result['csrfToken']
        if result.get('status') == 'CHALLENGE':
            self.challenge = result
        return status, result

    def begin(self, tenant='alpha'):
        self.request('/candidate/csrf')
        return self.request('/candidate/start', {'tenant': tenant})

    def password(self, username, password):
        return self.step(username=username, password=password)

    def totp(self, otp):
        return self.step(otp=otp)

    def step(self, **fields):
        if not self.challenge:
            raise ValueError('No active candidate transaction')
        return self.request('/candidate/step', {'transactionId': self.challenge['transactionId'],
                                              'actionToken': self.challenge['actionToken'], **fields})

    def resource(self, tenant='alpha'):
        return self.request('/candidate/resource?' + urllib.parse.urlencode({'tenant': tenant}))

    def refresh(self):
        return self.request('/candidate/refresh', {})

    def logout(self):
        return self.request('/candidate/logout', {})
