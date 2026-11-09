"""Student task: pure ASGI admission inside P7 context and outside the router."""
from .events import emit_limit_event
from .settings import LOGIN_PATH

LIMIT_DETAIL = "too many login attempts"


class LoginThrottleMiddleware:
    def __init__(self, app, limiter_provider):
        self.app, self.limiter_provider = app, limiter_provider

    async def __call__(self, scope, receive, send):
        """Pass non-HTTP and non-target method/path to app without counting.

        Match only POST with decoded scope.path == LOGIN_PATH; query and client
        headers cannot change the policy. Set scope['practice08_route_template']
        to the server LOGIN_PATH literal for the P7 safe route resolver.
        Call the shared provider().admit() ONCE, before receive/dependencies.
        If allowed forward messages unchanged. If denied emit exactly one limit
        event and send 429 JSON {'detail':LIMIT_DETAIL}, Retry-After positive
        integer seconds, Cache-Control:no-store; no WWW-Authenticate/token.
        Do not call receive/downstream/auth/DB on denial. P7 outer middleware
        supplies X-Request-ID and exactly one http.completed with status429.
        A failed safe event emission must not admit a rejected request.
        """
        raise NotImplementedError("TODO: safe pre-authentication ASGI gate")
