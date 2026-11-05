"""Student task: pure ASGI request boundary, safe metadata only, no body buffering."""
from time import perf_counter
from .context import CURRENT, new_request_context
from .events import Event
from .filelog import safe_emit


class SecurityLogMiddleware:
    def __init__(self, app, sink_provider):
        self.app, self.sink_provider = app, sink_provider

    async def __call__(self, scope, receive, send):
        """Non-HTTP scopes pass through unchanged.

        For HTTP create a fresh mutable RequestContext, set its sink from
        sink_provider() and set/reset CURRENT
        in try/finally. Never accept incoming X-Request-ID as your own id.
        Wrap response.start: replace any X-Request-ID with the server UUID.
        Forward messages unchanged otherwise. Do not read/store request/response
        bodies. On completion record http.completed or http.failed with status,
        method, route template (or '<unmatched>'), elapsed_ms from perf_counter.
        Use the same request object seen by sync FastAPI dependency threads.
        No raw path/query/IP/client headers, tracebacks or exception text.
        Log validation/denial once per relevant request; database.failed comes
        from the controlled DB error adapter, not from guessing every 500. If an
        unhandled exception occurs, record failure and reraise, do not invent
        successful completion. Do not duplicate domain events emitted by service.
        """
        raise NotImplementedError("TODO: isolated ASGI logging context")
