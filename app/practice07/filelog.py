"""Student formatting/emission task with provided safe handler infrastructure."""
import logging
from logging.handlers import RotatingFileHandler
import sys
from threading import RLock
from uuid import uuid4
from .events import Event
from .settings import LogSettings

SAFE_FAILURE = "security log write failed\n"


def report_failure() -> None:
    try:
        sys.stderr.write(SAFE_FAILURE)
        sys.stderr.flush()
    except Exception:
        pass  # Never expose the event, traceback, file path or another exception.


class JsonLineFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        """Use ONLY record.security_event (Event), plus catalog level.

        Return one JSON object, no trailing newline, ensure_ascii=False,
        allow_nan=False. Never use record.getMessage()/exc_info/stack_info,
        repr(record), request bodies, headers, query strings or arbitrary extra.
        JSON encoding escapes CR/LF; do not build JSON by concatenating strings.
        """
        raise NotImplementedError("TODO: allowlisted structured JSON formatter")


class SafeRotatingHandler(RotatingFileHandler):
    def __init__(self, settings: LogSettings):
        super().__init__(settings.path, maxBytes=settings.max_bytes,
                         backupCount=settings.backup_count, encoding="utf-8", delay=False)
        self.failures = 0

    def handleError(self, record):
        self.failures += 1
        report_failure()


class EventSink:
    def __init__(self, settings: LogSettings):
        settings.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.handler = SafeRotatingHandler(settings)  # OSError prevents startup.
        self.handler.setFormatter(JsonLineFormatter())
        self.logger = logging.getLogger("digital-dean.security." + uuid4().hex)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        self.logger.addHandler(self.handler)
        self.lock = RLock()
        self.closed = False

    def emit(self, event: Event) -> bool:
        """Serialize with lock; emit catalog level and extra={'security_event':event}.

        True iff this emission succeeded; compare handler.failures under lock.
        Reject non-Event objects. No secrets in exception reporting. A closed
        sink returns False, never reopens or silently claims success.
        """
        raise NotImplementedError("TODO: safe bounded event emission")

    def close(self) -> None:
        with self.lock:
            if not self.closed:
                self.closed = True
                self.logger.removeHandler(self.handler)
                self.handler.close()


def safe_emit(sink: EventSink, event: Event) -> bool:
    """After COMMIT, an event failure must not pretend the DB was rolled back."""
    try:
        return sink.emit(event)
    except Exception:
        report_failure()
        return False
