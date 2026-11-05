"""Student task: local read-only inspection, no HTTP access or write connection."""
import argparse
import json
from pathlib import Path
from app.db.connection import DB_PATH


def read_history(path: Path, *, request_id: str | None = None, limit: int = 100) -> list[dict]:
    """Open existing path.resolve().as_uri()+'?mode=ro', uri=True; always close.

    Parameterize request_id, require canonical UUID4 when present, limit int1..100.
    SELECT only explicit grade_audit fields, ORDER BY id, optional request_id.
    Decode old_values/new_values as JSON objects or None in returned dicts.
    Missing DB must fail without creating it. No plaintext SQL construction,
    autocommit writes, real credentials or local-path exception disclosure.
    """
    raise NotImplementedError("TODO: read-only parameterized audit inspection")


def main():
    parser = argparse.ArgumentParser(description="Read local synthetic grade audit")
    parser.add_argument("--database", type=Path, default=DB_PATH)
    parser.add_argument("--request-id")
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()
    try:
        rows = read_history(args.database, request_id=args.request_id, limit=args.limit)
    except Exception:
        parser.exit(1, "audit inspection failed\n")
    print(json.dumps(rows, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
