"""Working isolated standard-library example; not the completed API assignment."""
from contextlib import closing
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from uuid import uuid4


def run():
    with TemporaryDirectory(prefix="dean-p07-example-") as directory:
        path = Path(directory) / "events.jsonl"
        logger = logging.getLogger("p07.isolated." + uuid4().hex)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        handler = RotatingFileHandler(path, maxBytes=4096, backupCount=1, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        try:
            # json.dumps escapes line breaks inside values, never concatenate JSON.
            logger.info(json.dumps({"event": "demo.started", "label": "one\ntwo"}))
            with closing(sqlite3.connect(":memory:", autocommit=True)) as con:
                con.create_function("demo_actor", 0, lambda: 7)
                con.executescript("""
                    CREATE TABLE grade(value INTEGER NOT NULL);
                    CREATE TABLE history(actor INTEGER,old_value INTEGER,new_value INTEGER);
                    INSERT INTO grade VALUES (80);
                    CREATE TRIGGER demo_update AFTER UPDATE ON grade
                    WHEN OLD.value IS NOT NEW.value
                    BEGIN
                        INSERT INTO history VALUES (demo_actor(),OLD.value,NEW.value);
                    END;
                """)
                con.execute("BEGIN IMMEDIATE")
                con.execute("UPDATE grade SET value=90")
                assert con.execute("SELECT count(*) FROM history").fetchone()[0] == 1
                con.execute("ROLLBACK")
                assert con.execute("SELECT value FROM grade").fetchone()[0] == 80
                assert con.execute("SELECT count(*) FROM history").fetchone()[0] == 0
                con.execute("BEGIN IMMEDIATE")
                con.execute("UPDATE grade SET value=88")
                con.execute("COMMIT")
                assert con.execute("SELECT * FROM history").fetchone() == (7, 80, 88)
                con.execute("UPDATE grade SET value=88")
                assert con.execute("SELECT count(*) FROM history").fetchone()[0] == 1
            handler.flush()
            lines = path.read_text(encoding="utf-8").splitlines()
            assert len(lines) == 1 and json.loads(lines[0])["label"] == "one\ntwo"
        finally:
            logger.removeHandler(handler)
            handler.close()
    print("Practical 7 isolated JSON and rollback example passed")


if __name__ == "__main__":
    run()
