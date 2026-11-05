"""Row history, preservation and transaction acceptance checks."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
from threading import Barrier
import pytest
from app.db.connection import open_database,write_transaction
from app.practice07.database import open_audited_database
from app.practice07.audit import migrate_database,TRIGGER_NAMES
from app.practice07.inspect import read_history
from tests.practice07_support import p07_db,p06_seed,audit_context,rows


def test_migration_preserves_and_repeats(p07_db):
    path,ids=p07_db
    with open_database(path) as con:
        before=[tuple(x) for x in con.execute('SELECT * FROM "user" ORDER BY id')]
        grades=[tuple(x) for x in con.execute('SELECT * FROM grade ORDER BY course_id,student_id')]
        assert rows(path)==[]
    migrate_database(path);migrate_database(path)
    with open_database(path) as con:
        assert before==[tuple(x) for x in con.execute('SELECT * FROM "user" ORDER BY id')]
        assert grades==[tuple(x) for x in con.execute('SELECT * FROM grade ORDER BY course_id,student_id')]
        triggers={x[0] for x in con.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        assert TRIGGER_NAMES<=triggers
        assert con.execute('PRAGMA foreign_key_check').fetchall()==[]


def test_full_insert_update_delete_history(p07_db):
    path,ids=p07_db;context=audit_context(ids,'teacher_b')
    with open_audited_database(path,context) as con,write_transaction(con):
        # Trusted local SQL only: actor differs from grade author; not an HTTP permission.
        con.execute('INSERT INTO grade VALUES (?,?,?,?)',
                    (ids['student_a'],ids['teacher_a'],13,75))
        con.execute('UPDATE grade SET grade=85 WHERE course_id=13')
        con.execute('DELETE FROM grade WHERE course_id=13')
    history=rows(path)
    assert [x['operation'] for x in history]==['INSERT','UPDATE','DELETE']
    assert all(x['actor_id']==ids['teacher_b'] and x['request_id']==context.request_id for x in history)
    assert history[0]['old_values'] is None and history[-1]['new_values'] is None
    before=json.loads(history[1]['old_values']);after=json.loads(history[1]['new_values'])
    assert set(before)=={'student_id','teacher_id','course_id','grade'}
    assert before['grade']==75 and after['grade']==85
    assert before['teacher_id']==ids['teacher_a']!=history[1]['actor_id']
    from datetime import datetime
    assert all(datetime.fromisoformat(x['occurred_at'].replace('Z','+00:00')).utcoffset().total_seconds()==0 for x in history)


def test_noop_is_not_a_change(p07_db):
    path,ids=p07_db
    with open_audited_database(path,audit_context(ids)) as con,write_transaction(con):
        con.execute('UPDATE grade SET grade=grade')
    assert rows(path)==[]


def test_key_change_is_captured(p07_db):
    path,ids=p07_db
    with open_audited_database(path,audit_context(ids)) as con,write_transaction(con):
        con.execute('UPDATE grade SET course_id=13 WHERE course_id=11 AND student_id=?',(ids['student_a'],))
    history=rows(path);assert len(history)==1
    assert json.loads(history[0]['old_values'])['course_id']==11
    assert json.loads(history[0]['new_values'])['course_id']==13


def test_explicit_rollback_removes_both(p07_db):
    path,ids=p07_db
    with open_audited_database(path,audit_context(ids)) as con:
        with pytest.raises(RuntimeError):
            with write_transaction(con):
                con.execute('UPDATE grade SET grade=99 WHERE course_id=11')
                assert con.execute('SELECT count(*) FROM grade_audit').fetchone()[0]==2
                raise RuntimeError('synthetic rollback')
        assert con.execute('SELECT grade FROM grade WHERE course_id=11 AND student_id=?',(ids['student_a'],)).fetchone()[0]==80
    assert rows(path)==[]


def test_audit_failure_cancels_grade(p07_db):
    path,ids=p07_db
    with open_audited_database(path,audit_context(ids)) as con:
        con.execute("CREATE TRIGGER test_refuse BEFORE INSERT ON grade_audit BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
        with pytest.raises(sqlite3.Error),write_transaction(con):
            con.execute('UPDATE grade SET grade=99 WHERE course_id=11')
        assert con.execute('SELECT grade FROM grade WHERE course_id=11 AND student_id=?',(ids['student_a'],)).fetchone()[0]==80
    assert rows(path)==[]


def test_missing_actor_refuses_change(p07_db):
    path,ids=p07_db
    with open_database(path) as con:
        with pytest.raises(sqlite3.Error),write_transaction(con):
            con.execute('UPDATE grade SET grade=99 WHERE course_id=11')
    assert rows(path)==[]


def test_inactive_actor_refuses_change(p07_db):
    path,ids=p07_db
    with open_audited_database(path,audit_context(ids)) as con:
        con.execute('UPDATE "user" SET status_id=2 WHERE id=?',(ids['teacher_a'],))
        with pytest.raises(sqlite3.Error),write_transaction(con):
            con.execute('UPDATE grade SET grade=99 WHERE course_id=11')
    assert rows(path)==[]


@pytest.mark.parametrize('operation',['UPDATE grade_audit SET actor_id=1','DELETE FROM grade_audit'])
def test_history_mutation_denied(p07_db,operation):
    path,ids=p07_db
    with open_audited_database(path,audit_context(ids)) as con:
        with write_transaction(con):con.execute('UPDATE grade SET grade=81 WHERE course_id=11')
        with pytest.raises(sqlite3.Error),write_transaction(con):con.execute(operation)
    assert len(rows(path))==2


def test_parallel_connection_attribution(p07_db):
    path,ids=p07_db;barrier=Barrier(2)
    def change(pair):
        teacher,student,value=pair;context=audit_context(ids,teacher)
        with open_audited_database(path,context) as con:
            barrier.wait(timeout=10)
            with write_transaction(con):
                con.execute('UPDATE grade SET grade=? WHERE course_id=11 AND student_id=?',(value,ids[student]))
        return context
    with ThreadPoolExecutor(max_workers=2) as pool:
        contexts=list(pool.map(change,[('teacher_a','student_a',81),('teacher_b','student_b',71)]))
    by_request={x['request_id']:x for x in rows(path)}
    assert len(by_request)==2
    for context in contexts:assert by_request[context.request_id]['actor_id']==context.actor_id


def test_readonly_inspection_and_filter(p07_db):
    path,ids=p07_db;context=audit_context(ids)
    with open_audited_database(path,context) as con,write_transaction(con):
        con.execute('UPDATE grade SET grade=81 WHERE course_id=11')
    found=read_history(path,request_id=context.request_id,limit=1)
    assert len(found)==1 and isinstance(found[0]['new_values'],dict)
    assert len(rows(path))==2


@pytest.mark.parametrize('limit',[0,101,True])
def test_inspection_bounds(p07_db,limit):
    with pytest.raises((ValueError,TypeError)):read_history(p07_db[0],limit=limit)


def test_inspection_missing_db_does_not_create(tmp_path):
    path=tmp_path/'absent.sqlite3'
    with pytest.raises((sqlite3.Error,FileNotFoundError)):read_history(path)
    assert not path.exists()


def test_conflicting_trigger_is_not_replaced(p07_db):
    path,ids=p07_db
    with open_database(path) as con:
        con.execute('DROP TRIGGER p07_grade_update')
        con.execute('CREATE TRIGGER p07_grade_update AFTER UPDATE ON grade BEGIN SELECT 1; END')
        before=con.execute("SELECT sql FROM sqlite_master WHERE name='p07_grade_update'").fetchone()[0]
    with pytest.raises((ValueError,sqlite3.Error)):migrate_database(path)
    with open_database(path) as con:
        assert con.execute("SELECT sql FROM sqlite_master WHERE name='p07_grade_update'").fetchone()[0]==before
    assert rows(path)==[]


def test_late_migration_error_leaves_no_partial_schema(tmp_path,p06_seed,monkeypatch):
    from app.practice07 import audit
    source,_=p06_seed;path=tmp_path/'before-p7.sqlite3'
    with sqlite3.connect(source) as src,sqlite3.connect(path) as dst:src.backup(dst)
    with open_database(path) as con:
        before=[tuple(x) for x in con.execute('SELECT type,name,sql FROM sqlite_master ORDER BY type,name')]
    original=audit.trigger_statements
    monkeypatch.setattr(audit,'trigger_statements',lambda:original()+(
        'CREATE TRIGGER IF NOT EXISTS invalid_after_good THIS IS NOT SQL',))
    with pytest.raises(sqlite3.Error):audit.migrate_database(path)
    with open_database(path) as con:
        after=[tuple(x) for x in con.execute('SELECT type,name,sql FROM sqlite_master ORDER BY type,name')]
    assert before==after
