"""Isolated synthetic databases/logs; the student's actual integrated application."""
import importlib
import json
import sqlite3
import pytest
from fastapi.testclient import TestClient
from tests.practice06_support import p06_seed,p06_settings,PASSWORD
from app.practice06.service import DeanService
from app.practice07.audit import migrate_database
from app.practice07.context import AuditContext
from app.practice07.filelog import EventSink
from app.practice07.settings import LogSettings
from uuid import uuid4


@pytest.fixture
def p07_db(tmp_path,p06_seed):
    path=tmp_path/'isolated.sqlite3';source,ids=p06_seed
    with sqlite3.connect(source) as src,sqlite3.connect(path) as dst:src.backup(dst)
    migrate_database(path)
    return path,dict(ids)


def audit_context(ids,login='teacher_a'):
    return AuditContext(ids[login],str(uuid4()))


def rows(path):
    with sqlite3.connect(path) as con:
        con.row_factory=sqlite3.Row
        return [dict(x) for x in con.execute('SELECT * FROM grade_audit ORDER BY id')]


def events(path):
    if not path.exists():return []
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]


@pytest.fixture
def p07_lab(tmp_path,monkeypatch,p07_db,p06_settings):
    path,ids=p07_db;log_path=tmp_path/'logs'/'security.jsonl'
    monkeypatch.setenv('DEAN_JWT_SECRET_HEX',p06_settings.key.hex())
    monkeypatch.setenv('DEAN_SECURITY_LOG_PATH',str(log_path))
    app=importlib.import_module('app.main').app
    assert getattr(app.state,'practice07_installed',False),'integrate the actual existing app'
    from app.practice06.router import get_service,get_security_settings
    app.state.practice07_sink.close()
    app.state.practice07_sink=EventSink(LogSettings(log_path))
    app.dependency_overrides[get_service]=lambda:DeanService(path)
    app.dependency_overrides[get_security_settings]=lambda:p06_settings
    try:
        with TestClient(app,raise_server_exceptions=False) as client:
            yield client,path,ids,p06_settings,log_path
    finally:
        app.dependency_overrides.pop(get_service,None)
        app.dependency_overrides.pop(get_security_settings,None)
        app.state.practice07_sink.close()


def headers(lab,login):
    result=lab[0].post('/api/v1/auth/login',json={'login':login,'password':PASSWORD})
    assert result.status_code==200,result.text
    return {'Authorization':'Bearer '+result.json()['access_token']}
