"""Structured output, privacy, rotation and safe failure acceptance checks."""
import json
import logging
from uuid import uuid4
import pytest
from app.practice07.events import Event,EVENT_LEVELS
from app.practice07.filelog import EventSink,JsonLineFormatter,safe_emit,SAFE_FAILURE
from app.practice07.settings import LogSettings


def event(**fields):
    return Event('grade.read','success',request_id=str(uuid4()),actor_id=7,
                 role='teacher',course_id=11,returned_count=2,**fields)


def test_formatter_ignores_message_traceback_and_extra():
    record=logging.LogRecord('test',logging.INFO,'private-path',1,'SECRET PASSWORD',(),None)
    record.security_event=event()
    record.body={'password':'SHOULD NOT APPEAR'}
    record.stack_info='RAW TOKEN'
    text=JsonLineFormatter().format(record);value=json.loads(text)
    assert value['event']=='grade.read' and value['level']=='INFO'
    assert not any(x in text for x in ['SECRET','PASSWORD','SHOULD','RAW TOKEN','private-path','body'])
    assert set(value)==set(record.security_event.__dataclass_fields__)|{'level'}


def test_newline_is_data_not_another_record(tmp_path):
    path=tmp_path/'security.jsonl';sink=EventSink(LogSettings(path))
    try:assert sink.emit(event(route='/demo\r\n{"event":"fake"}')) is True
    finally:sink.close()
    lines=path.read_text(encoding='utf-8').splitlines()
    assert len(lines)==1 and json.loads(lines[0])['route'].startswith('/demo\r\n')


@pytest.mark.parametrize('name',list(EVENT_LEVELS))
def test_exact_catalog_level(tmp_path,name):
    path=tmp_path/'security.jsonl';sink=EventSink(LogSettings(path))
    try:assert sink.emit(Event(name,'success'))
    finally:sink.close()
    assert json.loads(path.read_text())['level']==EVENT_LEVELS[name]


def test_unknown_or_unbounded_fields_rejected():
    with pytest.raises(ValueError):Event('invented','success')
    with pytest.raises(TypeError):Event('grade.read','success',password='not a field')
    with pytest.raises(ValueError):event(route='x'*257)
    with pytest.raises(ValueError):event(elapsed_ms=float('nan'))
    with pytest.raises(ValueError):Event('grade.read','success',actor_id=True)


def test_rotation_bounded_and_parseable(tmp_path):
    path=tmp_path/'security.jsonl';sink=EventSink(LogSettings(path,max_bytes=800,backup_count=3))
    try:
        for _ in range(30):assert sink.emit(event())
    finally:sink.close()
    files=list(tmp_path.glob('security.jsonl*'))
    assert 2<=len(files)<=4
    for file in files:
        for line in file.read_text(encoding='utf-8').splitlines():assert json.loads(line)['event']=='grade.read'


@pytest.mark.parametrize('failure',['write','flush'])
def test_runtime_failure_is_safe_and_visible(tmp_path,monkeypatch,capsys,failure):
    path=tmp_path/'security.jsonl';sink=EventSink(LogSettings(path))
    class Broken:
        def seek(self,*args):pass
        def tell(self):return 0
        def write(self,text):
            if failure=='write':raise OSError('SECRET FULL EVENT private/path')
        def flush(self):
            if failure=='flush':raise OSError('SECRET FLUSH private/path')
    try:
        with monkeypatch.context() as patch:
            patch.setattr(sink.handler,'stream',Broken())
            assert safe_emit(sink,event()) is False
        error=capsys.readouterr().err
        assert error==SAFE_FAILURE and 'SECRET' not in error
    finally:sink.close()


def test_closed_sink_does_not_reopen(tmp_path):
    path=tmp_path/'security.jsonl';sink=EventSink(LogSettings(path));sink.close()
    before=path.read_bytes();assert sink.emit(event()) is False
    assert path.read_bytes()==before


def test_unusable_path_refuses_initialization(tmp_path):
    with pytest.raises(OSError):EventSink(LogSettings(tmp_path))
