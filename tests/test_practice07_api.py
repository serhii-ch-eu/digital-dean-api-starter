"""Actual P6 app extended by P7; logs and history agree without new privileges."""
from concurrent.futures import ThreadPoolExecutor
import json
import pytest
from app.db.connection import open_database
from app.practice07.context import CURRENT
from app.practice07.events import canonical_request_id
from app.practice07.hooks import verified_access_context
from tests.practice07_support import p07_lab,p07_db,p06_seed,p06_settings,headers,events,rows,PASSWORD


def test_request_id_is_server_generated(p07_lab):
    client,_,_,_,path=p07_lab
    result=client.get('/health',headers={'X-Request-ID':'injected\tvalue'})
    rid=result.headers.get('x-request-id')
    assert result.status_code==200 and canonical_request_id(rid)
    matching=[x for x in events(path) if x['event']=='http.completed' and x['request_id']==rid]
    assert len(matching)==1 and matching[0]['route']=='/health'
    assert matching[0]['elapsed_ms']>=0 and CURRENT.get() is None


def test_login_and_session_reference(p07_lab):
    client,_,ids,settings,path=p07_lab
    result=client.post('/api/v1/auth/login',json={'login':'teacher_a','password':PASSWORD})
    token=result.json()['access_token'];uid,reference=verified_access_context(token,settings)
    rid=result.headers['x-request-id']
    found=[x for x in events(path) if x['request_id']==rid]
    assert uid==ids['teacher_a'] and len(reference)==64
    for kind in ('auth.login_succeeded','auth.token_issued'):
        selected=[x for x in found if x['event']==kind]
        assert len(selected)==1 and selected[0]['actor_id']==uid and selected[0]['session_ref']==reference
    assert token not in path.read_text() and PASSWORD not in path.read_text()


def test_invalid_token_never_supplies_identity(p07_lab):
    client,_,_,_,path=p07_lab
    result=client.get('/api/v1/me/grades',headers={'Authorization':'Bearer FAKE_SECRET_TOKEN'})
    assert result.status_code==401
    found=[x for x in events(path) if x['request_id']==result.headers['x-request-id']]
    assert any(x['event']=='auth.token_rejected' for x in found)
    assert all(x['actor_id'] is None and x['role'] is None and x['session_ref'] is None for x in found)
    assert 'FAKE_SECRET_TOKEN' not in path.read_text()


def test_failed_login_body_and_query_are_not_logged(p07_lab):
    client,_,_,_,path=p07_lab;secret='SECRET_NOT_FOR_LOGS_07'
    result=client.post('/api/v1/auth/login?password='+secret,
                      json={'login':'missing','password':secret})
    assert result.status_code==401
    assert any(x['event']=='auth.login_failed' for x in events(path))
    text=path.read_text();assert secret not in text and 'missing' not in text


def test_grade_update_correlates_db_file_response(p07_lab):
    client,database,ids,_,log_path=p07_lab;auth=headers(p07_lab,'teacher_a')
    url=f'/api/v1/courses/11/grades/{ids["student_a"]}'
    result=client.patch(url,headers=auth,json={'grade':81})
    assert result.status_code==200
    rid=result.headers['x-request-id'];history=rows(database)
    assert len(history)==1 and history[0]['actor_id']==ids['teacher_a'] and history[0]['request_id']==rid
    assert json.loads(history[0]['old_values'])['grade']==80
    assert json.loads(history[0]['new_values'])['grade']==81
    found=[x for x in events(log_path) if x['request_id']==rid and x['event']=='grade.updated']
    assert len(found)==1 and found[0]['committed'] is True
    assert found[0]['actor_id']==ids['teacher_a'] and found[0]['student_id']==ids['student_a']
    assert 'old_values' not in found[0] and 'new_values' not in found[0] and 'grade' not in found[0]


def test_noop_api_has_no_audit_row(p07_lab):
    client,path,ids,_,logs=p07_lab
    result=client.patch(f'/api/v1/courses/11/grades/{ids["student_a"]}',
                        headers=headers(p07_lab,'teacher_a'),json={'grade':80})
    assert result.status_code==200 and rows(path)==[]
    assert any(x['event']=='grade.unchanged' and x['request_id']==result.headers['x-request-id'] for x in events(logs))


@pytest.mark.parametrize('login,route,count',[
    ('manager','/api/v1/courses/11/grades',2),
    ('teacher_a','/api/v1/courses/11/grades',1),
    ('student_a','/api/v1/me/grades',1),
])
def test_grade_reads_have_count_not_values(p07_lab,login,route,count):
    result=p07_lab[0].get(route,headers=headers(p07_lab,login));assert result.status_code==200
    found=[x for x in events(p07_lab[4]) if x['request_id']==result.headers['x-request-id'] and x['event']=='grade.read']
    assert len(found)==1 and found[0]['returned_count']==count
    assert 'grade' not in found[0] and 'body' not in found[0]


@pytest.mark.parametrize('login,target,code',[
    ('admin','student_a',403),('manager','student_a',403),
    ('student_a','student_a',403),('teacher_a','student_b',404),
])
def test_rbac_and_authorship_unchanged(p07_lab,login,target,code):
    client,path,ids,_,logs=p07_lab
    result=client.patch(f'/api/v1/courses/11/grades/{ids[target]}',
                        headers=headers(p07_lab,login),json={'grade':99})
    assert result.status_code==code and rows(path)==[]
    found=[x for x in events(logs) if x['request_id']==result.headers['x-request-id']]
    assert any(x['event']=='access.denied' for x in found)
    assert not any(x['event'] in {'grade.created','grade.updated'} for x in found)


def test_audit_failure_is_safe_http_500_and_no_change(p07_lab):
    client,path,ids,_,logs=p07_lab;auth=headers(p07_lab,'teacher_a')
    with open_database(path) as con:
        con.execute("CREATE TRIGGER test_refuse BEFORE INSERT ON grade_audit BEGIN SELECT RAISE(ABORT,'SECRET SQL MESSAGE'); END")
    result=client.patch(f'/api/v1/courses/11/grades/{ids["student_a"]}',headers=auth,json={'grade':99})
    assert result.status_code==500 and result.json()=={'detail':'database unavailable'}
    with open_database(path) as con:
        assert con.execute('SELECT grade FROM grade WHERE course_id=11 AND student_id=?',(ids['student_a'],)).fetchone()[0]==80
    assert rows(path)==[] and 'SECRET SQL MESSAGE' not in logs.read_text()


def test_file_failure_does_not_lie_about_commit(p07_lab,monkeypatch,capsys):
    from app.main import app
    client,path,ids,_,logs=p07_lab;auth=headers(p07_lab,'teacher_a')
    class Broken:
        def seek(self,*args):pass
        def tell(self):return 0
        def write(self,text):raise OSError('SECRET DISK MESSAGE')
        def flush(self):pass
    with monkeypatch.context() as patch:
        patch.setattr(app.state.practice07_sink.handler,'stream',Broken())
        result=client.patch(f'/api/v1/courses/11/grades/{ids["student_a"]}',headers=auth,json={'grade':82})
    assert result.status_code==200 and result.json()['grade']==82
    assert len(rows(path))==1 and 'SECRET DISK MESSAGE' not in capsys.readouterr().err


def test_parallel_http_identity_not_crossed(p07_lab):
    client,path,ids,_,logs=p07_lab
    auths={name:headers(p07_lab,name) for name in ['teacher_a','teacher_b']}
    def change(args):
        teacher,student,value=args
        result=client.patch(f'/api/v1/courses/11/grades/{ids[student]}',headers=auths[teacher],json={'grade':value})
        assert result.status_code==200
        return result.headers['x-request-id'],ids[teacher]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(change,[('teacher_a','student_a',83),('teacher_b','student_b',73)]))
    by_id={x['request_id']:x for x in rows(path)}
    assert len(by_id)==2
    for rid,actor in results:
        assert by_id[rid]['actor_id']==actor
        assert any(x['request_id']==rid and x['event']=='grade.updated' and x['actor_id']==actor for x in events(logs))


def test_validation_and_unmatched_path_do_not_leak(p07_lab):
    client,_,ids,_,logs=p07_lab;auth=headers(p07_lab,'teacher_a')
    result=client.patch(f'/api/v1/courses/11/grades/{ids["student_a"]}',
        headers=auth,json={'grade':99,'password':'SECRET_VALIDATION_INPUT'})
    assert result.status_code==422
    absent=client.get('/SECRET_PATH_INPUT?token=SECRET_QUERY_INPUT')
    assert absent.status_code==404
    text=logs.read_text()
    assert not any(x in text for x in ['SECRET_VALIDATION_INPUT','SECRET_PATH_INPUT','SECRET_QUERY_INPUT'])
    assert any(x['event']=='input.rejected' for x in events(logs))
    assert any(x['route']=='<unmatched>' for x in events(logs))


def test_no_new_audit_http_access_or_routes(p07_lab):
    client=p07_lab[0]
    schema=client.get('/openapi.json').json();assert schema['info']['version']=='0.7.0'
    assert not any('audit' in name or 'logs' in name for name in schema['paths'])
    operations=[(p,m) for p,v in schema['paths'].items() for m in v if m in {'get','post','put','patch','delete'}]
    assert len(operations)==21
    assert client.get('/api/v1/audit',headers=headers(p07_lab,'admin')).status_code==404


def test_double_install_refuses_before_side_effects(p07_lab,tmp_path):
    from app.main import app
    from app.practice07.integration import install_practice07
    from app.practice07.settings import LogSettings
    path=tmp_path/'must-not-exist'/'log.jsonl'
    with pytest.raises(RuntimeError):install_practice07(app,log_settings=LogSettings(path))
    assert not path.exists()


def test_conflict_is_failure_not_committed_grade(p07_lab):
    client,path,ids,_,logs=p07_lab
    result=client.post('/api/v1/courses/11/grades',headers=headers(p07_lab,'teacher_b'),
                        json={'student_id':ids['student_a'],'grade':99})
    assert result.status_code==409 and rows(path)==[]
    found=[x for x in events(logs) if x['request_id']==result.headers['x-request-id']]
    assert len([x for x in found if x['event']=='operation.failed'])==1
    assert not any(x['event'] in {'grade.created','grade.updated'} for x in found)


def test_account_block_has_target_and_action(p07_lab):
    client,_,ids,_,logs=p07_lab
    result=client.patch(f'/api/v1/users/{ids["student_a"]}/block',headers=headers(p07_lab,'admin'))
    assert result.status_code==200
    found=[x for x in events(logs) if x['request_id']==result.headers['x-request-id'] and x['event']=='operation.succeeded']
    assert len(found)==1 and found[0]['actor_id']==ids['admin']
    assert found[0]['target_id']==ids['student_a'] and found[0]['action']=='user.block'
