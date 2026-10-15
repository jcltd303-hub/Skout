import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('export_domains',Path(__file__).with_name('export_domains.py'))
if spec is not None and spec.loader is not None and Path(spec.origin).exists():
    exporter=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exporter)
else:
    exporter=None


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(exporter,'certificate evidence reducer is missing')
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.db=exporter.open_database(self.root/'results.sqlite')
        self.addCleanup(self.db.close)

    def fixture(self):
        return {'ip':'192.0.2.10','port':'443','host':'www.example.test','time':'2026-10-14T18:00:00Z','ssl':{'enabled':True,'certificate':{'cn':'Legacy.example.test','domain':['WWW.example.test.','*.example.test','WWW.example.test.','127.0.0.1'],'fingerprint':'a'*64,'not_after':'2027-01-01T00:00:00Z'}}}

    def test_replay_is_idempotent_and_preserves_sources(self):
        event=self.fixture()
        text=json.dumps(event)+'\n'
        first=exporter.ingest(self.db,io.StringIO(text))
        second=exporter.ingest(self.db,io.StringIO(text))
        self.assertEqual(first['imported'],1)
        self.assertEqual(second['duplicates'],1)
        self.assertEqual(self.db.execute('select count(*) from events').fetchone()[0],1)
        exporter.export(self.db,self.root/'domains.txt',self.root/'evidence.jsonl')
        self.assertEqual((self.root/'domains.txt').read_text().splitlines(),['*.example.test','legacy.example.test','www.example.test'])
        evidence=[json.loads(line) for line in (self.root/'evidence.jsonl').read_text().splitlines()]
        self.assertEqual({(x['domain'],x['source']) for x in evidence},{('*.example.test','san'),('legacy.example.test','cn'),('www.example.test','san')})
        self.assertTrue(all(x['ip']=='192.0.2.10' and x['port']==443 and x['host']=='www.example.test' for x in evidence))

    def test_new_sans_field_does_not_mislabel_cn_as_san(self):
        event=self.fixture()
        cert=event['ssl']['certificate']
        cert['san']=['www.example.test']
        cert['domain']=['www.example.test','legacy.example.test']
        exporter.ingest(self.db,io.StringIO(json.dumps(event)+'\n'))
        rows=self.db.execute('select name, source from evidence order by name').fetchall()
        self.assertEqual(rows,[('legacy.example.test','cn'),('www.example.test','san')])

    def test_null_malformed_and_error_records_do_not_kill_good_results(self):
        text='null\n{broken\n'+json.dumps({'event_type':'service','ip':'192.0.2.1','port':'587','error':'timeout'})+'\n'+json.dumps(self.fixture())+'\n'
        stats=exporter.ingest(self.db,io.StringIO(text))
        self.assertEqual(stats['invalid'],2)
        self.assertEqual(stats['without_certificate'],1)
        self.assertEqual(stats['imported'],1)

    def test_new_observations_preserve_different_endpoints_and_times(self):
        first=self.fixture();second=self.fixture();second['ip']='192.0.2.11'
        third=self.fixture();third['time']='2026-10-14T19:00:00Z'
        exporter.ingest(self.db,io.StringIO('\n'.join(json.dumps(x) for x in [first,second,third])))
        self.assertEqual(self.db.execute('select count(*) from events').fetchone()[0],3)
        self.assertEqual(self.db.execute('select count(*) from names').fetchone()[0],3)
        self.assertEqual(self.db.execute('select count(*) from evidence').fetchone()[0],9)

    def test_database_restart_retains_deduplication(self):
        text=json.dumps(self.fixture())+'\n'
        exporter.ingest(self.db,io.StringIO(text))
        other=exporter.open_database(self.root/'results.sqlite')
        try:
            stats=exporter.ingest(other,io.StringIO(text))
            self.assertEqual(stats['duplicates'],1)
        finally:
            other.close()

    def test_normalization_keeps_wildcards_without_synthesizing_hosts(self):
        cases={'*.EXAMPLE.TEST.':'*.example.test','127.0.0.1':None,'bad..test':None,'https://example.test':None,'name':None,'xn--bcher-kva.example':'xn--bcher-kva.example','foo.*.test':None,'example.test..':None}
        for value,want in cases.items():
            self.assertEqual(exporter.normalize(value),want)

    def test_failed_observation_does_not_commit_incomplete_evidence(self):
        self.db.execute("CREATE TRIGGER fail_name BEFORE INSERT ON names WHEN NEW.name='www.example.test' BEGIN SELECT RAISE(ABORT,'interrupted write'); END")
        self.db.commit()
        text=json.dumps(self.fixture())+'\n'
        with self.assertRaises(sqlite3.IntegrityError):
            exporter.ingest(self.db,io.StringIO(text))
        self.assertEqual(self.db.execute('select count(*) from events').fetchone()[0],0)
        self.assertEqual(self.db.execute('select count(*) from evidence').fetchone()[0],0)
        self.db.execute('DROP TRIGGER fail_name')
        self.db.commit()
        self.assertEqual(exporter.ingest(self.db,io.StringIO(text))['imported'],1)

    def test_live_names_are_durable_and_not_repeated_after_replay(self):
        text=json.dumps(self.fixture())+'\n'
        live=io.StringIO()
        exporter.ingest(self.db,io.StringIO(text),live_output=live)
        self.assertEqual(live.getvalue().splitlines(),['*.example.test','legacy.example.test','www.example.test'])
        other=exporter.open_database(self.root/'results.sqlite')
        try:
            second=io.StringIO()
            exporter.ingest(other,io.StringIO(text),live_output=second)
            self.assertEqual(second.getvalue(),'')
        finally:
            other.close()

    def test_explicit_null_san_never_becomes_cn_as_san(self):
        event=self.fixture()
        event['ssl']['certificate']={'cn':'cn.example.test','domain':['cn.example.test'],'san':None,'fingerprint':'a'*64}
        exporter.ingest(self.db,io.StringIO(json.dumps(event)+'\n'))
        rows=self.db.execute('select name, source from evidence').fetchall()
        self.assertEqual(rows,[('cn.example.test','cn')])


if __name__=='__main__':
    unittest.main()
