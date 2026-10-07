import sys,unittest,tempfile,time,subprocess,json,urllib.request,urllib.error
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from core import Problem
import app
ADMIN={'name':'admin','role':'security_admin'}

class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.lab=app.Application(Path(self.tmp.name)/'lab.sqlite')
    def tearDown(self):self.tmp.cleanup()
    def test_dataset_size_and_identities(self):
        o=self.lab.overview()
        self.assertEqual(o['totals']['events'],2400)
        self.assertEqual(o['totals']['principals'],12)
        self.assertGreater(o['totals']['unsafe_allows'],0)
    def test_unused_permission_known_candidate(self):
        self.assertTrue(any(x['principal']=='build-service' and x['resource']=='finance-payroll' and x['action']=='export' for x in self.lab.findings()['unused_permissions']))
    def test_volume_spike_has_evidence(self):
        spikes=self.lab.findings()['volume_spikes']
        s=next(x for x in spikes if x['principal']=='report-service' and x['day']==17 and x['hour']==3)
        self.assertGreaterEqual(s['count'],60)
        self.assertGreater(s['count'],s['threshold'])
    def test_cross_department_findings(self):
        self.assertTrue(any(x['principal']=='report-service' and x['resource']=='finance-payroll' and x['count']>=60 for x in self.lab.findings()['cross_department_access']))
    def test_log_filters_count(self):
        r=self.lab.logs({'principal':'report-service','decision':'allow'})
        self.assertGreaterEqual(r['matching_total'],60)
        self.assertTrue(all(e['principal']=='report-service' and e['observed_allow']==1 for e in r['events']))
        self.assertLessEqual(len(r['events']),100)
    def test_unknown_identity_returns_no_rows(self):
        self.assertEqual(self.lab.logs({'principal':'nonexistent-identity'})['matching_total'],0)
    def test_invalid_filter_rejected(self):
        with self.assertRaises(Problem):self.lab.logs({'decision':'other'})
    def test_policy_full_validation(self):
        e=self.lab.evaluate()
        self.assertEqual(e['candidate']['false_allow'],0)
        self.assertEqual(e['candidate']['false_deny'],0)
        self.assertGreater(e['observed']['false_allow'],0)
        self.assertEqual(sum(e['observed'][k] for k in ('tp','fp','fn','tn')),2400)
    def test_policy_disable_exposes_risk(self):
        self.lab.route('POST','/api/policy',{'rules':{**app.RULES,'department_boundary':False}},ADMIN)
        self.assertGreater(self.lab.evaluate()['candidate']['false_allow'],0)
    def test_replay_no_live_mutation(self):
        before=self.lab.csv_export();self.lab.evaluate()
        self.assertEqual(before,self.lab.csv_export())
    def test_reproducible_labels(self):
        a=self.lab.evaluate();b=self.lab.evaluate()
        for name in ('observed','candidate'):
            for k in ('tp','fp','fn','tn'):self.assertEqual(a[name][k],b[name][k])
    def test_bad_policy_shape(self):
        with self.assertRaises(Problem):self.lab.route('POST','/api/policy',{'rules':{**app.RULES,'department_boundary':'true'}},ADMIN)
    def test_employee_cannot_analyze_or_change_policy(self):
        with self.assertRaises(Problem):self.lab.route('POST','/api/evaluate',{}, {'name':'alice','role':'employee'})
    def test_report_includes_findings_results_and_limits(self):
        self.lab.evaluate();text=self.lab.report()
        self.assertIn('Latest policy replay',text);self.assertIn('Detailed evidence',text)
        self.assertIn('Synthetic',text);self.assertIn('before revocation',text)
    def test_csv_export_rows(self):
        import csv,io
        self.assertEqual(len(list(csv.DictReader(io.StringIO(self.lab.csv_export())))),2400)
    def test_confidence_interval_and_timing(self):
        r=self.lab.evaluate()['candidate'];lo,hi=r['accuracy_interval_95']
        self.assertLessEqual(lo,r['accuracy']);self.assertGreaterEqual(hi,r['accuracy'])
        self.assertGreater(r['mean_latency_us'],0)

class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
                cls.tmp=tempfile.TemporaryDirectory();cls.processes=[]
                for directory,port in [('policy-lens', 18767)]:
                    p=subprocess.Popen([sys.executable,str(ROOT/'app.py'),'--port',str(port),'--db',str(Path(cls.tmp.name)/(directory+'.sqlite'))],stdout=subprocess.DEVNULL)
                    cls.processes.append(p)
                for port in (18767,):
                    for _ in range(100):
                        try:urllib.request.urlopen(f'http://127.0.0.1:{port}/',timeout=.3);break
                        except (OSError,urllib.error.URLError):time.sleep(.05)
                    else:raise RuntimeError('HTTP test server did not start')
    @classmethod
    def tearDownClass(cls):
                for p in cls.processes:p.terminate();p.wait()
                cls.tmp.cleanup()
    def req(self,path,data=None,headers=None,port=18767):
                h={'Content-Type':'application/json',**(headers or {})}
                req=urllib.request.Request(f'http://127.0.0.1:{port}'+path,json.dumps(data).encode() if data is not None else None,headers=h)
                try:
                    with urllib.request.urlopen(req) as r:return r.status,json.loads(r.read()),r.headers
                except urllib.error.HTTPError as r:return r.code,json.loads(r.read()),r.headers
    def login(self,name='admin',port=18767):
                status,r,h=self.req('/api/login',{'name':name,'password':'DemoPass!2026'},port=port)
                self.assertEqual(status,200)
                return {'Cookie':h['Set-Cookie'].split(';')[0],'X-CSRF-Token':r['csrf']}
    def test_unauthenticated_api_denied(self):self.assertEqual(self.req('/api/state')[0],401)
    def test_csrf_required(self):
                h=self.login();h.pop('X-CSRF-Token')
                self.assertEqual(self.req('/api/access',{'resource':'sales-dashboard'},h)[0],403)
    def test_cross_origin_login_rejected(self):
                self.assertEqual(self.req('/api/login',{'name':'alice','password':'DemoPass!2026'},{'Origin':'https://untrusted.example'})[0],403)
    def test_wrong_host_rejected(self):self.assertEqual(self.req('/api/state',headers={'Host':'untrusted.example'})[0],403)
    def test_login_rate_limit_persists(self):
                for _ in range(8):self.assertEqual(self.req('/api/login',{'name':'rate-test','password':'wrong'})[0],401)
                self.assertEqual(self.req('/api/login',{'name':'rate-test','password':'wrong'})[0],429)
    def test_session_invalidation_on_logout(self):
                h=self.login();self.assertEqual(self.req('/api/logout',{},h)[0],200)
                self.assertEqual(self.req('/api/state',headers=h)[0],401)
    def test_api_security_headers(self):
                _,_,h=self.req('/api/state')
                self.assertEqual(h['X-Content-Type-Options'],'nosniff')
                self.assertIn("frame-ancestors 'none'",h['Content-Security-Policy'])
if __name__=='__main__':unittest.main(verbosity=2)
