"""Policy Lens — offline access-log analysis and policy validation."""
import argparse
import csv
import io
import json
import random
import time
from pathlib import Path
from core import Store,Problem,admin,serve

SEED=412469
RULES={'department_boundary':True,'managed_device':True,'deny_high_risk':True,'sensitive_export':True}
RESOURCES=[('sales-crm','sales','internal'),('finance-payroll','finance','restricted'),
           ('engineering-code','engineering','confidential'),('company-handbook','shared','public')]
PRINCIPALS=[(f'{dep}-{n}',dep,'employee') for dep in ('sales','finance','engineering') for n in (1,2,3)] + [
    ('report-service','sales','service'),('build-service','engineering','service'),('security-admin','security','admin')]


def desired_deny(e):
    """Independent synthetic labeling rubric; positive label means SHOULD deny."""
    if e['risk']=='high':return True
    if e['sensitivity']!='public' and e['device']=='unmanaged':return True
    if e['action']=='export' and e['sensitivity'] in ('restricted','confidential'):return True
    return e['kind']!='admin' and e['resource_department'] not in (e['department'],'shared')


def candidate_deny(e,rules):
    reasons=[]
    if rules['department_boundary'] and e['kind']!='admin' and e['resource_department'] not in (e['department'],'shared'):
        reasons.append('department_boundary')
    if rules['managed_device'] and e['device']=='unmanaged' and e['sensitivity']!='public':reasons.append('managed_device')
    if rules['deny_high_risk'] and e['risk']=='high':reasons.append('deny_high_risk')
    if rules['sensitive_export'] and e['action']=='export' and e['sensitivity'] in ('restricted','confidential'):reasons.append('sensitive_export')
    return bool(reasons),reasons


class Application:
    def __init__(self,path):
        self.store=Store(path);self.store.initialize()
        with self.store.connect() as db:
            db.executescript('''
              CREATE TABLE IF NOT EXISTS entitlements(principal TEXT,resource TEXT,action TEXT,PRIMARY KEY(principal,resource,action));
              CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,day INTEGER,hour INTEGER,principal TEXT,
                department TEXT,kind TEXT,resource TEXT,resource_department TEXT,sensitivity TEXT,
                action TEXT,device TEXT,risk TEXT,observed_allow INTEGER,expected_deny INTEGER);
              CREATE TABLE IF NOT EXISTS policies(id INTEGER PRIMARY KEY,rules TEXT,created REAL);
              CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY,created REAL,version INTEGER,summary TEXT);
              CREATE TABLE IF NOT EXISTS replay(run_id INTEGER,event_id INTEGER,variant TEXT,predicted_deny INTEGER,
                expected_deny INTEGER,latency_us REAL,PRIMARY KEY(run_id,event_id,variant));
            ''')
            if not db.execute('SELECT 1 FROM policies').fetchone():
                db.execute('INSERT INTO policies VALUES(NULL,?,?)',(json.dumps(RULES),time.time()))
            if not db.execute('SELECT 1 FROM events').fetchone():
                rng=random.Random(SEED)
                for principal,dep,kind in PRINCIPALS:
                    for resource,owner,sensitivity in RESOURCES:
                        # A deliberately broad legacy entitlement snapshot for review.
                        for action in ('read','export'):
                            if owner in (dep,'shared') or kind=='admin' or rng.random()<.38:
                                db.execute('INSERT INTO entitlements VALUES(?,?,?)',(principal,resource,action))
                # Ensure reviewable over-privilege, unused permission, and volume spike.
                db.execute("INSERT OR IGNORE INTO entitlements VALUES('report-service','finance-payroll','read')")
                db.execute("INSERT OR IGNORE INTO entitlements VALUES('build-service','finance-payroll','export')")
                for i in range(2400):
                    day=i%30+1;hour=rng.randrange(24)
                    principal,dep,kind=rng.choice(PRINCIPALS)
                    resource,owner,sensitivity=rng.choice(RESOURCES)
                    action=rng.choices(['read','export'],weights=[9,1])[0]
                    if i>=2340:
                        day,hour,principal,dep,kind,resource,owner,sensitivity,action=17,3,'report-service','sales','service','finance-payroll','finance','restricted','read'
                    # Preserve a known unused grant; no event exercises this entitlement.
                    if principal=='build-service' and resource=='finance-payroll' and action=='export':resource,owner,sensitivity='company-handbook','shared','public'
                    device=rng.choices(['managed','unmanaged'],weights=[9,1])[0]
                    risk=rng.choices(['low','high'],weights=[19,1])[0]
                    granted=bool(db.execute('SELECT 1 FROM entitlements WHERE principal=? AND resource=? AND action=?',(principal,resource,action)).fetchone())
                    e={'department':dep,'kind':kind,'resource_department':owner,'sensitivity':sensitivity,'device':device,'risk':risk,'action':action}
                    db.execute('INSERT INTO events VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                               (day,hour,principal,dep,kind,resource,owner,sensitivity,action,device,risk,int(granted),int(desired_deny(e))))

    def policy(self):
        with self.store.connect() as db:p=db.execute('SELECT * FROM policies ORDER BY id DESC LIMIT 1').fetchone()
        return {'version':p['id'],'rules':json.loads(p['rules'])}

    def overview(self):
        with self.store.connect() as db:
            totals=dict(db.execute('''SELECT COUNT(*) AS events,COUNT(DISTINCT principal) AS principals,
              SUM(observed_allow) AS allowed,SUM(observed_allow=1 AND expected_deny=1) AS unsafe_allows FROM events''').fetchone())
            totals['entitlements']=db.execute('SELECT COUNT(*) FROM entitlements').fetchone()[0]
            days=[dict(x) for x in db.execute('''SELECT day,COUNT(*) AS volume,
              SUM(observed_allow=1 AND expected_deny=1) AS unsafe_allows FROM events GROUP BY day ORDER BY day''')]
        return {'totals':totals,'days':days,'seed':SEED,'window_days':30}

    def findings(self):
        with self.store.connect() as db:
            unused=[dict(x) for x in db.execute('''SELECT g.principal,g.resource,g.action,COUNT(e.id) AS successful_uses
              FROM entitlements g LEFT JOIN events e ON g.principal=e.principal AND g.resource=e.resource
              AND g.action=e.action AND e.observed_allow=1
              GROUP BY g.principal,g.resource,g.action HAVING COUNT(e.id)=0 ORDER BY g.principal,g.resource''')]
            exposure=[dict(x) for x in db.execute('''SELECT principal,resource,COUNT(*) AS count,
              MIN(id) AS example_event FROM events WHERE observed_allow=1 AND kind!='admin'
              AND resource_department NOT IN (department,'shared') GROUP BY principal,resource ORDER BY count DESC''')]
            sensitive=[dict(x) for x in db.execute('''SELECT principal,resource,COUNT(*) AS count,MIN(id) AS example_event
              FROM events WHERE observed_allow=1 AND action='export' AND sensitivity IN ('restricted','confidential')
              GROUP BY principal,resource ORDER BY count DESC''')]
            buckets=[dict(x) for x in db.execute('SELECT principal,day,hour,COUNT(*) AS count FROM events GROUP BY principal,day,hour')]
        # Poisson-style rate heuristic, using the principal's average hourly volume
        # over the full observed 30-day window, including hours with no events.
        volume={p:sum(x['count'] for x in buckets if x['principal']==p)/720 for p,_,_ in PRINCIPALS}
        spikes=[]
        for b in buckets:
            avg=volume[b['principal']];threshold=max(10,avg+4*(avg**.5))
            if b['count']>threshold:spikes.append({**b,'baseline_per_hour':round(avg,3),'threshold':round(threshold,3)})
        spikes.sort(key=lambda x:x['count'],reverse=True)
        return {'unused_permissions':unused,'cross_department_access':exposure,'sensitive_exports':sensitive,'volume_spikes':spikes,
                'limits':'Review candidates, not automatic revocation. Unused means no observed successful use in this 30-day synthetic window. Volume spikes are rate heuristics, not proof of compromise.'}

    def logs(self,body):
        principal=str(body.get('principal','')).strip();decision=body.get('decision','all')
        if decision not in ('all','allow','deny'):raise Problem(400,'Unknown decision filter.')
        query='SELECT * FROM events WHERE 1=1';args=[]
        if principal:query+=' AND principal=?';args.append(principal)
        if decision!='all':query+=' AND observed_allow=?';args.append(int(decision=='allow'))
        with self.store.connect() as db:
            total=db.execute('SELECT COUNT(*) FROM ('+query+')',args).fetchone()[0]
            rows=[dict(e) for e in db.execute(query+' ORDER BY id DESC LIMIT 100',args)]
        return {'events':rows,'matching_total':total,'shown':len(rows)}

    def evaluate(self):
        p=self.policy()
        with self.store.connect() as db:
            events=[dict(x) for x in db.execute('SELECT * FROM events ORDER BY id')]
            run=db.execute('INSERT INTO runs VALUES(NULL,?,?,?)',(time.time(),p['version'],'{}')).lastrowid
            for e in events:
                for name in ('observed','candidate'):
                    start=time.perf_counter_ns()
                    prediction=not e['observed_allow'] if name=='observed' else candidate_deny(e,p['rules'])[0]
                    latency=(time.perf_counter_ns()-start)/1000
                    db.execute('INSERT INTO replay VALUES(?,?,?,?,?,?)',(run,e['id'],name,int(prediction),e['expected_deny'],latency))
            result={'run_id':run,'version':p['version'],'events':len(events),'seed':SEED,'positive_class':'deny','kind':'paired offline replay on synthetic labels'}
            for name in ('observed','candidate'):
                counts=dict(db.execute('''SELECT SUM(predicted_deny=1 AND expected_deny=1) AS tp,
                  SUM(predicted_deny=1 AND expected_deny=0) AS fp,SUM(predicted_deny=0 AND expected_deny=1) AS fn,
                  SUM(predicted_deny=0 AND expected_deny=0) AS tn,AVG(latency_us) AS mean_latency_us
                  FROM replay WHERE run_id=? AND variant=?''',(run,name)).fetchone())
                tp,fp,fn,tn=[counts[k] for k in ('tp','fp','fn','tn')]
                accuracy=(tp+tn)/len(events);n=len(events);z=1.96
                center=(accuracy+z*z/(2*n))/(1+z*z/n);half=z*((accuracy*(1-accuracy)/n+z*z/(4*n*n))**.5)/(1+z*z/n)
                counts.update(false_allow=fn,false_deny=fp,precision=tp/(tp+fp) if tp+fp else None,
                              recall=tp/(tp+fn) if tp+fn else None,accuracy=accuracy,
                              accuracy_interval_95=[max(0,center-half),min(1,center+half)])
                result[name]=counts
            result['changed_decisions']=db.execute('''SELECT COUNT(*) FROM replay a JOIN replay b ON a.run_id=b.run_id
              AND a.event_id=b.event_id WHERE a.run_id=? AND a.variant='observed' AND b.variant='candidate'
              AND a.predicted_deny!=b.predicted_deny''',(run,)).fetchone()[0]
            db.execute('UPDATE runs SET summary=? WHERE id=?',(json.dumps(result),run))
        return result

    def csv_export(self):
        with self.store.connect() as db:rows=[dict(e) for e in db.execute('SELECT * FROM events ORDER BY id')]
        out=io.StringIO();writer=csv.DictWriter(out,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
        return out.getvalue()

    def report(self):
        overview=self.overview();f=self.findings()
        with self.store.connect() as db:r=db.execute('SELECT summary FROM runs ORDER BY id DESC LIMIT 1').fetchone()
        latest=json.loads(r['summary']) if r else None
        text=f'''# Policy Lens — access policy review

## Evidence scope
Synthetic Northstar access logs: {overview['totals']['events']} events, {overview['totals']['principals']} identities,
30 days, seed {SEED}. All conclusions are review candidates for this fictional dataset.

## Findings
- Unused permission candidates: {len(f['unused_permissions'])}.
- Cross-department identity/resource groups with successful access: {len(f['cross_department_access'])}.
- Sensitive export groups: {len(f['sensitive_exports'])}.
- Hourly volume spikes: {len(f['volume_spikes'])}.

## Proposed actions
Review unused entitlements with resource owners; confirm business need before revocation.
Review cross-department exceptions and sensitive export privileges.
Investigate high-volume buckets using event evidence; a spike does not establish compromise.
Replay candidate controls before considering rollout; verify behavior on independently labeled real traffic.

## Limitations
Synthetic labels encode the desired policy rubric. No real incidents, live A/B experiment,
production access changes, or automatic revocations occur. Time-window non-use does not prove a permission is unnecessary.
In-process replay latency excludes HTTP/database overhead; Wilson intervals describe this sample only.
'''
        if latest:
            text+=f"\n## Latest policy replay\nRun {latest['run_id']}; policy v{latest['version']}.\nObserved false allows: {latest['observed']['false_allow']}; false denies: {latest['observed']['false_deny']}.\nCandidate false allows: {latest['candidate']['false_allow']}; false denies: {latest['candidate']['false_deny']}.\nChanged decisions: {latest['changed_decisions']}.\n"
        text+='\n## Detailed evidence\n```json\n'+json.dumps(f,indent=2)+'\n```\n'
        return text

    def route(self,method,path,body,user):
        admin(user)
        if method=='GET' and path=='/api/state':
            with self.store.connect() as db:r=db.execute('SELECT summary FROM runs ORDER BY id DESC LIMIT 1').fetchone()
            return {'user':{'name':user['name'],'role':user['role']},'csrf':user['csrf'],'overview':self.overview(),
                    'findings':self.findings(),'policy':self.policy(),'evaluation':json.loads(r['summary']) if r else None,
                    'principals':[p for p,_,_ in PRINCIPALS]}
        if method=='POST' and path=='/api/logs':return self.logs(body)
        if method=='POST' and path=='/api/policy':
            rules=body.get('rules',{})
            if set(rules)!=set(RULES) or any(type(v)!=bool for v in rules.values()):raise Problem(400,'Supply four boolean rules.')
            with self.store.connect() as db:db.execute('INSERT INTO policies VALUES(NULL,?,?)',(json.dumps(rules),time.time()))
            return self.policy()
        if method=='POST' and path=='/api/evaluate':return self.evaluate()
        if method=='GET' and path=='/api/report':return {'markdown':self.report()}
        if method=='GET' and path=='/api/export':return {'csv':self.csv_export()}
        raise Problem(404,'Endpoint does not exist.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--port',type=int,default=8767)
    parser.add_argument('--db',default=str(Path(__file__).with_name('demo.sqlite')));args=parser.parse_args()
    serve(Application(args.db),Path(__file__).with_name('web'),args.port)
