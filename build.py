"""Build CDN assets for the public demo; the localhost UI stays unchanged."""
from pathlib import Path
import shutil

root = Path(__file__).resolve().parent
output = root / 'public'
output.mkdir(exist_ok=True)
for name in ('index.html', 'style.css', 'favicon.svg'):
    shutil.copyfile(root / 'web' / name, output / name)
shutil.copytree(root / 'web' / 'fonts', output / 'fonts', dirs_exist_ok=True)
source = (root / 'web' / 'app.js').read_text()
start = source.index('async function api(')
end = source.index('\nfunction run(', start)
replacement = '''let demoSettings;
try { demoSettings=JSON.parse(localStorage.getItem('policy-lens-demo')||'null'); } catch { demoSettings=null; }
async function api(path,body){
  const headers={'X-Demo-State':JSON.stringify(demoSettings||{rules:{department_boundary:true,managed_device:true,deny_high_risk:true,sensitive_export:true},version:1,runs:0,last:null})};
  if(body!==undefined)headers['Content-Type']='application/json';
  const r=await fetch('/api/'+path,{method:body===undefined?'GET':'POST',headers,body:body===undefined?undefined:JSON.stringify(body)});
  const out=await r.json();if(!r.ok)throw Error(out.error||'The demo could not load.');
  if(out._demo){demoSettings=out._demo;try{localStorage.setItem('policy-lens-demo',JSON.stringify(demoSettings));}catch{}delete out._demo;}
  return out;
}'''
source = source[:start] + replacement + source[end:]
source = source.replace('<button id="logout">Sign out</button>', '<button id="logout">Reset demo</button>')
source = source.replace('SECURITY ANALYTICS / OFFLINE REVIEW', 'PUBLIC DEMO / SYNTHETIC DATA')
source = source.replace('30-day synthetic window<br>12 human and service identities', '30-day synthetic window<br>12 human and service identities<br>Settings stay in this browser')
source = source.replace("await api('logout',{});state=null;csrf='';login();", "demoSettings=null;try{localStorage.removeItem('policy-lens-demo');}catch{}view='findings';await refresh();toast('Demo reset.');")
source = source.replace('refresh().catch(()=>login());', '''refresh().catch(err=>{root.innerHTML='<section class="panel spaced"><h1>Policy Lens</h1><p>'+esc(err.message)+'</p><button id="retry">Reset and retry</button></section>';root.querySelector('#retry').onclick=()=>{try{localStorage.removeItem('policy-lens-demo');}catch{}location.reload();};});''')
(output / 'app.js').write_text(source)
print('Built Policy Lens public demo assets.')
