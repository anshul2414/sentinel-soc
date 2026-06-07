
const $ = s => document.querySelector(s);
const SEV_ORDER = {CRITICAL:1,HIGH:2,MEDIUM:3,LOW:4,INFO:5};

// ── Sidebar navigation ────────────────────────────────────────────────────
document.querySelectorAll('.rail nav a').forEach((a,i)=>{
  a.onclick=()=>{document.querySelectorAll('.rail nav a').forEach(x=>x.classList.remove('active'));a.classList.add('active')};
});

// ── KPI cards ─────────────────────────────────────────────────────────────
async function loadStats(){
  const s = await fetch('/api/stats').then(r=>r.json()).catch(()=>({
    critical:2,open_alerts:9,mttr_hours:2.4,alert_vol_24h:47,soc_health:'NOMINAL',severity_dist:{CRITICAL:2,HIGH:7,MEDIUM:12,LOW:8}
  }));
  $('#health').textContent = s.soc_health||'NOMINAL';
  const kpis = [
    {label:'CRITICAL ACTIVE',   value: s.critical||0,         cls:'red',  sub:'Needs immediate action'},
    {label:'OPEN ALERTS',       value: s.open_alerts||0,       cls:'warn', sub:'In triage queue'},
    {label:'MTTR (HRS)',        value: s.mttr_hours||0,        cls:'blue', sub:'Mean time to resolve'},
    {label:'AI AUTO-RESOLVED',  value: s.alert_vol_24h||0,    cls:'ok',   sub:'Last 24 hours'},
  ];
  $('#kpis').innerHTML = kpis.map(k=>`
    <div class="kpi">
      <div class="kpi-label">${k.label}</div>
      <div class="kpi-value ${k.cls}">${k.value}</div>
      <div class="kpi-sub">${k.sub}</div>
    </div>`).join('');
}

// ── Threat Velocity Chart ──────────────────────────────────────────────────
let chart;
function initChart(){
  const ctx = document.getElementById('threatChart');
  if(!ctx) return;
  const hours = Array.from({length:24},(_,i)=>`${String(i).padStart(2,'0')}:00`);
  const data  = Array.from({length:24},()=>Math.floor(Math.random()*60+5));
  const crit  = data.map(v=>Math.floor(v*0.2));
  chart = new Chart(ctx,{
    type:'bar',
    data:{
      labels:hours,
      datasets:[
        {label:'Total Alerts',data,backgroundColor:'rgba(0,102,177,0.35)',borderColor:'#0066b1',borderWidth:1},
        {label:'Critical',data:crit,backgroundColor:'rgba(226,39,24,0.45)',borderColor:'#e22718',borderWidth:1}
      ]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{legend:{labels:{color:'#7e7e7e',boxWidth:10,font:{size:10}}}},
      scales:{
        x:{ticks:{color:'#7e7e7e',font:{size:9},maxRotation:0,autoSkip:true,maxTicksLimit:8},grid:{color:'#1a1a1a'}},
        y:{ticks:{color:'#7e7e7e',font:{size:9}},grid:{color:'#262626'}}
      }
    }
  });
}

// ── Alert Queue ────────────────────────────────────────────────────────────
async function loadAlerts(){
  const data = await fetch('/api/alerts?limit=20').then(r=>r.json()).catch(()=>[]);
  const el = $('#alerts');
  if(!data.length){el.innerHTML='<p style="color:#7e7e7e;padding:20px">No alerts</p>';return;}
  el.innerHTML = `<div class="table"><table>
    <thead><tr><th>SEV</th><th>TITLE</th><th>SOURCE</th><th>TACTIC</th><th>STATUS</th></tr></thead>
    <tbody>${data.map(a=>`<tr onclick="analyzeAlert('${a.id}')">
      <td><span class="badge ${a.severity}">${a.severity}</span></td>
      <td><span class="title">${a.title}</span></td>
      <td><span class="ip">${a.source_ip||'—'}</span></td>
      <td><span style="font-size:10px;color:#7e7e7e">${(a.mitre_tactic||'—').split(' ').slice(0,2).join(' ')}</span></td>
      <td><span class="badge ${a.status}">${a.status}</span></td>
    </tr>`).join('')}</tbody>
  </table></div>`;
  $('#alertCount').textContent = data.length;
}

// ── Incidents ──────────────────────────────────────────────────────────────
async function loadIncidents(){
  const data = await fetch('/api/incidents').then(r=>r.json()).catch(()=>[]);
  const el = $('#incidents');
  if(!data.length){
    el.innerHTML=`<div class="inc-card"><div class="inc-card-head"><span class="inc-card-title">INC-2024-0089 — Ransomware Outbreak</span><span class="badge CRITICAL">CRITICAL</span></div><div class="inc-card-meta">Analyst: Alice Chen · SLA: 2h · Playbook: Active</div></div>
    <div class="inc-card"><div class="inc-card-head"><span class="inc-card-title">INC-2024-0088 — APT Lateral Movement</span><span class="badge HIGH">HIGH</span></div><div class="inc-card-meta">Analyst: Bob Martinez · Status: Investigating</div></div>
    <div class="inc-card"><div class="inc-card-head"><span class="inc-card-title">INC-2024-0087 — Phishing Campaign</span><span class="badge MEDIUM">MEDIUM</span></div><div class="inc-card-meta">Analyst: Clara Singh · Status: Contained</div></div>`;
    return;
  }
  el.innerHTML = data.slice(0,5).map(inc=>`
    <div class="inc-card">
      <div class="inc-card-head">
        <span class="inc-card-title">${inc.title}</span>
        <span class="badge ${inc.severity}">${inc.severity}</span>
      </div>
      <div class="inc-card-meta">${inc.analyst?'Analyst: '+inc.analyst+' · ':''}Status: ${inc.status}</div>
    </div>`).join('');
}

// ── Assets ─────────────────────────────────────────────────────────────────
async function loadAssets(){
  const data = await fetch('/api/assets').then(r=>r.json()).catch(()=>[]);
  const el = $('#assets');
  const demo = [{hostname:'DC01',ip_address:'10.0.0.1',risk_score:95},{hostname:'WEB01',ip_address:'10.0.1.10',risk_score:72},{hostname:'DB01',ip_address:'10.0.2.5',risk_score:65},{hostname:'MAIL01',ip_address:'10.0.0.5',risk_score:45},{hostname:'WKS101',ip_address:'10.1.1.15',risk_score:30}];
  const list = data.length ? data : demo;
  el.innerHTML = list.slice(0,6).map(a=>{
    const r=a.risk_score||0;
    const cls=r>75?'':'r>50?med:low';
    return `<div class="asset-row">
      <span class="asset-name">${a.hostname}</span>
      <span class="asset-ip">${a.ip_address||''}</span>
      <div class="risk-bar"><div class="risk-fill ${r>75?'':'r>50?med:low'}" style="width:${r}%"></div></div>
      <span style="font-size:10px;color:${r>75?'#e22718':r>50?'#f4b400':'#0fa336'}">${r}</span>
    </div>`;
  }).join('');
}

// ── MITRE ATT&CK ───────────────────────────────────────────────────────────
async function loadMitre(){
  const data = await fetch('/api/mitre').then(r=>r.json()).catch(()=>[]);
  const tactics = ['Initial Access','Execution','Persistence','Privilege Escalation','Defense Evasion','Credential Access','Discovery','Lateral Movement','Collection','Exfiltration','C2','Impact'];
  const hot = data.map(d=>d.mitre_tactic);
  const critical = data.filter(d=>d.count>2).map(d=>d.mitre_tactic);
  $('#mitre').innerHTML = `<div class="mitre-grid">${tactics.map(t=>`<div class="mitre-cell ${critical.includes(t)?'hot':hot.includes(t)?'active':''}">${t.replace('Privilege Escalation','Priv Esc').replace('Command and Control','C2').replace('Defense Evasion','Def Evasion').replace('Credential Access','Cred Access')}</div>`).join('')}</div>`;
}

// ── IOCs ────────────────────────────────────────────────────────────────────
async function loadIOCs(){
  const data = await fetch('/api/iocs').then(r=>r.json()).catch(()=>[]);
  const el = $('#iocs');
  const demo = [{ioc_type:'IP',value:'185.220.101.45',confidence:95},{ioc_type:'DOMAIN',value:'c2-beacon.xyz',confidence:97},{ioc_type:'HASH',value:'a1b2c3d4e5f6ab12',confidence:80},{ioc_type:'EMAIL',value:'spoof@phish.ru',confidence:70},{ioc_type:'URL',value:'http://evil.ru/pay.exe',confidence:88}];
  const list = data.length ? data : demo;
  el.innerHTML = list.slice(0,8).map(i=>`
    <div class="ioc-row">
      <span class="ioc-type">${i.ioc_type||i.type}</span>
      <span class="ioc-val">${i.value}</span>
      <span class="ioc-conf">${i.confidence||80}%</span>
    </div>`).join('');
}

// ── AI Chat ─────────────────────────────────────────────────────────────────
const history = [];
async function askAI(){
  const inp = $('#ask');
  const msg = inp.value.trim();
  if(!msg) return;
  inp.value = '';
  addMsg('user', msg);
  history.push({role:'user',content:msg});
  const res = await fetch('/api/ai/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg,history:history.slice(-6)})}).then(r=>r.json()).catch(()=>({reply:'AI unavailable — check backend connectivity.'}));
  addMsg('ai', res.reply||'No response.');
  history.push({role:'assistant',content:res.reply});
}
function addMsg(role,text){
  const el = $('#chat');
  const d = document.createElement('div');
  d.className = `chat-msg ${role}`;
  d.innerHTML = text.replace(/\*\*(.*?)\*\*/g,'<strong>$1</strong>').replace(/`([^`]+)`/g,'<code style="background:#262626;padding:1px 4px;font-family:monospace">$1</code>').replace(/
/g,'<br>');
  el.appendChild(d);
  el.scrollTop = el.scrollHeight;
}
$('#ask').addEventListener('keydown',e=>{if(e.key==='Enter') askAI();});

// ── Analyze single alert via AI ─────────────────────────────────────────────
async function analyzeAlert(id){
  addMsg('user',`Analyze alert ${id}`);
  const alert = await fetch(`/api/alerts/${id}`).then(r=>r.json()).catch(()=>({id}));
  const res = await fetch('/api/ai/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alert_id:id,alert})}).then(r=>r.json()).catch(()=>null);
  if(res) addMsg('ai',`**AI ANALYSIS — ${id}**

${res.threat_assessment||''}

**Risk Score:** ${res.risk_score||'N/A'}/100

**Immediate Actions:**
${(res.recommended_actions?.immediate||[]).map(s=>'• '+s).join('
')}`);
}

// ── Auto-refresh ────────────────────────────────────────────────────────────
async function init(){
  await Promise.all([loadStats(),loadAlerts(),loadIncidents(),loadAssets(),loadMitre(),loadIOCs()]);
  initChart();
  addMsg('ai','**SENTINEL AI** online. Ask me to analyze threats, hunt IOCs, generate KQL/SPL queries, map MITRE techniques, or explain any alert in the queue. Click any alert row to trigger instant AI analysis.');
}
init();
setInterval(()=>Promise.all([loadStats(),loadAlerts()]),30000);
