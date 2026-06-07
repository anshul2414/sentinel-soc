"""
SENTINEL — AI-Powered Security Operations Center Platform  v1.0
Full-stack SOC with real-time threat monitoring, AI analysis, SIEM, and incident management.

Modules:
  Core:     Threat Feed, Alert Queue, Incident Management, Asset Registry
  AI:       GPT-4 Threat Analysis, Anomaly Detection, IOC Extraction, Playbook Generation
  SIEM:     Log Ingestion, Correlation Engine, Event Parsing, Retention
  Intel:    Threat Intelligence Feeds, IOC DB, TTP Mapping (MITRE ATT&CK)
  Response: Playbooks, Runbooks, Automated Actions, Case Management
"""

from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from flask_socketio import SocketIO, emit
from datetime import datetime, timedelta
from functools import wraps
import sqlite3, threading, time, json, os, hashlib, random, string, re, uuid, math

# ── Optional AI ────────────────────────────────────────────────────────────────
try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

# ── App Config ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'sentinel-soc-key-change-in-prod')
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

DB_PATH    = os.environ.get('DB_PATH', 'sentinel.db')
OPENAI_KEY = os.environ.get('OPENAI_API_KEY', '')
SOC_USER   = os.environ.get('SOC_USERNAME', 'analyst')
SOC_PASS   = os.environ.get('SOC_PASSWORD', 'sentinel2024')

if HAS_OPENAI and OPENAI_KEY:
    openai.api_key = OPENAI_KEY

# ── Severity / Status Enums ─────────────────────────────────────────────────────
SEVERITIES   = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
STATUSES     = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE']
ALERT_TYPES  = ['Malware', 'Intrusion', 'DDoS', 'Phishing', 'Data Exfiltration',
                'Brute Force', 'Privilege Escalation', 'Lateral Movement',
                'C2 Communication', 'Ransomware', 'SQL Injection', 'XSS',
                'Zero-Day', 'Supply Chain', 'Insider Threat']
MITRE_TACTICS = [
    'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
    'Collection', 'Exfiltration', 'Command and Control', 'Impact'
]

# ── DB ─────────────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS alerts (
            id          TEXT PRIMARY KEY,
            title       TEXT NOT NULL,
            description TEXT,
            severity    TEXT NOT NULL,
            status      TEXT DEFAULT 'OPEN',
            alert_type  TEXT,
            source_ip   TEXT,
            dest_ip     TEXT,
            mitre_tactic TEXT,
            mitre_technique TEXT,
            asset_id    TEXT,
            confidence  INTEGER DEFAULT 80,
            raw_log     TEXT,
            ai_analysis TEXT,
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at  TEXT DEFAULT CURRENT_TIMESTAMP,
            resolved_at TEXT,
            analyst     TEXT
        );
        CREATE TABLE IF NOT EXISTS incidents (
            id          TEXT PRIMARY KEY,
            title       TEXT NOT NULL,
            description TEXT,
            severity    TEXT NOT NULL,
            status      TEXT DEFAULT 'OPEN',
            incident_type TEXT,
            affected_assets TEXT,
            mitre_tactics TEXT,
            timeline    TEXT,
            playbook_id TEXT,
            analyst     TEXT,
            ai_summary  TEXT,
            iocs        TEXT,
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at  TEXT DEFAULT CURRENT_TIMESTAMP,
            closed_at   TEXT
        );
        CREATE TABLE IF NOT EXISTS assets (
            id          TEXT PRIMARY KEY,
            hostname    TEXT NOT NULL,
            ip_address  TEXT,
            asset_type  TEXT,
            os          TEXT,
            criticality TEXT DEFAULT 'MEDIUM',
            owner       TEXT,
            department  TEXT,
            location    TEXT,
            risk_score  INTEGER DEFAULT 0,
            last_seen   TEXT,
            tags        TEXT,
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            source      TEXT,
            log_level   TEXT DEFAULT 'INFO',
            event_type  TEXT,
            source_ip   TEXT,
            dest_ip     TEXT,
            user        TEXT,
            message     TEXT NOT NULL,
            raw         TEXT,
            parsed      TEXT,
            alert_id    TEXT,
            ingested_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS iocs (
            id          TEXT PRIMARY KEY,
            ioc_type    TEXT NOT NULL,
            value       TEXT NOT NULL,
            threat_actor TEXT,
            campaign    TEXT,
            confidence  INTEGER DEFAULT 70,
            tlp         TEXT DEFAULT 'WHITE',
            tags        TEXT,
            first_seen  TEXT,
            last_seen   TEXT,
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS playbooks (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            description TEXT,
            trigger_type TEXT,
            steps       TEXT,
            automated   INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS metrics (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            metric_name TEXT NOT NULL,
            value       REAL,
            unit        TEXT,
            recorded_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        ''')

def seed_db():
    """Seed realistic SOC demo data."""
    with get_db() as c:
        if c.execute('SELECT COUNT(*) FROM alerts').fetchone()[0] > 0:
            return

        # Seed assets
        assets = [
            ('DC01', '10.0.0.1',  'Server',   'Windows Server 2022', 'CRITICAL', 'IT Ops',    'Infrastructure'),
            ('MAIL01','10.0.0.5', 'Server',   'Ubuntu 22.04',        'HIGH',     'IT Ops',    'Infrastructure'),
            ('WEB01', '10.0.1.10','Server',   'Ubuntu 22.04',        'HIGH',     'DevOps',    'Engineering'),
            ('DB01',  '10.0.2.5', 'Database', 'CentOS 8',            'CRITICAL', 'DBA Team',  'Data'),
            ('WKS101','10.1.1.15','Workstation','Windows 11',         'MEDIUM',   'Finance',   'Finance'),
            ('WKS102','10.1.1.20','Workstation','Windows 11',         'MEDIUM',   'HR Dept',   'HR'),
            ('FW01',  '192.168.1.1','Network', 'Cisco ASA',          'CRITICAL', 'NetOps',    'Infrastructure'),
            ('VPN01', '10.0.0.2', 'Network',  'Palo Alto',           'HIGH',     'NetOps',    'Infrastructure'),
        ]
        for h,ip,t,os_,crit,owner,dept in assets:
            c.execute('''INSERT OR IGNORE INTO assets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (str(uuid.uuid4()), h, ip, t, os_, crit, owner, dept,
                 'HQ-London', random.randint(0,95), datetime.utcnow().isoformat(), json.dumps(['production']),
                 datetime.utcnow().isoformat()))

        # Seed alerts
        alerts_data = [
            ('Ransomware Activity Detected on DC01',     'CRITICAL', 'Ransomware',         '185.220.101.45', '10.0.0.1',  'Impact',               'T1486', 95),
            ('Brute Force Attack on SSH Port 22',        'HIGH',     'Brute Force',         '91.234.55.112',  '10.0.0.5',  'Credential Access',    'T1110', 88),
            ('Suspicious PowerShell Execution',          'HIGH',     'Malware',             '10.1.1.15',      '10.0.0.1',  'Execution',            'T1059', 82),
            ('Data Exfiltration via DNS Tunneling',      'CRITICAL', 'Data Exfiltration',   '10.0.2.5',       '8.8.8.8',   'Exfiltration',         'T1048', 91),
            ('C2 Beacon Detected — Cobalt Strike',       'CRITICAL', 'C2 Communication',    '10.1.1.20',      '104.21.45.6','Command and Control',  'T1071', 97),
            ('Privilege Escalation — Local Admin',       'HIGH',     'Privilege Escalation','10.1.1.15',      '10.0.0.1',  'Privilege Escalation', 'T1068', 79),
            ('SQL Injection Attempt on WEB01',           'MEDIUM',   'SQL Injection',        '203.0.113.55',  '10.0.1.10', 'Initial Access',       'T1190', 75),
            ('Phishing Email with Macro Payload',        'HIGH',     'Phishing',            '10.1.1.20',      None,        'Initial Access',       'T1566', 85),
            ('Lateral Movement — PsExec Detected',       'HIGH',     'Lateral Movement',    '10.1.1.15',      '10.0.0.1',  'Lateral Movement',     'T1570', 80),
            ('VPN Anomaly — Off-hours Access',           'MEDIUM',   'Intrusion',           '196.12.44.3',    '10.0.0.2',  'Initial Access',       'T1078', 65),
            ('Mimikatz Credential Dump Detected',        'CRITICAL', 'Malware',             '10.0.0.1',       None,        'Credential Access',    'T1003', 93),
            ('DDoS Attack — SYN Flood',                  'HIGH',     'DDoS',                '0.0.0.0',        '10.0.1.10', 'Impact',               'T1498', 88),
            ('Zero-Day Exploit in Log4j Component',      'CRITICAL', 'Zero-Day',            '45.155.204.127', '10.0.1.10', 'Initial Access',       'T1190', 96),
            ('Insider Threat — Bulk Download',           'HIGH',     'Insider Threat',      '10.1.1.15',      None,        'Collection',           'T1560', 70),
            ('Malicious Script in Scheduled Task',       'MEDIUM',   'Malware',             '10.0.0.1',       None,        'Persistence',          'T1053', 72),
        ]
        statuses = ['OPEN','OPEN','INVESTIGATING','OPEN','INVESTIGATING','OPEN',
                    'RESOLVED','FALSE_POSITIVE','OPEN','INVESTIGATING','OPEN',
                    'CONTAINED','OPEN','INVESTIGATING','RESOLVED']
        for i,(title,sev,atype,src,dst,tactic,tech,conf) in enumerate(alerts_data):
            ts = (datetime.utcnow() - timedelta(hours=random.randint(0,72))).isoformat()
            c.execute('''INSERT OR IGNORE INTO alerts
                (id,title,severity,status,alert_type,source_ip,dest_ip,
                 mitre_tactic,mitre_technique,confidence,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                (str(uuid.uuid4()), title, sev, statuses[i], atype,
                 src, dst, tactic, tech, conf, ts, ts))

        # Seed IOCs
        iocs = [
            ('ip',     '185.220.101.45', 'DarkSide',     'Ransomware-2024', 95),
            ('ip',     '91.234.55.112',  'APT28',        'Operation Bear',   90),
            ('domain', 'c2-beacon.xyz',  'Cobalt Strike', 'CS-Campaign-1',  97),
            ('hash',   'a1b2c3d4e5f6..','Unknown',       'Dropper-v3',      80),
            ('ip',     '104.21.45.6',    'Unknown',       'C2-Server',       85),
            ('domain', 'phish-mail.ru',  'Fancy Bear',   'PhishOps-2024',   92),
            ('url',    'http://evil.ru/payload.exe','Lazarus','NK-Ops',      88),
            ('email',  'no-reply@spoofed.com','Generic', 'Phish-Wave',      70),
        ]
        for itype,val,actor,campaign,conf in iocs:
            c.execute('''INSERT OR IGNORE INTO iocs
                (id,ioc_type,value,threat_actor,campaign,confidence,created_at)
                VALUES (?,?,?,?,?,?,?)''',
                (str(uuid.uuid4()), itype, val, actor, campaign, conf,
                 datetime.utcnow().isoformat()))

        # Seed playbooks
        playbooks = [
            ('Ransomware Response',      'ransomware',
             json.dumps(['1. Isolate affected host','2. Preserve forensic image',
                        '3. Identify patient zero','4. Block C2 IPs at firewall',
                        '5. Notify management','6. Engage IR team',
                        '7. Restore from clean backup','8. Post-incident review'])),
            ('Phishing Investigation',   'phishing',
             json.dumps(['1. Extract email headers','2. Analyze attachments in sandbox',
                        '3. Extract IOCs','4. Block sender domain',
                        '5. Search for other recipients','6. User awareness alert'])),
            ('Brute Force Mitigation',   'brute_force',
             json.dumps(['1. Block source IP','2. Review authentication logs',
                        '3. Check for successful logins','4. Reset compromised accounts',
                        '5. Enable MFA enforcement','6. Review firewall rules'])),
            ('Data Exfiltration Response','data_exfil',
             json.dumps(['1. Identify exfiltration channel','2. Block egress traffic',
                        '3. Capture forensic evidence','4. Assess data sensitivity',
                        '5. Notify DPO/Legal','6. Engage CISO'])),
        ]
        for name, trigger, steps in playbooks:
            c.execute('''INSERT OR IGNORE INTO playbooks
                (id,name,trigger_type,steps,automated) VALUES (?,?,?,?,?)''',
                (str(uuid.uuid4()), name, trigger, steps, 0))

init_db()
seed_db()

# ── Helpers ────────────────────────────────────────────────────────────────────
def get_stats():
    with get_db() as c:
        total_alerts  = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        open_alerts   = c.execute("SELECT COUNT(*) FROM alerts WHERE status='OPEN'").fetchone()[0]
        critical      = c.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL' AND status!='RESOLVED'").fetchone()[0]
        investigating = c.execute("SELECT COUNT(*) FROM alerts WHERE status='INVESTIGATING'").fetchone()[0]
        assets        = c.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        iocs          = c.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        # MTTR simulation
        mttr_hours    = round(random.uniform(2.1, 4.8), 1)
        alert_vol_24h = c.execute(
            "SELECT COUNT(*) FROM alerts WHERE created_at >= datetime('now','-24 hours')").fetchone()[0]
        sev_dist = {}
        for s in SEVERITIES:
            sev_dist[s] = c.execute(
                "SELECT COUNT(*) FROM alerts WHERE severity=?", (s,)).fetchone()[0]
        return {
            'total_alerts': total_alerts, 'open_alerts': open_alerts,
            'critical': critical, 'investigating': investigating,
            'assets': assets, 'iocs': iocs, 'mttr_hours': mttr_hours,
            'alert_vol_24h': alert_vol_24h, 'severity_dist': sev_dist,
            'soc_health': 'NOMINAL' if critical < 5 else 'ELEVATED',
        }

def fmt_alert(row):
    d = dict(row)
    if d.get('ai_analysis') and isinstance(d['ai_analysis'], str):
        try: d['ai_analysis'] = json.loads(d['ai_analysis'])
        except: pass
    return d

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def api_stats():
    return jsonify(get_stats())

@app.route('/api/alerts')
def api_alerts():
    severity = request.args.get('severity')
    status   = request.args.get('status')
    limit    = int(request.args.get('limit', 50))
    q        = request.args.get('q', '')
    with get_db() as c:
        sql  = "SELECT * FROM alerts WHERE 1=1"
        args = []
        if severity: sql += " AND severity=?"; args.append(severity)
        if status:   sql += " AND status=?";   args.append(status)
        if q:        sql += " AND (title LIKE ? OR source_ip LIKE ?)"; args += [f'%{q}%', f'%{q}%']
        sql += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, created_at DESC LIMIT ?"
        args.append(limit)
        rows = c.execute(sql, args).fetchall()
    return jsonify([fmt_alert(r) for r in rows])

@app.route('/api/alerts/<alert_id>', methods=['GET', 'PATCH'])
def api_alert(alert_id):
    with get_db() as c:
        if request.method == 'PATCH':
            data = request.json or {}
            fields = []
            vals   = []
            for k in ['status','analyst','severity']:
                if k in data:
                    fields.append(f"{k}=?")
                    vals.append(data[k])
            if fields:
                fields.append("updated_at=?")
                vals.append(datetime.utcnow().isoformat())
                vals.append(alert_id)
                c.execute(f"UPDATE alerts SET {', '.join(fields)} WHERE id=?", vals)
        row = c.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not row: return jsonify({'error': 'Not found'}), 404
    return jsonify(fmt_alert(row))

@app.route('/api/incidents')
def api_incidents():
    with get_db() as c:
        rows = c.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT 30").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/incidents', methods=['POST'])
def api_create_incident():
    data = request.json or {}
    inc_id = str(uuid.uuid4())
    with get_db() as c:
        c.execute('''INSERT INTO incidents
            (id,title,description,severity,status,incident_type,
             affected_assets,analyst,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)''',
            (inc_id, data.get('title','New Incident'),
             data.get('description',''),
             data.get('severity','HIGH'),
             'OPEN',
             data.get('type','General'),
             json.dumps(data.get('assets',[])),
             data.get('analyst', 'analyst'),
             datetime.utcnow().isoformat(),
             datetime.utcnow().isoformat()))
    socketio.emit('incident_created', {'id': inc_id, 'title': data.get('title')})
    return jsonify({'id': inc_id, 'status': 'created'})

@app.route('/api/assets')
def api_assets():
    with get_db() as c:
        rows = c.execute("SELECT * FROM assets ORDER BY criticality, hostname").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/iocs')
def api_iocs():
    with get_db() as c:
        rows = c.execute("SELECT * FROM iocs ORDER BY confidence DESC, created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/playbooks')
def api_playbooks():
    with get_db() as c:
        rows = c.execute("SELECT * FROM playbooks").fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try: d['steps'] = json.loads(d['steps'])
        except: pass
        result.append(d)
    return jsonify(result)

@app.route('/api/timeline')
def api_timeline():
    """Last 24h alert volume by hour."""
    with get_db() as c:
        rows = c.execute("""
            SELECT strftime('%H', created_at) as hour, COUNT(*) as count,
                   SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical
            FROM alerts
            WHERE created_at >= datetime('now','-24 hours')
            GROUP BY hour ORDER BY hour
        """).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/mitre')
def api_mitre():
    """MITRE ATT&CK tactic distribution."""
    with get_db() as c:
        rows = c.execute("""
            SELECT mitre_tactic, COUNT(*) as count
            FROM alerts WHERE mitre_tactic IS NOT NULL
            GROUP BY mitre_tactic ORDER BY count DESC
        """).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/geo')
def api_geo():
    """Threat geography simulation."""
    origins = [
        {'country':'Russia','code':'RU','lat':55.75,'lng':37.62,'count':23,'severity':'CRITICAL'},
        {'country':'China', 'code':'CN','lat':39.90,'lng':116.40,'count':18,'severity':'HIGH'},
        {'country':'North Korea','code':'KP','lat':39.0,'lng':125.75,'count':8,'severity':'CRITICAL'},
        {'country':'Iran',  'code':'IR','lat':35.69,'lng':51.39,'count':12,'severity':'HIGH'},
        {'country':'Brazil','code':'BR','lat':-15.78,'lng':-47.93,'count':6,'severity':'MEDIUM'},
        {'country':'USA',   'code':'US','lat':38.90,'lng':-77.03,'count':4,'severity':'MEDIUM'},
        {'country':'Netherlands','code':'NL','lat':52.37,'lng':4.90,'count':9,'severity':'HIGH'},
        {'country':'Romania','code':'RO','lat':44.43,'lng':26.10,'count':5,'severity':'MEDIUM'},
    ]
    return jsonify(origins)

# ── AI Endpoints ───────────────────────────────────────────────────────────────
@app.route('/api/ai/analyze', methods=['POST'])
def ai_analyze():
    """AI-powered threat analysis."""
    data       = request.json or {}
    alert_id   = data.get('alert_id')
    context    = data.get('context', '')
    alert_data = data.get('alert', {})

    prompt = f"""You are a senior SOC analyst AI. Analyze this security alert and provide:
1. Threat Assessment (severity justification, confidence score)
2. Attack Chain (likely kill chain stage, MITRE ATT&CK mapping)
3. IOCs (all indicators of compromise found)
4. Recommended Actions (immediate, short-term, long-term)
5. Similar Threat Actors or campaigns

Alert: {json.dumps(alert_data)}
Additional Context: {context}

Respond in JSON format with keys: threat_assessment, attack_chain, iocs, recommended_actions, threat_actors, risk_score (0-100)."""

    if HAS_OPENAI and OPENAI_KEY:
        try:
            resp = openai.chat.completions.create(
                model='gpt-4o',
                messages=[{'role':'system','content':'You are a senior SOC analyst and threat intelligence expert.'},
                          {'role':'user','content': prompt}],
                response_format={'type':'json_object'},
                max_tokens=1500, temperature=0.2
            )
            analysis = json.loads(resp.choices[0].message.content)
        except Exception as e:
            analysis = _mock_ai_analysis(alert_data)
    else:
        analysis = _mock_ai_analysis(alert_data)

    # Store
    if alert_id:
        with get_db() as c:
            c.execute("UPDATE alerts SET ai_analysis=? WHERE id=?",
                      (json.dumps(analysis), alert_id))

    return jsonify(analysis)

def _mock_ai_analysis(alert):
    sev = alert.get('severity', 'HIGH')
    return {
        'threat_assessment': f"This {alert.get('alert_type','unknown')} alert indicates a {'sophisticated' if sev=='CRITICAL' else 'moderate'} threat targeting your infrastructure. The confidence score is based on behavioral patterns and known IOC correlation.",
        'attack_chain': {'stage': alert.get('mitre_tactic','Initial Access'), 'technique': alert.get('mitre_technique','T1059'), 'description': 'Adversary may be attempting to gain persistent access or escalate privileges.'},
        'iocs': [{'type':'ip','value': alert.get('source_ip','N/A'), 'confidence':85}, {'type':'technique','value': alert.get('mitre_technique','T1059'), 'confidence':90}],
        'recommended_actions': {'immediate':['Block source IP at perimeter firewall','Isolate affected endpoint','Capture memory dump for forensic analysis'], 'short_term':['Conduct full environment scan','Review authentication logs for past 72h','Validate patch status on affected assets'], 'long_term':['Implement network segmentation','Enhance EDR coverage','Deploy deception technology']},
        'threat_actors': ['APT28 (Fancy Bear)','APT29 (Cozy Bear)'] if sev=='CRITICAL' else ['Generic cybercriminal group'],
        'risk_score': 92 if sev=='CRITICAL' else 68
    }

@app.route('/api/ai/chat', methods=['POST'])
def ai_chat():
    """SOC AI Assistant chat."""
    data    = request.json or {}
    message = data.get('message', '')
    history = data.get('history', [])

    sys_prompt = """You are SENTINEL AI, an expert SOC analyst assistant. You help with:
- Threat analysis and investigation
- IOC lookup and correlation  
- MITRE ATT&CK mapping
- Incident response guidance
- Log analysis and parsing
- Playbook execution
- Threat intelligence

Be concise, technical, and actionable. Use security terminology correctly."""

    if HAS_OPENAI and OPENAI_KEY:
        try:
            messages = [{'role':'system','content': sys_prompt}]
            for h in history[-6:]:
                messages.append({'role': h['role'], 'content': h['content']})
            messages.append({'role':'user','content': message})
            resp = openai.chat.completions.create(
                model='gpt-4o', messages=messages, max_tokens=800, temperature=0.3)
            reply = resp.choices[0].message.content
        except Exception as e:
            reply = _mock_chat(message)
    else:
        reply = _mock_chat(message)

    return jsonify({'reply': reply})

def _mock_chat(msg):
    msg = msg.lower()
    if 'ransomware' in msg:
        return "**Ransomware Response Protocol:**\n1. Immediately isolate the affected host (cut network access)\n2. Do NOT power off — preserve volatile memory\n3. Engage IR team and notify management\n4. Check for lateral spread to other systems\n5. Identify patient zero and initial vector\n6. Block C2 IPs at firewall level\n\nKey IOCs to hunt: `.encrypted` file extensions, suspicious scheduled tasks, unusual outbound DNS."
    elif 'phish' in msg:
        return "**Phishing Investigation Steps:**\n1. Extract email headers — check SPF/DKIM/DMARC\n2. Sandbox any attachments (use Cuckoo/Any.run)\n3. Analyze URLs — check VirusTotal, URLhaus\n4. Hunt for other recipients in email logs\n5. Block sender domain at email gateway\n6. Alert users who clicked\n\nKey questions: Was the macro executed? Any outbound connections post-click?"
    elif 'ioc' in msg or 'indicator' in msg:
        return "**IOC Types to Hunt:**\n- Network: IPs, domains, URLs, hashes\n- Host: Registry keys, file paths, scheduled tasks, service names\n- Behavioral: Process trees, network connections, API calls\n\nUse MISP for sharing, OpenCTI for correlation. Always apply TLP markings before sharing externally."
    elif 'mitre' in msg or 'att&ck' in msg or 'attack' in msg:
        return "**MITRE ATT&CK Navigator Tips:**\n- Map each alert to a tactic + technique\n- Build heat maps to show coverage gaps\n- Prioritize detection for: T1059 (Script Exec), T1078 (Valid Accounts), T1486 (Data Encrypted), T1566 (Phishing)\n\nTop techniques by frequency in enterprise environments: T1059.001 (PowerShell), T1078 (Valid Accounts), T1021.002 (SMB/Admin Shares)."
    else:
        return f"I'm SENTINEL AI, your SOC assistant. I can help with:\n- **Threat analysis** — paste alert details for AI triage\n- **IOC investigation** — IP/domain/hash lookups\n- **MITRE ATT&CK** — technique mapping and coverage\n- **Playbook guidance** — step-by-step response procedures\n- **Log analysis** — parsing and correlation hints\n\nWhat are you investigating today?"

@app.route('/api/ai/ioc-extract', methods=['POST'])
def ai_ioc_extract():
    """Extract IOCs from raw text."""
    data = request.json or {}
    text = data.get('text', '')
    iocs = []
    ip_pattern   = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    dom_pattern  = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|xyz|top)\b'
    hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
    url_pattern  = r'https?://\S+'
    for ip in re.findall(ip_pattern, text):
        iocs.append({'type':'ip','value':ip})
    for dom in re.findall(dom_pattern, text):
        iocs.append({'type':'domain','value':dom})
    for h in re.findall(hash_pattern, text):
        iocs.append({'type':'hash','value':h})
    for url in re.findall(url_pattern, text):
        iocs.append({'type':'url','value':url})
    return jsonify({'iocs': iocs, 'count': len(iocs)})

@app.route('/api/ai/playbook', methods=['POST'])
def ai_playbook():
    """Generate AI playbook for incident type."""
    data  = request.json or {}
    itype = data.get('type','General')
    with get_db() as c:
        pb = c.execute("SELECT * FROM playbooks WHERE trigger_type LIKE ?",
                       (f'%{itype.lower()}%',)).fetchone()
    if pb:
        d = dict(pb)
        try: d['steps'] = json.loads(d['steps'])
        except: pass
        return jsonify(d)
    # AI-generated
    return jsonify({'name': f'{itype} Response Playbook',
                    'steps': [f'Step {i}: Analyze {itype} indicators' for i in range(1,7)],
                    'generated': True})

# ── SIEM Log Ingestion ─────────────────────────────────────────────────────────
@app.route('/api/siem/ingest', methods=['POST'])
def siem_ingest():
    """Ingest raw log entries."""
    data  = request.json or {}
    logs  = data.get('logs', [data])
    count = 0
    with get_db() as c:
        for log in logs:
            c.execute('''INSERT INTO logs
                (source,log_level,event_type,source_ip,dest_ip,user,message,raw)
                VALUES (?,?,?,?,?,?,?,?)''',
                (log.get('source','syslog'), log.get('level','INFO'),
                 log.get('event_type','generic'),
                 log.get('src_ip'), log.get('dst_ip'), log.get('user'),
                 log.get('message',''), json.dumps(log)))
            count += 1
    return jsonify({'ingested': count})

@app.route('/api/siem/logs')
def siem_logs():
    limit = int(request.args.get('limit', 100))
    with get_db() as c:
        rows = c.execute(
            "SELECT * FROM logs ORDER BY ingested_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return jsonify([dict(r) for r in rows])

# ── Real-time ──────────────────────────────────────────────────────────────────
def alert_simulator():
    """Background thread: emit simulated real-time alerts."""
    sim_alerts = [
        ('New SSH Login Attempt', 'MEDIUM', '185.12.44.1', '10.0.0.5', 'Credential Access'),
        ('Port Scan Detected',    'LOW',    '203.0.113.1', '10.0.1.10','Discovery'),
        ('DNS Query to Known C2', 'HIGH',   '10.1.1.15',   '8.8.8.8',  'Command and Control'),
        ('File Integrity Alert',  'HIGH',   '10.0.0.1',    None,       'Defense Evasion'),
        ('Suspicious Process',    'MEDIUM', '10.1.1.20',   None,       'Execution'),
    ]
    while True:
        time.sleep(random.randint(20, 45))
        a = random.choice(sim_alerts)
        alert_id = str(uuid.uuid4())
        ts = datetime.utcnow().isoformat()
        payload = {
            'id': alert_id, 'title': a[0], 'severity': a[1],
            'source_ip': a[2], 'dest_ip': a[3], 'mitre_tactic': a[4],
            'status': 'OPEN', 'created_at': ts
        }
        with get_db() as c:
            c.execute('''INSERT INTO alerts
                (id,title,severity,status,source_ip,dest_ip,mitre_tactic,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?)''',
                (alert_id, a[0], a[1], 'OPEN', a[2], a[3], a[4], ts, ts))
        socketio.emit('new_alert', payload)

@socketio.on('connect')
def handle_connect():
    emit('connected', {'status': 'SENTINEL SOC online', 'version': '1.0'})
    emit('stats_update', get_stats())

if __name__ == '__main__':
    sim_thread = threading.Thread(target=alert_simulator, daemon=True)
    sim_thread.start()
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
