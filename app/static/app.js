const API = '';
let ws = null;
let polling = null;
let timelineData = [];
let isSimulating = false;
let hoveredPoint = null;
let canvasInitialized = false;
let inspectorEvents = [];
let inspectorSelectedIdx = null;
let inspectorPaused = false;
let inspectorFilterText = '';
let liveEventBuffer = [];

function init() {
    connectWebSocket();
    startPolling();
    document.getElementById('speedSlider').addEventListener('input', (e) => {
        document.getElementById('speedLabel').textContent = e.target.value + 'x';
    });
    loadAdminData();
    initCanvas();
}

// ============ CANVAS INIT (fix glitching) ============

function initCanvas() {
    const canvas = document.getElementById('timelineCanvas');
    if (!canvas) return;
    const container = canvas.parentElement;
    const rect = container.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    canvas.style.width = rect.width + 'px';
    canvas.style.height = rect.height + 'px';
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    canvasInitialized = true;
    setupTimelineInteraction();
    drawTimeline();
}

window.addEventListener('resize', () => {
    canvasInitialized = false;
    initCanvas();
});

// ============ WEBSOCKET (real-time events) ============

function connectWebSocket() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}/ws`);
    ws.onopen = () => {
        document.getElementById('statusDot').className = 'status-dot';
        document.getElementById('statusText').textContent = 'Connected';
    };
    ws.onmessage = (e) => {
        try {
            const data = JSON.parse(e.data);
            if (data.type === 'event') {
                handleLiveEvent(data);
            } else {
                updateDashboard(data);
            }
        } catch(err) {}
    };
    ws.onclose = () => {
        document.getElementById('statusDot').className = 'status-dot disconnected';
        document.getElementById('statusText').textContent = 'Reconnecting...';
        setTimeout(connectWebSocket, 3000);
    };
    ws.onerror = () => ws.close();
}

function handleLiveEvent(ev) {
    liveEventBuffer.unshift(ev);
    if (liveEventBuffer.length > 500) liveEventBuffer = liveEventBuffer.slice(0, 500);
    if (!inspectorPaused) {
        renderInspectorList();
    }
    updateFilterStatus();
}

// ============ POLLING ============

function startPolling() {
    polling = setInterval(async () => {
        try {
            const res = await fetch(`${API}/api/simulation/status`);
            const data = await res.json();
            isSimulating = data.running;
            updateSimulationUI(data.running);
            if (data.risk_history && data.risk_history.length > 0) {
                timelineData = data.risk_history;
                drawTimeline();
            }
            const evRes = await fetch(`${API}/api/events?limit=50`);
            const events = await evRes.json();
            updateEventsTable(events);
            // Push new events to inspector buffer
            if (events && events.length > 0) {
                const knownIds = new Set(liveEventBuffer.map(e => e.event_id || e.id));
                let newCount = 0;
                for (const ev of events) {
                    const eid = ev.event_id || ev.id;
                    if (!knownIds.has(eid)) {
                        liveEventBuffer.unshift({
                            type: 'event',
                            event_id: eid,
                            timestamp: ev.timestamp,
                            event_type: ev.event_type || '',
                            user_id: ev.user_id || '',
                            source_ip: ev.source_ip || '',
                            destination_ip: ev.destination_ip || '',
                            risk_score: 0,
                            risk_level: 'LOW',
                            anomaly_score: 0,
                            temporal_score: 0,
                            attack_probability: 0,
                            attack_stage: ev.attack_stage || '',
                        });
                        newCount++;
                    }
                }
                if (newCount > 0 && !inspectorPaused) {
                    renderInspectorList();
                    updateFilterStatus();
                }
            }
        } catch(e) {}
    }, 800);
}

// ============ DASHBOARD ============

function updateDashboard(data) {
    const score = data.risk_score || 0;
    const level = (data.risk_level || 'LOW').toUpperCase();

    document.getElementById('riskScore').textContent = Math.round(score);
    document.getElementById('riskScore').className = 'risk-number' + (level !== 'LOW' ? ' ' + level.toLowerCase() : '');
    document.getElementById('riskLevel').textContent = level;

    const riskBar = document.getElementById('riskBar');
    riskBar.style.width = score + '%';
    riskBar.className = 'risk-bar' + (level !== 'LOW' ? ' ' + level.toLowerCase() : '');

    const riskCard = document.getElementById('riskCard');
    riskCard.style.borderColor = level === 'CRITICAL' ? '#cc0033' : level === 'HIGH' ? '#cc6600' : level === 'MODERATE' ? '#ccaa00' : '#2a2a2a';

    document.getElementById('attackProb').textContent = Math.round(data.attack_probability || 0) + '%';
    document.getElementById('anomalyScore').textContent = Math.round(data.anomaly_score || 0);
    document.getElementById('temporalScore').textContent = Math.round(data.temporal_score || 0);

    const c = data.components || {};
    setBar('barAnomaly', 'valAnomaly', c.anomaly_score || 0);
    setBar('barProb', 'valProb', c.attack_probability || 0);
    setBar('barTemporal', 'valTemporal', c.temporal_score || 0);
    setBar('barBehavior', 'valBehavior', c.behavioral_contribution || 0);

    const signalsEl = document.getElementById('keySignals');
    const signals = data.key_signals || [];
    if (signals.length > 0) {
        signalsEl.innerHTML = signals.map(s => {
            const cls = s.toLowerCase().includes('critical') || s.toLowerCase().includes('privilege') || s.toLowerCase().includes('reconnaissance') ? 'signal-high' :
                        s.toLowerCase().includes('elevated') || s.toLowerCase().includes('suspicious') ? 'signal-medium' : 'signal-info';
            return `<div class="signal-item ${cls}">${escHtml(s)}</div>`;
        }).join('');
    }

    if (data.stage_label) {
        document.getElementById('currentStage').textContent = data.stage_label;
        document.getElementById('stageCard').style.display = '';
        updateStageProgress(score);
    }

    if (data.explanation) {
        document.getElementById('explanationCard').style.display = '';
        document.getElementById('explanationText').textContent = data.explanation.summary || '';
        document.getElementById('recommendationText').textContent = data.explanation.recommendation || '';
    }

    if (data.risk_score !== undefined) {
        timelineData.push({
            timestamp: data.timestamp || new Date().toISOString(),
            risk_score: data.risk_score,
            risk_level: data.risk_level || 'LOW',
            stage: data.stage_label || '',
            event_type: data.event_type || '',
        });
        if (timelineData.length > 120) timelineData = timelineData.slice(-120);
        drawTimeline();
    }
}

function setBar(barId, valId, value) {
    document.getElementById(barId).style.width = Math.min(value, 100) + '%';
    document.getElementById(valId).textContent = Math.round(value) + '%';
}

function updateStageProgress(score) {
    const stages = 9;
    const container = document.getElementById('stageProgress');
    let html = '';
    for (let i = 0; i < stages; i++) {
        const threshold = (i / stages) * 100;
        let cls = '';
        if (score > threshold + 10) cls = score > 75 ? 'critical' : score > 50 ? 'danger' : score > 25 ? 'warning' : 'completed';
        else if (score > threshold) cls = 'active';
        html += `<div class="stage-step ${cls}"></div>`;
    }
    container.innerHTML = html;
}

function updateSimulationUI(running) {
    const startBtn = document.getElementById('startBtn');
    const stopBtn = document.getElementById('stopBtn');
    const dot = document.getElementById('statusDot');
    if (running) {
        startBtn.style.display = 'none';
        stopBtn.style.display = '';
        stopBtn.disabled = false;
        stopBtn.textContent = 'STOP';
        dot.className = 'status-dot simulating';
        document.getElementById('statusText').textContent = 'Simulating...';
    } else {
        startBtn.style.display = '';
        startBtn.disabled = false;
        startBtn.textContent = 'START ATTACK SIMULATION';
        stopBtn.style.display = 'none';
        dot.className = 'status-dot';
        document.getElementById('statusText').textContent = 'Connected';
    }
}

function updateEventsTable(events) {
    const tbody = document.getElementById('eventsBody');
    if (!events || events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="no-data">No events yet</td></tr>';
        return;
    }
    tbody.innerHTML = events.slice(0, 30).map(e => {
        const time = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '';
        const attack = e.is_attack ? 'event-attack' : 'event-normal';
        return `<tr>
            <td>${escHtml(time)}</td>
            <td class="${attack}">${escHtml(e.event_type || '')}</td>
            <td>${escHtml(e.user_id || '')}</td>
            <td>${escHtml(e.source_ip || '')}</td>
            <td>${escHtml(e.destination_ip || '')}</td>
            <td>${escHtml(e.attack_stage || '')}</td>
        </tr>`;
    }).join('');
}

// ============ TIMELINE (no glitch) ============

function drawTimeline() {
    const canvas = document.getElementById('timelineCanvas');
    if (!canvas || !canvasInitialized) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.width / dpr;
    const H = canvas.height / dpr;
    ctx.clearRect(0, 0, W, H);

    if (timelineData.length < 2) {
        ctx.fillStyle = '#666';
        ctx.font = '11px monospace';
        ctx.fillText('Risk timeline will appear during simulation...', W/2 - 160, H/2);
        return;
    }

    const pad = { top: 25, right: 20, bottom: 35, left: 50 };
    const plotW = W - pad.left - pad.right;
    const plotH = H - pad.top - pad.bottom;

    ctx.strokeStyle = '#1e1e1e';
    ctx.lineWidth = 1;
    for (let y = 0; y <= 100; y += 25) {
        const py = pad.top + plotH - (y / 100) * plotH;
        ctx.beginPath(); ctx.moveTo(pad.left, py); ctx.lineTo(W - pad.right, py); ctx.stroke();
        ctx.fillStyle = '#555'; ctx.font = '9px monospace';
        ctx.fillText(y.toString(), pad.left - 28, py + 3);
    }

    [{y:75,h:25,c:'rgba(204,0,51,0.06)'},{y:50,h:25,c:'rgba(204,102,0,0.04)'},{y:25,h:25,c:'rgba(204,170,0,0.03)'}].forEach(z => {
        const y1 = pad.top + plotH - ((z.y+z.h)/100)*plotH;
        const y2 = pad.top + plotH - (z.y/100)*plotH;
        ctx.fillStyle = z.c; ctx.fillRect(pad.left, y1, plotW, y2-y1);
    });

    ctx.font = '8px monospace'; ctx.fillStyle = '#444';
    ctx.fillText('CRITICAL', W-pad.right-55, pad.top+8);
    ctx.fillText('HIGH', W-pad.right-35, pad.top+plotH*0.4+8);
    ctx.fillText('MODERATE', W-pad.right-55, pad.top+plotH*0.65+8);

    ctx.beginPath(); ctx.strokeStyle = '#00d4ff'; ctx.lineWidth = 2;
    const points = [];
    timelineData.forEach((d, i) => {
        const x = pad.left + (i / (timelineData.length-1)) * plotW;
        const y = pad.top + plotH - (d.risk_score/100) * plotH;
        points.push({x, y, data: d, idx: i});
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.stroke();

    const grad = ctx.createLinearGradient(0, pad.top, 0, H-pad.bottom);
    grad.addColorStop(0, 'rgba(0,212,255,0.12)');
    grad.addColorStop(1, 'rgba(0,212,255,0)');
    ctx.lineTo(pad.left+plotW, pad.top+plotH);
    ctx.lineTo(pad.left, pad.top+plotH);
    ctx.closePath(); ctx.fillStyle = grad; ctx.fill();

    points.forEach(p => {
        ctx.beginPath();
        ctx.arc(p.x, p.y, hoveredPoint===p.idx?5:3, 0, Math.PI*2);
        ctx.fillStyle = p.data.risk_level==='CRITICAL'?'#cc0033':p.data.risk_level==='HIGH'?'#cc6600':p.data.risk_level==='MODERATE'?'#ccaa00':'#00cc66';
        ctx.fill();
        if (hoveredPoint===p.idx) { ctx.strokeStyle='#fff'; ctx.lineWidth=1; ctx.stroke(); }
    });

    if (hoveredPoint !== null && hoveredPoint < points.length) {
        const p = points[hoveredPoint];
        const tipW = 180, tipH = 60;
        let tipX = p.x+10, tipY = p.y-tipH-10;
        if (tipX+tipW > W) tipX = p.x-tipW-10;
        if (tipY < 0) tipY = p.y+15;
        ctx.fillStyle = '#1a1a1a'; ctx.strokeStyle = '#3a3a3a'; ctx.lineWidth = 1;
        ctx.beginPath(); ctx.roundRect(tipX, tipY, tipW, tipH, 4); ctx.fill(); ctx.stroke();
        ctx.fillStyle = '#c8c8c8'; ctx.font = '10px monospace';
        ctx.fillText(`Risk: ${Math.round(p.data.risk_score)} (${p.data.risk_level})`, tipX+8, tipY+16);
        ctx.fillStyle = '#888';
        ctx.fillText(`${p.data.stage||p.data.event_type||''}`, tipX+8, tipY+32);
        ctx.fillText(new Date(p.data.timestamp).toLocaleTimeString(), tipX+8, tipY+46);
    }
    canvas._timelinePoints = points;
}

function setupTimelineInteraction() {
    const canvas = document.getElementById('timelineCanvas');
    if (!canvas) return;
    canvas.addEventListener('mousemove', (e) => {
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left, my = e.clientY - rect.top;
        const points = canvas._timelinePoints || [];
        let closest = null, minDist = 20;
        points.forEach(p => {
            const d = Math.sqrt((mx-p.x)**2 + (my-p.y)**2);
            if (d < minDist) { minDist = d; closest = p.idx; }
        });
        if (closest !== hoveredPoint) {
            hoveredPoint = closest;
            canvas.style.cursor = closest !== null ? 'pointer' : 'default';
            drawTimeline();
        }
    });
    canvas.addEventListener('mouseleave', () => {
        hoveredPoint = null;
        canvas.style.cursor = 'default';
        drawTimeline();
    });
}

// ============ SIMULATION ============

async function startSimulation() {
    const btn = document.getElementById('startBtn');
    btn.disabled = true; btn.textContent = 'STARTING...';
    timelineData = [];
    liveEventBuffer = [];
    const scenario = document.getElementById('scenarioSelect').value;
    const speed = parseFloat(document.getElementById('speedSlider').value);
    try {
        await fetch(`${API}/api/simulation/start`, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({scenario, speed}),
        });
        document.getElementById('stageCard').style.display = '';
        addDiagnostic(`Simulation started: ${scenario} (speed ${speed}x)`);
    } catch(e) {
        btn.disabled = false; btn.textContent = 'START ATTACK SIMULATION';
        addDiagnostic('Failed to start: ' + e.message);
    }
}

async function stopSimulation() {
    const btn = document.getElementById('stopBtn');
    btn.disabled = true; btn.textContent = 'STOPPING...';
    try {
        await fetch(`${API}/api/simulation/stop`, {method: 'POST'});
        isSimulating = false;
        updateSimulationUI(false);
        addDiagnostic('Simulation stopped.');
    } catch(e) { btn.disabled = false; btn.textContent = 'STOP'; }
}

// ============ INSPECTOR ============

function renderInspectorList() {
    const container = document.getElementById('inspectorList');
    const countEl = document.getElementById('inspectorCount');
    let events = inspectorFilterText ? filterInspectorEvents(liveEventBuffer, inspectorFilterText) : liveEventBuffer;
    countEl.textContent = `${events.length} of ${liveEventBuffer.length} events`;
    if (events.length === 0) {
        container.innerHTML = '<div class="no-data">Waiting for events...</div>';
        return;
    }
    container.innerHTML = events.slice(0, 200).map((ev, i) => {
        const time = ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : '';
        const risk = Math.round(ev.risk_score || 0);
        const level = (ev.risk_level || 'LOW').toLowerCase();
        const sel = inspectorSelectedIdx === i ? ' selected' : '';
        return `<div class="inspector-event${sel}" onclick="selectInspectorEvent(${i})" data-idx="${i}">
            <span class="ev-time">${escHtml(time)}</span>
            <span class="ev-type">${escHtml(ev.event_type || '')}</span>
            <span class="ev-user">${escHtml(ev.user_id || '')}</span>
            <span class="ev-src">${escHtml(ev.source_ip || '')}</span>
            <span class="ev-dest">${escHtml(ev.destination_ip || '')}</span>
            <span class="ev-detail">${escHtml(ev.attack_stage || ev.stage_label || '')}</span>
            <span class="ev-risk risk-${level}">${risk}</span>
        </div>`;
    }).join('');
}

function filterInspectorEvents(events, query) {
    if (!query) return events;
    const parts = query.toLowerCase().split(/\s+and\s+/);
    return events.filter(ev => {
        return parts.every(part => {
            part = part.trim();
            const neg = part.startsWith('not ');
            if (neg) part = part.slice(4).trim();
            let match = false;
            for (const op of ['>=','<=','!=','>','<','=',':']) {
                if (part.includes(op)) {
                    const [field, val] = part.split(op, 2);
                    const f = field.trim(), v = val.trim();
                    let evVal = ev[f] ?? ev[f.replace('user','user_id').replace('type','event_type').replace('src','source_ip').replace('dest','destination_ip')];
                    if (evVal === undefined) evVal = '';
                    evVal = String(evVal).toLowerCase();
                    if (op === ':' || op === '=') match = evVal === v || evVal.includes(v);
                    else if (op === '!=') match = evVal !== v;
                    else if (op === '>') match = parseFloat(evVal) > parseFloat(v);
                    else if (op === '<') match = parseFloat(evVal) < parseFloat(v);
                    else if (op === '>=') match = parseFloat(evVal) >= parseFloat(v);
                    else if (op === '<=') match = parseFloat(evVal) <= parseFloat(v);
                    break;
                }
            }
            return neg ? !match : match;
        });
    });
}

function selectInspectorEvent(idx) {
    inspectorSelectedIdx = idx;
    let events = inspectorFilterText ? filterInspectorEvents(liveEventBuffer, inspectorFilterText) : liveEventBuffer;
    const ev = events[idx];
    if (!ev) return;

    const detailEl = document.getElementById('inspectorDetail');
    const fields = [
        ['timestamp', ev.timestamp], ['event_type', ev.event_type], ['user_id', ev.user_id],
        ['source_ip', ev.source_ip], ['destination_ip', ev.destination_ip],
        ['event_id', ev.event_id], ['risk_score', ev.risk_score],
        ['risk_level', ev.risk_level], ['attack_stage', ev.attack_stage],
        ['anomaly_score', ev.anomaly_score], ['temporal_score', ev.temporal_score],
        ['attack_probability', ev.attack_probability],
    ];
    detailEl.innerHTML = fields.map(([k, v]) =>
        `<div class="detail-row"><span class="detail-key">${k}</span><span class="detail-val${k==='attack_stage'?' attack':''}">${escHtml(v !== undefined && v !== null ? v : '-')}</span></div>`
    ).join('');

    const traceEl = document.getElementById('inspectorTrace');
    const stages = [
        {name: 'INGESTED', detail: 'Raw event stored to database'},
        {name: 'FEATURES', detail: '48 features computed (5m/15m/1h windows)'},
        {name: 'ANOMALY', detail: `Score: ${ev.anomaly_score || 0}`},
        {name: 'TEMPORAL', detail: `Score: ${ev.temporal_score || 0}`},
        {name: 'RISK', detail: `${ev.risk_score || 0} (${ev.risk_level || 'LOW'})`},
        {name: 'EXPLAINED', detail: 'Human-readable summary generated'},
        {name: 'STORED', detail: 'Predictions + risk history saved'},
    ];
    traceEl.innerHTML = stages.map((s, i) =>
        `<div class="trace-step active"><div class="trace-num">${i+1}</div><div class="trace-info"><div class="trace-stage">${s.name}</div><div class="trace-detail">${s.detail}</div></div></div>`
    ).join('');

    renderInspectorList();
}

function applyInspectorFilter() {
    inspectorFilterText = document.getElementById('inspectorFilter').value;
    inspectorSelectedIdx = null;
    renderInspectorList();
    updateFilterStatus();
}

function clearInspectorFilter() {
    inspectorFilterText = '';
    document.getElementById('inspectorFilter').value = '';
    inspectorSelectedIdx = null;
    renderInspectorList();
    updateFilterStatus();
}

function updateFilterStatus() {
    const el = document.getElementById('filterStatus');
    if (!el) return;
    const total = liveEventBuffer.length;
    const filtered = inspectorFilterText ? filterInspectorEvents(liveEventBuffer, inspectorFilterText).length : total;
    el.textContent = inspectorFilterText ? `${filtered}/${total} events` : `${total} events`;
}

document.getElementById('inspectorPause')?.addEventListener('change', (e) => {
    inspectorPaused = e.target.checked;
});

async function exportInspectorCSV() {
    let events = inspectorFilterText ? filterInspectorEvents(liveEventBuffer, inspectorFilterText) : liveEventBuffer;
    if (events.length === 0) { addDiagnostic('No events to export'); return; }
    const headers = ['timestamp','event_type','user_id','source_ip','destination_ip','risk_score','risk_level','anomaly_score','temporal_score','attack_stage'];
    const csv = [headers.join(','), ...events.map(e => headers.map(h => e[h] || '').join(','))].join('\n');
    downloadFile(csv, 'prevail_events.csv', 'text/csv');
    addDiagnostic(`Exported ${events.length} events as CSV`);
}

async function exportInspectorJSON() {
    let events = inspectorFilterText ? filterInspectorEvents(liveEventBuffer, inspectorFilterText) : liveEventBuffer;
    if (events.length === 0) { addDiagnostic('No events to export'); return; }
    downloadFile(JSON.stringify(events, null, 2), 'prevail_events.json', 'application/json');
    addDiagnostic(`Exported ${events.length} events as JSON`);
}

function downloadFile(content, filename, type) {
    const blob = new Blob([content], {type});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
}

// ============ ADMIN ============

async function loadAdminData() {
    try {
        const [statusRes, modelsRes] = await Promise.all([
            fetch(`${API}/api/admin/system-info`),
            fetch(`${API}/api/models`),
        ]);
        const status = await statusRes.json();
        const models = await modelsRes.json();

        const sysEl = document.getElementById('sysInfo');
        if (sysEl) {
            sysEl.innerHTML = `
                <div class="sysrow"><span>App</span><span class="sysval">${status.app_name} v${status.version}</span></div>
                <div class="sysrow"><span>Models Loaded</span><span class="sysval ${status.models_loaded?'ok':'err'}">${status.models_loaded?'YES':'NO'}</span></div>
                <div class="sysrow"><span>Model Features</span><span class="sysval">${status.model_features}</span></div>
                <div class="sysrow"><span>Simulation</span><span class="sysval ${status.simulation_running?'warn':'ok'}">${status.simulation_running?'RUNNING':'IDLE'}</span></div>
                <div class="sysrow"><span>Current Scenario</span><span class="sysval">${status.current_scenario||'None'}</span></div>
                <div class="sysrow"><span>Events in Memory</span><span class="sysval">${status.events_in_memory}</span></div>`;
        }

        const dbEl = document.getElementById('dbInfo');
        if (dbEl && status.database) {
            const db = status.database;
            dbEl.innerHTML = `
                <div class="sysrow"><span>Path</span><span class="sysval" style="font-size:9px">${db.path.split('/').pop()}</span></div>
                <div class="sysrow"><span>Size</span><span class="sysval">${db.size_mb} MB</span></div>
                <div class="sysrow"><span>Events</span><span class="sysval">${db.tables.events}</span></div>
                <div class="sysrow"><span>Predictions</span><span class="sysval">${db.tables.predictions}</span></div>
                <div class="sysrow"><span>Risk History</span><span class="sysval">${db.tables.risk_history}</span></div>
                <div class="sysrow"><span>Sim Runs</span><span class="sysval">${db.tables.simulation_runs}</span></div>
                <div class="sysrow"><span>Models</span><span class="sysval">${db.tables.model_metadata}</span></div>`;
        }

        const modelEl = document.getElementById('modelList');
        if (modelEl) {
            const meta = models.models || [];
            if (meta.length > 0) {
                modelEl.innerHTML = meta.map(m => {
                    const metrics = typeof m.metrics_json === 'string' ? JSON.parse(m.metrics_json) : (m.metrics_json || {});
                    const metricStr = Object.entries(metrics).filter(([k])=>!k.startsWith('n_')).map(([k,v])=>`${k}:${typeof v==='number'?v.toFixed(4):v}`).join(' | ');
                    return `<div class="model-item"><div class="model-name">${escHtml(m.model_name)}</div><div class="model-type">${escHtml(m.model_type)} -- ${metricStr}</div><div class="model-date">${escHtml((m.trained_at||'').replace('T',' ').slice(0,19))}</div></div>`;
                }).join('');
            } else {
                modelEl.innerHTML = '<div class="model-item"><div class="model-name" style="color:#666">No models trained</div></div>';
            }
        }

        const statsRes = await fetch(`${API}/api/inspector/stats`);
        const stats = await statsRes.json();
        renderStats(stats);
    } catch(e) { addDiagnostic('Failed to load admin data: ' + e.message); }
}

function renderStats(stats) {
    const typesEl = document.getElementById('statsEventTypes');
    if (typesEl && stats.event_types) {
        const max = Math.max(...stats.event_types.map(e=>e.count), 1);
        typesEl.innerHTML = stats.event_types.slice(0,8).map(e =>
            `<div class="stat-bar-row"><span class="stat-label" style="min-width:90px;font-size:10px">${e.type}</span><div class="stat-bar-bg"><div class="stat-bar-fill" style="width:${(e.count/max)*100}%"></div></div><span class="stat-val" style="font-size:10px;min-width:30px;text-align:right">${e.count}</span></div>`
        ).join('');
    }
    const ipsEl = document.getElementById('statsTopIPs');
    if (ipsEl && stats.top_source_ips) {
        ipsEl.innerHTML = stats.top_source_ips.map(e =>
            `<div class="stat-row"><span class="stat-label">${e.ip}</span><span class="stat-val">${e.count}</span></div>`
        ).join('');
    }
    const riskEl = document.getElementById('statsRiskDist');
    if (riskEl && stats.risk_distribution) {
        const colors = {LOW:'var(--green)',MODERATE:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)'};
        const total = Object.values(stats.risk_distribution).reduce((a,b)=>a+b,0) || 1;
        riskEl.innerHTML = Object.entries(stats.risk_distribution).map(([k,v]) =>
            `<div class="stat-bar-row"><span class="stat-label" style="min-width:70px;font-size:10px;color:${colors[k]}">${k}</span><div class="stat-bar-bg"><div class="stat-bar-fill" style="width:${(v/total)*100}%;background:${colors[k]}"></div></div><span class="stat-val" style="font-size:10px">${v}</span></div>`
        ).join('');
    }
}

async function trainModels() {
    const btn = document.getElementById('trainBtn');
    btn.disabled = true; btn.textContent = 'TRAINING...';
    addDiagnostic('Training models (Isolation Forest + Random Forest + XGBoost + Logistic Regression)...');
    try {
        await fetch(`${API}/api/models/train`, {method:'POST'});
        let attempts = 0;
        const check = setInterval(async () => {
            attempts++;
            try {
                const res = await fetch(`${API}/api/models`);
                const data = await res.json();
                if (data.models && data.models.length >= 2) {
                    clearInterval(check);
                    addDiagnostic(`Training complete. ${data.models.length} models.`);
                    loadAdminData();
                    btn.disabled = false; btn.textContent = 'RETRAIN ALL MODELS';
                } else if (attempts > 20) {
                    clearInterval(check);
                    addDiagnostic('Training timed out.');
                    btn.disabled = false; btn.textContent = 'RETRAIN ALL MODELS';
                }
            } catch(e) {}
        }, 1500);
    } catch(e) {
        btn.disabled = false; btn.textContent = 'RETRAIN ALL MODELS';
        addDiagnostic('Training failed: ' + e.message);
    }
}

async function injectCustomEvent() {
    const eventType = document.getElementById('adminEventType').value;
    const user = document.getElementById('adminUser').value || 'admin_user';
    const srcIp = document.getElementById('adminSrcIp').value || '10.0.2.99';
    const destIp = document.getElementById('adminDestIp').value || '10.0.1.10';
    const severity = document.getElementById('adminSeverity').value;
    addDiagnostic(`Injecting: ${eventType} | user=${user} | ${srcIp}->${destIp} | severity=${severity}`);
    try {
        const res = await fetch(`${API}/api/admin/inject-event`, {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({event_type:eventType, user_id:user, source_ip:srcIp, destination_ip:destIp, severity}),
        });
        const data = await res.json();
        addDiagnostic(`Injected. Risk: ${data.risk_score} (${data.risk_level})`);
        // Force refresh inspector
        refreshInspector();
    } catch(e) { addDiagnostic('Injection failed: ' + e.message); }
}

async function injectAttackChain() {
    const chainType = document.getElementById('adminChainType').value;
    addDiagnostic(`Starting attack chain: ${chainType}`);
    try {
        const res = await fetch(`${API}/api/admin/inject-attack-chain`, {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({chain_type: chainType}),
        });
        const data = await res.json();
        addDiagnostic(`Chain started. ${data.events_count} events firing.`);
        // Refresh inspector periodically while chain runs
        let refreshes = 0;
        const interval = setInterval(() => {
            refreshInspector();
            refreshes++;
            if (refreshes >= 10) clearInterval(interval);
        }, 1500);
    } catch(e) { addDiagnostic('Chain failed: ' + e.message); }
}

async function refreshInspector() {
    try {
        const res = await fetch(`${API}/api/events?limit=100`);
        const events = await res.json();
        if (events && events.length > 0) {
            const knownIds = new Set(liveEventBuffer.map(e => e.event_id || e.id));
            for (const ev of events) {
                const eid = ev.event_id || ev.id;
                if (!knownIds.has(eid)) {
                    liveEventBuffer.unshift({
                        type: 'event',
                        event_id: eid,
                        timestamp: ev.timestamp,
                        event_type: ev.event_type || '',
                        user_id: ev.user_id || '',
                        source_ip: ev.source_ip || '',
                        destination_ip: ev.destination_ip || '',
                        risk_score: 0,
                        risk_level: 'LOW',
                        anomaly_score: 0,
                        temporal_score: 0,
                        attack_probability: 0,
                        attack_stage: ev.attack_stage || '',
                    });
                }
            }
            if (!inspectorPaused) {
                renderInspectorList();
                updateFilterStatus();
            }
        }
    } catch(e) {}
}

async function resetAll() {
    if (!confirm('Delete ALL data, models, and history?')) return;
    addDiagnostic('Resetting all data...');
    try {
        await fetch(`${API}/api/admin/reset`, {method:'POST'});
        addDiagnostic('All data cleared.');
        timelineData = []; liveEventBuffer = [];
        loadAdminData();
        document.getElementById('riskScore').textContent = '8';
        document.getElementById('riskScore').className = 'risk-number';
        document.getElementById('riskLevel').textContent = 'LOW';
        document.getElementById('riskBar').style.width = '8%';
    } catch(e) { addDiagnostic('Reset failed: ' + e.message); }
}

async function resetTable(table) {
    if (!confirm(`Delete all ${table} data?`)) return;
    addDiagnostic(`Resetting: ${table}...`);
    try {
        await fetch(`${API}/api/admin/reset/${table}`, {method:'POST'});
        addDiagnostic(`Table ${table} cleared.`);
        loadAdminData();
    } catch(e) { addDiagnostic('Reset failed: ' + e.message); }
}

function addDiagnostic(msg) {
    const el = document.getElementById('diagnosticLog');
    if (!el) return;
    const time = new Date().toLocaleTimeString();
    const line = document.createElement('div');
    line.className = 'diag-line';
    line.innerHTML = `<span class="diag-time">[${time}]</span> ${escHtml(msg)}`;
    el.insertBefore(line, el.firstChild);
    if (el.children.length > 100) el.removeChild(el.lastChild);
}

function clearDiagnostics() {
    const el = document.getElementById('diagnosticLog');
    if (el) el.innerHTML = '<div class="diag-line"><span class="diag-time">[system]</span> Log cleared.</div>';
}

function showTab(tab) {
    document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    document.getElementById('tab' + tab).style.display = '';
    document.querySelector(`[data-tab="${tab}"]`).classList.add('active');
    if (tab === 'admin') loadAdminData();
    if (tab === 'inspector') { renderInspectorList(); updateFilterStatus(); }
}

function escHtml(s) {
    if (!s) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

document.addEventListener('DOMContentLoaded', init);
