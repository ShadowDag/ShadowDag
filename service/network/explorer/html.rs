// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Advanced Explorer HTML — full-featured SPA with:
//   - Dashboard with live stats
//   - Block list with pagination
//   - Block & transaction detail views
//   - DAG visualization (canvas-based)
//   - Mempool viewer
//   - Rich list
//   - Network info
//   - Universal search
// ═══════════════════════════════════════════════════════════════════════════

pub const EXPLORER_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ShadowDAG Explorer</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0e14;--bg2:#0d1117;--card:#161b22;--card2:#1c2128;--border:#30363d;--border2:#21262d;--text:#c9d1d9;--text2:#e6edf3;--dim:#8b949e;--dim2:#6e7681;--accent:#58a6ff;--accent2:#1f6feb;--green:#3fb950;--green2:#238636;--red:#f85149;--orange:#d29922;--purple:#bc8cff;--cyan:#39d2e0;--pink:#f778ba;--radius:8px;--shadow:0 2px 8px rgba(0,0,0,.3)}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;min-height:100vh}
a{color:var(--accent);text-decoration:none;transition:color .15s}
a:hover{color:var(--cyan);text-decoration:none}
.container{max-width:1400px;margin:0 auto;padding:0 20px}

/* ── Header ─────────────────────────────────── */
header{background:var(--card);border-bottom:1px solid var(--border);padding:12px 0;position:sticky;top:0;z-index:100;backdrop-filter:blur(12px);background:rgba(22,27,34,.9)}
header .container{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.logo{font-size:22px;font-weight:800;color:#fff;display:flex;align-items:center;gap:8px;flex-shrink:0}
.logo span{background:linear-gradient(135deg,var(--accent),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo .dot{width:10px;height:10px;border-radius:50%;background:var(--green);animation:pulse 2s infinite;flex-shrink:0}
.search-box{flex:1;max-width:540px;position:relative}
.search-box input{width:100%;padding:9px 16px 9px 38px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:14px;outline:none;transition:border-color .2s}
.search-box input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(88,166,255,.15)}
.search-box svg{position:absolute;left:12px;top:50%;transform:translateY(-50%);fill:var(--dim);width:16px;height:16px}
nav{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}
nav button{background:none;border:none;color:var(--dim);padding:8px 14px;font-size:13px;font-weight:500;cursor:pointer;border-radius:6px;transition:all .15s}
nav button:hover{color:var(--text);background:var(--bg2)}
nav button.active{color:var(--accent);background:rgba(88,166,255,.12)}

/* ── Stats ──────────────────────────────────── */
.stats-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:20px 0}
.stat{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px;transition:border-color .2s}
.stat:hover{border-color:var(--accent)}
.stat .lbl{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.8px;font-weight:600}
.stat .val{font-size:26px;font-weight:700;color:#fff;margin:4px 0 2px}
.stat .sub{font-size:12px;color:var(--dim2)}
.stat .val.green{color:var(--green)}
.stat .val.cyan{color:var(--cyan)}
.stat .val.orange{color:var(--orange)}
.stat .val.purple{color:var(--purple)}

/* ── Panels / Views ─────────────────────────── */
.panel{display:none;margin:20px 0}
.panel.active{display:block}
.section{margin:24px 0}
.section-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.section-head h2{font-size:16px;color:#fff;display:flex;align-items:center;gap:8px;font-weight:600}
.badge{background:var(--accent2);color:#fff;font-size:11px;padding:2px 10px;border-radius:12px;font-weight:600}
.badge.green{background:var(--green2)}
.badge.orange{background:rgba(210,153,34,.3);color:var(--orange)}

/* ── Tables ─────────────────────────────────── */
.tbl-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:var(--radius);background:var(--card)}
table{width:100%;border-collapse:collapse}
th{background:var(--card2);text-align:left;padding:10px 14px;font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:10px 14px;font-size:13px;border-bottom:1px solid var(--border2)}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(88,166,255,.03)}
.mono{font-family:'SF Mono',SFMono-Regular,Consolas,'Liberation Mono',Menlo,monospace;font-size:12px}
.trunc{max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:middle}
.trunc-lg{max-width:240px}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.tag-tx{background:rgba(88,166,255,.12);color:var(--accent)}
.tag-cb{background:rgba(63,185,80,.12);color:var(--green)}
.tag-pending{background:rgba(210,153,34,.12);color:var(--orange)}

/* ── Detail View ────────────────────────────── */
.detail-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:24px;margin:16px 0}
.detail-card h2{color:#fff;margin-bottom:16px;font-size:18px;display:flex;align-items:center;gap:10px}
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px 32px}
.d-row{display:flex;gap:10px;padding:6px 0;border-bottom:1px solid var(--border2)}
.d-row:last-child{border-bottom:none}
.d-key{color:var(--dim);min-width:130px;font-size:13px;flex-shrink:0;font-weight:500}
.d-val{font-size:13px;word-break:break-all;color:var(--text2)}
.back-link{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;background:var(--card2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;font-weight:500;cursor:pointer;transition:all .15s;margin-bottom:14px}
.back-link:hover{border-color:var(--accent);color:var(--accent)}

/* ── DAG Canvas ─────────────────────────────── */
.dag-container{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px;overflow:hidden;position:relative}
.dag-container canvas{display:block;width:100%;border-radius:6px;cursor:grab}
.dag-legend{display:flex;gap:16px;margin-top:12px;flex-wrap:wrap}
.dag-legend span{font-size:12px;color:var(--dim);display:flex;align-items:center;gap:6px}
.dag-legend .dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}

/* ── Pool Section ───────────────────────────── */
.pool-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin:16px 0}
.pool-card h3{color:#fff;margin-bottom:12px;font-size:15px}
.pool-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px}
.pool-item .label{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
.pool-item .val{font-size:22px;font-weight:700;color:var(--green);margin-top:2px}

/* ── Footer ─────────────────────────────────── */
footer{text-align:center;padding:28px 20px;color:var(--dim2);font-size:12px;border-top:1px solid var(--border);margin-top:48px}
footer a{color:var(--dim)}

/* ── Responsive ─────────────────────────────── */
@media(max-width:768px){
  .stats-row{grid-template-columns:1fr 1fr}
  .detail-grid{grid-template-columns:1fr}
  .search-box{max-width:100%;order:3;flex-basis:100%}
  nav{order:2}
  .trunc{max-width:100px}
}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.panel.active{animation:fadeIn .25s ease}
</style>
</head>
<body>

<header>
<div class="container">
  <div class="logo"><div class="dot"></div><span>Shadow</span>DAG<span style="font-weight:400;font-size:14px;color:var(--dim);margin-left:4px">Explorer</span></div>
  <div class="search-box">
    <svg viewBox="0 0 16 16"><path d="M11.5 7a4.5 4.5 0 11-9 0 4.5 4.5 0 019 0zm-.82 4.74a6 6 0 111.06-1.06l3.04 3.04a.75.75 0 11-1.06 1.06l-3.04-3.04z"/></svg>
    <input id="searchInput" placeholder="Search block hash, height, tx hash, or address..." onkeydown="if(event.key==='Enter')doSearch()">
  </div>
  <nav>
    <button class="active" onclick="showPanel('dashboard')">Dashboard</button>
    <button onclick="showPanel('blocks')">Blocks</button>
    <button onclick="showPanel('mempool')">Mempool</button>
    <button onclick="showPanel('dag')">DAG</button>
    <button onclick="showPanel('richlist')">Rich List</button>
    <button onclick="showPanel('network')">Network</button>
  </nav>
</div>
</header>

<div class="container">

<!-- ═══ Dashboard ═══ -->
<div id="p-dashboard" class="panel active">
  <div class="stats-row" id="statsGrid"></div>
  <div id="poolSection"></div>
  <div class="section">
    <div class="section-head">
      <h2><svg width="16" height="16" viewBox="0 0 16 16" fill="var(--accent)" style="flex-shrink:0"><path d="M1 2.75A.75.75 0 011.75 2h12.5a.75.75 0 010 1.5H1.75A.75.75 0 011 2.75zm0 5A.75.75 0 011.75 7h12.5a.75.75 0 010 1.5H1.75A.75.75 0 011 7.75zM1.75 12a.75.75 0 000 1.5h12.5a.75.75 0 000-1.5H1.75z"/></svg> Latest Blocks <span class="badge" id="blockCount">0</span></h2>
    </div>
    <div class="tbl-wrap">
      <table><thead><tr><th>Height</th><th>Hash</th><th>Age</th><th>TXs</th><th>Difficulty</th><th>Parents</th></tr></thead>
      <tbody id="blocksBody"></tbody></table>
    </div>
  </div>
</div>

<!-- ═══ All Blocks ═══ -->
<div id="p-blocks" class="panel">
  <div class="section">
    <div class="section-head">
      <h2>All Blocks <span class="badge" id="allBlockCount">0</span></h2>
    </div>
    <div class="tbl-wrap">
      <table><thead><tr><th>Height</th><th>Hash</th><th>Age</th><th>TXs</th><th>Difficulty</th><th>Parents</th></tr></thead>
      <tbody id="allBlocksBody"></tbody></table>
    </div>
  </div>
</div>

<!-- ═══ Mempool ═══ -->
<div id="p-mempool" class="panel">
  <div class="stats-row" id="mempoolStats"></div>
  <div class="section">
    <div class="section-head">
      <h2>Pending Transactions <span class="badge orange" id="mempoolCount">0</span></h2>
    </div>
    <div class="tbl-wrap">
      <table><thead><tr><th>Hash</th><th>Type</th><th>Outputs</th><th>Total Value</th><th>Fee</th><th>Age</th></tr></thead>
      <tbody id="mempoolBody"></tbody></table>
    </div>
  </div>
</div>

<!-- ═══ DAG ═══ -->
<div id="p-dag" class="panel">
  <div class="section">
    <div class="section-head">
      <h2><svg width="16" height="16" viewBox="0 0 16 16" fill="var(--purple)" style="flex-shrink:0"><path d="M8 0a8 8 0 100 16A8 8 0 008 0zM1.5 8a6.5 6.5 0 1113 0 6.5 6.5 0 01-13 0z"/></svg> DAG Visualization</h2>
    </div>
    <div class="dag-container">
      <canvas id="dagCanvas" height="500"></canvas>
      <div class="dag-legend">
        <span><div class="dot" style="background:var(--accent)"></div> Block</span>
        <span><div class="dot" style="background:var(--green)"></div> Tip</span>
        <span><div class="dot" style="background:var(--dim)"></div> Parent Link</span>
      </div>
    </div>
  </div>
</div>

<!-- ═══ Rich List ═══ -->
<div id="p-richlist" class="panel">
  <div class="section">
    <div class="section-head">
      <h2>Rich List — Top Addresses <span class="badge green" id="totalAddrs">0</span></h2>
    </div>
    <div class="tbl-wrap">
      <table><thead><tr><th>#</th><th>Address</th><th>Balance (SDAG)</th><th>Balance (sat)</th></tr></thead>
      <tbody id="richlistBody"></tbody></table>
    </div>
  </div>
</div>

<!-- ═══ Network ═══ -->
<div id="p-network" class="panel">
  <div class="stats-row" id="networkStats"></div>
  <div class="pool-card" id="netPoolCard" style="display:none"></div>
</div>

<!-- ═══ Block Detail ═══ -->
<div id="p-blockDetail" class="panel">
  <a class="back-link" href="#" onclick="goBack();return false"><svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path fill-rule="evenodd" d="M7.78 12.53a.75.75 0 01-1.06 0L2.47 8.28a.75.75 0 010-1.06l4.25-4.25a.75.75 0 011.06 1.06L4.81 7h7.44a.75.75 0 010 1.5H4.81l2.97 2.97a.75.75 0 010 1.06z"/></svg> Back</a>
  <div id="blockDetailContent"></div>
</div>

<!-- ═══ TX Detail ═══ -->
<div id="p-txDetail" class="panel">
  <a class="back-link" href="#" onclick="goBack();return false"><svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path fill-rule="evenodd" d="M7.78 12.53a.75.75 0 01-1.06 0L2.47 8.28a.75.75 0 010-1.06l4.25-4.25a.75.75 0 011.06 1.06L4.81 7h7.44a.75.75 0 010 1.5H4.81l2.97 2.97a.75.75 0 010 1.06z"/></svg> Back</a>
  <div id="txDetailContent"></div>
</div>

<!-- ═══ Address Detail ═══ -->
<div id="p-addressDetail" class="panel">
  <a class="back-link" href="#" onclick="goBack();return false"><svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path fill-rule="evenodd" d="M7.78 12.53a.75.75 0 01-1.06 0L2.47 8.28a.75.75 0 010-1.06l4.25-4.25a.75.75 0 011.06 1.06L4.81 7h7.44a.75.75 0 010 1.5H4.81l2.97 2.97a.75.75 0 010 1.06z"/></svg> Back</a>
  <div id="addressDetailContent"></div>
</div>

</div>

<footer>ShadowDAG Explorer &mdash; Powered by ShadowDAG Node &bull; Real-time blockchain data</footer>

<script>
const API='';
let refreshTimer,currentPanel='dashboard',prevPanel='dashboard';

async function fetchJson(url){
  try{const r=await fetch(API+url);if(!r.ok)return{error:r.status};return await r.json()}
  catch(e){return{error:e.message}}
}

function fmt(n){return n==null?'-':Number(n).toLocaleString()}
function fmtSdag(sats){return sats==null?'-':(sats/1e8).toFixed(8)}
function truncH(h,n){if(!h)return'-';n=n||10;return h.length>n*2?h.slice(0,n)+'\u2026'+h.slice(-n):h}
function age(ts){
  if(!ts)return'-';
  const d=Math.floor(Date.now()/1000-ts);
  if(d<0)return'just now';
  if(d<60)return d+'s ago';
  if(d<3600)return Math.floor(d/60)+'m ago';
  if(d<86400)return Math.floor(d/3600)+'h ago';
  return Math.floor(d/86400)+'d ago';
}

/* ── Navigation ─────────────────────────────── */
function showPanel(id){
  prevPanel=currentPanel;
  currentPanel=id;
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.getElementById('p-'+id).classList.add('active');
  document.querySelectorAll('nav button').forEach(b=>b.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b=>{if(b.textContent.toLowerCase().replace(/\s/g,'')===id)b.classList.add('active')});

  if(id==='mempool')loadMempool();
  if(id==='dag')loadDag();
  if(id==='richlist')loadRichlist();
  if(id==='network')loadNetwork();
  if(id==='blocks')loadAllBlocks();
}
function goBack(){showPanel(prevPanel==='blockDetail'||prevPanel==='txDetail'||prevPanel==='addressDetail'?'dashboard':prevPanel)}

/* ── Dashboard ──────────────────────────────── */
async function loadStats(){
  const s=await fetchJson('/api/stats');
  if(s.error)return;
  document.getElementById('statsGrid').innerHTML=`
    <div class="stat"><div class="lbl">Block Height</div><div class="val">${fmt(s.best_height)}</div><div class="sub">${fmt(s.block_count)} total blocks</div></div>
    <div class="stat"><div class="lbl">Network</div><div class="val cyan" style="font-size:18px">${s.network||'-'}</div><div class="sub">${s.version||''}</div></div>
    <div class="stat"><div class="lbl">Connected Peers</div><div class="val green">${fmt(s.peer_count)}</div><div class="sub">P2P :${s.p2p_port} &bull; RPC :${s.rpc_port}</div></div>
    <div class="stat"><div class="lbl">Mempool</div><div class="val orange">${fmt(s.mempool_size)}</div><div class="sub">pending transactions</div></div>
    <div class="stat"><div class="lbl">Algorithm</div><div class="val" style="font-size:12px;color:var(--purple)">${s.algorithm||'-'}</div><div class="sub">Proof of Work</div></div>
    <div class="stat"><div class="lbl">Max Supply</div><div class="val" style="font-size:18px">${fmt(s.max_supply?s.max_supply/1e8:0)}</div><div class="sub">SDAG</div></div>
    <div class="stat"><div class="lbl">Chain</div><div class="val" style="font-size:14px;color:var(--cyan)">${s.chain_name||'-'}</div><div class="sub">ID: ${s.chain_id||'-'}</div></div>
  `;
}

async function loadBlocks(){
  const d=await fetchJson('/api/blocks');
  if(d.error||!d.blocks)return;
  document.getElementById('blockCount').textContent=d.best_height||0;
  document.getElementById('blocksBody').innerHTML=d.blocks.slice(0,20).map(b=>`
    <tr>
      <td><strong style="color:#fff">${b.height}</strong></td>
      <td class="mono"><a href="#" onclick="showBlock('${b.hash}');return false" class="trunc">${truncH(b.hash,10)}</a></td>
      <td style="color:var(--dim)">${age(b.timestamp)}</td>
      <td><span class="tag tag-tx">${b.tx_count}</span></td>
      <td>${fmt(b.difficulty)}</td>
      <td>${b.parents}</td>
    </tr>
  `).join('');
}

async function loadAllBlocks(){
  const d=await fetchJson('/api/blocks');
  if(d.error||!d.blocks)return;
  document.getElementById('allBlockCount').textContent=d.best_height||0;
  document.getElementById('allBlocksBody').innerHTML=d.blocks.map(b=>`
    <tr>
      <td><strong style="color:#fff">${b.height}</strong></td>
      <td class="mono"><a href="#" onclick="showBlock('${b.hash}');return false" class="trunc">${truncH(b.hash,10)}</a></td>
      <td style="color:var(--dim)">${age(b.timestamp)}</td>
      <td><span class="tag tag-tx">${b.tx_count}</span></td>
      <td>${fmt(b.difficulty)}</td>
      <td>${b.parents}</td>
    </tr>
  `).join('');
}

async function loadPool(){
  const p=await fetchJson('/api/pool');
  const el=document.getElementById('poolSection');
  if(p.status==='active'){
    el.innerHTML=`<div class="pool-card"><h3>Mining Pool (Stratum)</h3><div class="pool-grid">
      <div class="pool-item"><div class="label">Status</div><div class="val">${p.status}</div></div>
      <div class="pool-item"><div class="label">Workers</div><div class="val">${p.workers}</div></div>
      <div class="pool-item"><div class="label">Blocks Found</div><div class="val">${p.blocks_found}</div></div>
      <div class="pool-item"><div class="label">Pool Fee</div><div class="val">${p.pool_fee_pct}%</div></div>
    </div></div>`;
  }else{el.innerHTML=''}
}

/* ── Block Detail ───────────────────────────── */
async function showBlock(id){
  const b=await fetchJson('/api/block/'+encodeURIComponent(id));
  if(b.error){alert('Block not found');return}
  prevPanel=currentPanel;
  currentPanel='blockDetail';
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.getElementById('p-blockDetail').classList.add('active');
  document.querySelectorAll('nav button').forEach(btn=>btn.classList.remove('active'));

  document.getElementById('blockDetailContent').innerHTML=`
    <div class="detail-card">
      <h2><svg width="18" height="18" viewBox="0 0 16 16" fill="var(--accent)"><path d="M1 2.75A.75.75 0 011.75 2h12.5a.75.75 0 01.75.75v10.5a.75.75 0 01-.75.75H1.75a.75.75 0 01-.75-.75V2.75z"/></svg> Block #${fmt(b.height)}</h2>
      <div class="detail-grid">
        <div class="d-row"><span class="d-key">Hash</span><span class="d-val mono">${b.hash}</span></div>
        <div class="d-row"><span class="d-key">Height</span><span class="d-val">${fmt(b.height)}</span></div>
        <div class="d-row"><span class="d-key">Timestamp</span><span class="d-val">${b.timestamp?new Date(b.timestamp*1000).toLocaleString():'-'} (${age(b.timestamp)})</span></div>
        <div class="d-row"><span class="d-key">Difficulty</span><span class="d-val">${fmt(b.difficulty)}</span></div>
        <div class="d-row"><span class="d-key">Version</span><span class="d-val">${b.version}</span></div>
        <div class="d-row"><span class="d-key">Nonce</span><span class="d-val mono">${b.nonce}</span></div>
        <div class="d-row"><span class="d-key">Merkle Root</span><span class="d-val mono">${b.merkle_root||'-'}</span></div>
        <div class="d-row"><span class="d-key">Parents</span><span class="d-val">${(b.parents||[]).map(p=>'<a href="#" onclick="showBlock(\''+p+'\');return false" class="mono">'+truncH(p,10)+'</a>').join(', ')||'<span style="color:var(--green)">Genesis</span>'}</span></div>
      </div>
    </div>
    <div class="section">
      <div class="section-head"><h2>Transactions <span class="badge">${b.tx_count}</span></h2></div>
      <div class="tbl-wrap"><table><thead><tr><th>Hash</th><th>Inputs</th><th>Outputs</th><th>Fee (sat)</th></tr></thead><tbody>
      ${(b.transactions||[]).map(tx=>`<tr>
        <td class="mono"><a href="#" onclick="showTx('${tx.hash}');return false" class="trunc">${truncH(tx.hash,12)}</a></td>
        <td>${tx.inputs}</td><td>${tx.outputs}</td><td>${fmt(tx.fee)}</td>
      </tr>`).join('')}
      </tbody></table></div>
    </div>`;
}

/* ── TX Detail ──────────────────────────────── */
async function showTx(hash){
  const tx=await fetchJson('/api/tx/'+encodeURIComponent(hash));
  if(tx.error){alert('Transaction not found');return}
  prevPanel=currentPanel;
  currentPanel='txDetail';
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.getElementById('p-txDetail').classList.add('active');
  document.querySelectorAll('nav button').forEach(btn=>btn.classList.remove('active'));

  const statusTag=tx.confirmed
    ?'<span class="tag tag-cb">Confirmed</span>'
    :'<span class="tag tag-pending">Pending</span>';

  document.getElementById('txDetailContent').innerHTML=`
    <div class="detail-card">
      <h2><svg width="18" height="18" viewBox="0 0 16 16" fill="var(--green)"><path d="M8.22 1.754a.25.25 0 00-.44 0L1.698 13.132a.25.25 0 00.22.368h12.164a.25.25 0 00.22-.368L8.22 1.754zm-1.763-.707c.659-1.234 2.427-1.234 3.086 0l6.082 11.378A1.75 1.75 0 0114.082 15H1.918a1.75 1.75 0 01-1.543-2.575L6.457 1.047z"/></svg> Transaction ${statusTag}</h2>
      <div class="detail-grid">
        <div class="d-row"><span class="d-key">Hash</span><span class="d-val mono">${tx.hash}</span></div>
        <div class="d-row"><span class="d-key">Status</span><span class="d-val">${tx.confirmed?'Confirmed in block':'Pending in mempool'}</span></div>
        ${tx.block_hash?`<div class="d-row"><span class="d-key">Block</span><span class="d-val"><a href="#" onclick="showBlock('${tx.block_hash}');return false" class="mono">${truncH(tx.block_hash,12)}</a> (height ${fmt(tx.block_height)})</span></div>`:''}
        <div class="d-row"><span class="d-key">Type</span><span class="d-val"><span class="tag tag-tx">${tx.tx_type||'Transfer'}</span>${tx.is_coinbase?' <span class="tag tag-cb">Coinbase</span>':''}</span></div>
        <div class="d-row"><span class="d-key">Fee</span><span class="d-val">${fmt(tx.fee)} sat (${fmtSdag(tx.fee)} SDAG)</span></div>
        <div class="d-row"><span class="d-key">Total Output</span><span class="d-val">${fmt(tx.total_output)} sat (${fmtSdag(tx.total_output)} SDAG)</span></div>
        <div class="d-row"><span class="d-key">Timestamp</span><span class="d-val">${tx.timestamp?new Date(tx.timestamp*1000).toLocaleString():'-'}</span></div>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <div class="section">
        <div class="section-head"><h2>Inputs <span class="badge">${(tx.inputs||[]).length}</span></h2></div>
        <div class="tbl-wrap"><table><thead><tr><th>From</th><th>TXID</th><th>Index</th></tr></thead><tbody>
        ${(tx.inputs||[]).map(i=>`<tr>
          <td class="mono"><a href="#" onclick="showAddress('${i.owner}');return false" class="trunc">${truncH(i.owner,8)}</a></td>
          <td class="mono trunc">${truncH(i.txid,8)}</td>
          <td>${i.index}</td>
        </tr>`).join('')||'<tr><td colspan="3" style="color:var(--dim)">Coinbase (no inputs)</td></tr>'}
        </tbody></table></div>
      </div>
      <div class="section">
        <div class="section-head"><h2>Outputs <span class="badge">${(tx.outputs||[]).length}</span></h2></div>
        <div class="tbl-wrap"><table><thead><tr><th>To</th><th>Amount (SDAG)</th><th>Amount (sat)</th></tr></thead><tbody>
        ${(tx.outputs||[]).map(o=>`<tr>
          <td class="mono"><a href="#" onclick="showAddress('${o.address}');return false" class="trunc">${truncH(o.address,8)}</a></td>
          <td><strong style="color:var(--green)">${fmtSdag(o.amount)}</strong></td>
          <td>${fmt(o.amount)}</td>
        </tr>`).join('')}
        </tbody></table></div>
      </div>
    </div>`;
}

/* ── Address Detail ─────────────────────────── */
async function showAddress(addr){
  const a=await fetchJson('/api/address/'+encodeURIComponent(addr));
  if(a.error){alert('Address not found');return}
  prevPanel=currentPanel;
  currentPanel='addressDetail';
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.getElementById('p-addressDetail').classList.add('active');
  document.querySelectorAll('nav button').forEach(btn=>btn.classList.remove('active'));

  document.getElementById('addressDetailContent').innerHTML=`
    <div class="detail-card">
      <h2><svg width="18" height="18" viewBox="0 0 16 16" fill="var(--cyan)"><path d="M10.5 5a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0zm.061 3.073a4 4 0 10-5.123 0 6.004 6.004 0 00-3.431 5.142.75.75 0 001.498.07 4.5 4.5 0 018.99 0 .75.75 0 101.498-.07 6.005 6.005 0 00-3.432-5.142z"/></svg> Address</h2>
      <div class="detail-grid">
        <div class="d-row"><span class="d-key">Address</span><span class="d-val mono">${a.address}</span></div>
        <div class="d-row"><span class="d-key">Balance</span><span class="d-val"><strong style="color:var(--green);font-size:18px">${a.balance_sdag} SDAG</strong></span></div>
        <div class="d-row"><span class="d-key">Satoshis</span><span class="d-val">${fmt(a.balance)} sat</span></div>
      </div>
    </div>`;
}

/* ── Mempool ────────────────────────────────── */
async function loadMempool(){
  const m=await fetchJson('/api/mempool');
  if(m.error)return;
  document.getElementById('mempoolCount').textContent=m.count||0;
  document.getElementById('mempoolStats').innerHTML=`
    <div class="stat"><div class="lbl">Pending TXs</div><div class="val orange">${fmt(m.count)}</div></div>
    <div class="stat"><div class="lbl">Total Fees</div><div class="val green">${fmtSdag(m.total_fees)}</div><div class="sub">SDAG</div></div>
    <div class="stat"><div class="lbl">Total Fees (sat)</div><div class="val">${fmt(m.total_fees)}</div></div>
  `;
  document.getElementById('mempoolBody').innerHTML=(m.transactions||[]).map(tx=>`
    <tr>
      <td class="mono"><a href="#" onclick="showTx('${tx.hash}');return false" class="trunc">${truncH(tx.hash,10)}</a></td>
      <td><span class="tag tag-tx">${tx.tx_type||'Transfer'}</span></td>
      <td>${tx.outputs}</td>
      <td>${fmtSdag(tx.total_output)} SDAG</td>
      <td>${fmt(tx.fee)} sat</td>
      <td style="color:var(--dim)">${age(tx.timestamp)}</td>
    </tr>
  `).join('')||'<tr><td colspan="6" style="color:var(--dim);text-align:center;padding:24px">Mempool is empty</td></tr>';
}

/* ── DAG Visualization ──────────────────────── */
async function loadDag(){
  const d=await fetchJson('/api/dag');
  if(d.error||!d.nodes)return;
  const canvas=document.getElementById('dagCanvas');
  const ctx=canvas.getContext('2d');
  const dpr=window.devicePixelRatio||1;
  const W=canvas.parentElement.clientWidth-32;
  const H=500;
  canvas.width=W*dpr;
  canvas.height=H*dpr;
  canvas.style.width=W+'px';
  canvas.style.height=H+'px';
  ctx.scale(dpr,dpr);
  ctx.clearRect(0,0,W,H);

  if(d.nodes.length===0){
    ctx.fillStyle='#8b949e';ctx.font='14px sans-serif';ctx.textAlign='center';
    ctx.fillText('No DAG data available',W/2,H/2);return;
  }

  // Layout: group nodes by height
  const byHeight={};
  d.nodes.forEach(n=>{if(!byHeight[n.height])byHeight[n.height]=[];byHeight[n.height].push(n)});
  const heights=Object.keys(byHeight).map(Number).sort((a,b)=>a-b);
  const nodePos={};
  const padX=60,padY=50;
  const colW=Math.max(50,Math.min(120,(W-padX*2)/(heights.length||1)));

  heights.forEach((h,ci)=>{
    const group=byHeight[h];
    const rowH=(H-padY*2)/(group.length+1);
    group.forEach((n,ri)=>{
      const x=padX+ci*colW;
      const y=padY+(ri+1)*rowH;
      nodePos[n.id]={x,y,node:n};
    });
  });

  // Draw edges
  ctx.strokeStyle='#30363d';ctx.lineWidth=1.5;
  d.edges.forEach(e=>{
    const from=nodePos[e.from],to=nodePos[e.to];
    if(!from||!to)return;
    ctx.beginPath();
    ctx.moveTo(from.x,from.y);
    const cpx=(from.x+to.x)/2;
    ctx.bezierCurveTo(cpx,from.y,cpx,to.y,to.x,to.y);
    ctx.stroke();
  });

  // Draw nodes
  const lastHeight=heights[heights.length-1];
  Object.values(nodePos).forEach(({x,y,node})=>{
    const isTip=node.height===lastHeight;
    const r=isTip?8:6;
    ctx.beginPath();ctx.arc(x,y,r,0,Math.PI*2);
    ctx.fillStyle=isTip?'#3fb950':'#58a6ff';ctx.fill();
    ctx.strokeStyle=isTip?'#238636':'#1f6feb';ctx.lineWidth=2;ctx.stroke();

    // Label
    ctx.fillStyle='#8b949e';ctx.font='10px monospace';ctx.textAlign='center';
    ctx.fillText('#'+node.height,x,y-r-4);
    if(node.tx_count>0){
      ctx.fillStyle='#d29922';ctx.fillText(node.tx_count+'tx',x,y+r+12);
    }
  });

  // Height axis
  ctx.fillStyle='#6e7681';ctx.font='10px sans-serif';ctx.textAlign='center';
  heights.forEach((h,i)=>{
    ctx.fillText('H:'+h,padX+i*colW,H-10);
  });
}

/* ── Rich List ──────────────────────────────── */
async function loadRichlist(){
  const r=await fetchJson('/api/richlist');
  if(r.error)return;
  document.getElementById('totalAddrs').textContent=fmt(r.total_addresses)+' addresses';
  document.getElementById('richlistBody').innerHTML=(r.richlist||[]).map(e=>`
    <tr>
      <td><strong style="color:var(--dim)">${e.rank}</strong></td>
      <td class="mono"><a href="#" onclick="showAddress('${e.address}');return false" class="trunc trunc-lg">${truncH(e.address,14)}</a></td>
      <td><strong style="color:var(--green)">${e.balance_sdag.toFixed(8)}</strong></td>
      <td>${fmt(e.balance)}</td>
    </tr>
  `).join('')||'<tr><td colspan="4" style="color:var(--dim);text-align:center;padding:24px">No addresses found</td></tr>';
}

/* ── Network ────────────────────────────────── */
async function loadNetwork(){
  const[n,p]=await Promise.all([fetchJson('/api/network'),fetchJson('/api/pool')]);
  if(!n.error){
    document.getElementById('networkStats').innerHTML=`
      <div class="stat"><div class="lbl">Peers</div><div class="val green">${fmt(n.peer_count)}</div></div>
      <div class="stat"><div class="lbl">Node Version</div><div class="val" style="font-size:16px">${n.node_version||'-'}</div></div>
      <div class="stat"><div class="lbl">Network</div><div class="val cyan" style="font-size:18px">${n.network||'-'}</div></div>
      <div class="stat"><div class="lbl">P2P Port</div><div class="val">${n.p2p_port}</div></div>
      <div class="stat"><div class="lbl">RPC Port</div><div class="val">${n.rpc_port}</div></div>
      <div class="stat"><div class="lbl">Best Height</div><div class="val">${fmt(n.best_height)}</div></div>
      <div class="stat"><div class="lbl">Best Hash</div><div class="val mono" style="font-size:11px">${truncH(n.best_hash,16)}</div></div>
    `;
  }
  const card=document.getElementById('netPoolCard');
  if(!p.error&&p.status==='active'){
    card.style.display='block';
    card.innerHTML=`<h3>Stratum Mining Pool</h3><div class="pool-grid">
      <div class="pool-item"><div class="label">Status</div><div class="val">${p.status}</div></div>
      <div class="pool-item"><div class="label">Workers</div><div class="val">${p.workers}</div></div>
      <div class="pool-item"><div class="label">Blocks Found</div><div class="val">${p.blocks_found}</div></div>
      <div class="pool-item"><div class="label">Pool Fee</div><div class="val">${p.pool_fee_pct}%</div></div>
    </div>`;
  }else{card.style.display='none'}
}

/* ── Search ─────────────────────────────────── */
async function doSearch(){
  const q=document.getElementById('searchInput').value.trim();
  if(!q)return;
  const r=await fetchJson('/api/search/'+encodeURIComponent(q));
  if(r.type==='block')showBlock(r.id);
  else if(r.type==='tx')showTx(r.id);
  else if(r.type==='address')showAddress(r.id);
  else alert('Nothing found for: '+q);
}

/* ── Auto Refresh ───────────────────────────── */
async function refresh(){
  await Promise.all([loadStats(),loadBlocks(),loadPool()]);
}
refresh();
refreshTimer=setInterval(()=>{
  if(currentPanel==='dashboard')refresh();
  if(currentPanel==='mempool')loadMempool();
},5000);
</script>
</body>
</html>"##;
