// Embedded HTML/CSS/JS for the ShadowDAG blockchain explorer.
// Single-page app with auto-refreshing dashboard, block list, and search.

pub const EXPLORER_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShadowDAG Explorer</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--dim:#8b949e;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--orange:#d29922}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.container{max-width:1200px;margin:0 auto;padding:0 16px}
header{background:var(--card);border-bottom:1px solid var(--border);padding:12px 0;position:sticky;top:0;z-index:10}
header .container{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
.logo{font-size:20px;font-weight:700;color:#fff;display:flex;align-items:center;gap:8px}
.logo span{color:var(--accent)}
.search{flex:1;max-width:500px}
.search input{width:100%;padding:8px 14px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:14px;outline:none}
.search input:focus{border-color:var(--accent)}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:20px 0}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px}
.stat-card .label{font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
.stat-card .value{font-size:24px;font-weight:700;color:#fff;margin-top:4px}
.stat-card .sub{font-size:12px;color:var(--dim);margin-top:2px}
.section{margin:24px 0}
.section h2{font-size:16px;color:#fff;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.section h2 .badge{background:var(--accent);color:#fff;font-size:11px;padding:2px 8px;border-radius:10px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:8px;overflow:hidden}
th{background:#1c2128;text-align:left;padding:10px 14px;font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border)}
td{padding:10px 14px;font-size:13px;border-bottom:1px solid var(--border)}
tr:last-child td{border-bottom:none}
tr:hover td{background:#1c2128}
.hash{font-family:'SF Mono',SFMono-Regular,Consolas,'Liberation Mono',Menlo,monospace;font-size:12px}
.truncate{max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:middle}
.pool-section{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;margin:20px 0}
.pool-section h3{color:#fff;margin-bottom:8px}
.pool-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.pool-item .label{font-size:11px;color:var(--dim)}
.pool-item .val{font-size:18px;font-weight:700;color:var(--green)}
.block-detail{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;margin:20px 0}
.block-detail h2{color:#fff;margin-bottom:16px}
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px 24px}
.detail-row{display:flex;gap:8px}
.detail-row .dk{color:var(--dim);min-width:120px;font-size:13px}
.detail-row .dv{font-size:13px;word-break:break-all}
.back-btn{display:inline-block;margin-bottom:12px;padding:6px 14px;background:var(--border);border-radius:6px;color:var(--text);cursor:pointer;font-size:13px}
.back-btn:hover{background:var(--accent);color:#fff;text-decoration:none}
footer{text-align:center;padding:24px;color:var(--dim);font-size:12px;border-top:1px solid var(--border);margin-top:40px}
.live{display:inline-block;width:8px;height:8px;background:var(--green);border-radius:50%;margin-right:6px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
@media(max-width:768px){.stats-grid{grid-template-columns:1fr 1fr}.detail-grid{grid-template-columns:1fr}.search{max-width:100%}}
</style>
</head>
<body>
<header>
<div class="container">
<div class="logo"><span>Shadow</span>DAG Explorer</div>
<div class="search"><input id="searchInput" placeholder="Search by block hash, height, or address..." onkeydown="if(event.key==='Enter')doSearch()"></div>
</div>
</header>
<div class="container">
<div id="dashboard">
<div class="stats-grid" id="statsGrid"></div>
<div class="pool-section" id="poolSection" style="display:none"></div>
<div class="section">
<h2><span class="live"></span>Latest Blocks <span class="badge" id="blockCount">0</span></h2>
<div style="overflow-x:auto"><table><thead><tr><th>Height</th><th>Hash</th><th>Time</th><th>TXs</th><th>Difficulty</th><th>Parents</th></tr></thead><tbody id="blocksBody"></tbody></table></div>
</div>
</div>
<div id="blockDetail" style="display:none"></div>
<div id="addressDetail" style="display:none"></div>
</div>
<footer>ShadowDAG Explorer &mdash; Powered by ShadowDAG Node</footer>
<script>
const API='';
let refreshTimer;

async function fetchJson(url){
  try{const r=await fetch(API+url);return await r.json()}
  catch(e){return{error:e.message}}
}

function formatTime(ts){
  if(!ts)return'-';
  const d=new Date(ts*1000);
  const now=Date.now()/1000;
  const diff=Math.floor(now-ts);
  if(diff<60)return diff+'s ago';
  if(diff<3600)return Math.floor(diff/60)+'m ago';
  if(diff<86400)return Math.floor(diff/3600)+'h ago';
  return d.toLocaleDateString();
}

function truncHash(h,n){
  if(!h)return'-';
  n=n||8;
  return h.length>n*2?h.slice(0,n)+'...'+h.slice(-n):h;
}

function fmtNum(n){
  if(n===undefined||n===null)return'-';
  return Number(n).toLocaleString();
}

async function loadStats(){
  const s=await fetchJson('/api/stats');
  if(s.error)return;
  document.getElementById('statsGrid').innerHTML=`
    <div class="stat-card"><div class="label">Block Height</div><div class="value">${fmtNum(s.best_height)}</div><div class="sub">${fmtNum(s.block_count)} total blocks</div></div>
    <div class="stat-card"><div class="label">Network</div><div class="value">${s.network||'-'}</div><div class="sub">${s.version||''}</div></div>
    <div class="stat-card"><div class="label">Peers</div><div class="value">${fmtNum(s.peer_count)}</div><div class="sub">P2P: ${s.p2p_port} / RPC: ${s.rpc_port}</div></div>
    <div class="stat-card"><div class="label">Mempool</div><div class="value">${fmtNum(s.mempool_size)}</div><div class="sub">pending transactions</div></div>
    <div class="stat-card"><div class="label">Algorithm</div><div class="value" style="font-size:14px">${s.algorithm||'-'}</div></div>
    <div class="stat-card"><div class="label">Max Supply</div><div class="value" style="font-size:16px">${fmtNum(s.max_supply?s.max_supply/100000000:0)}</div><div class="sub">SDAG</div></div>
  `;
}

async function loadBlocks(){
  const d=await fetchJson('/api/blocks');
  if(d.error||!d.blocks)return;
  document.getElementById('blockCount').textContent=d.best_height||0;
  const tbody=document.getElementById('blocksBody');
  tbody.innerHTML=d.blocks.map(b=>`
    <tr>
      <td><strong>${b.height}</strong></td>
      <td class="hash"><a href="#" onclick="showBlock('${b.hash}');return false" class="truncate">${truncHash(b.hash,10)}</a></td>
      <td>${formatTime(b.timestamp)}</td>
      <td>${b.tx_count}</td>
      <td>${fmtNum(b.difficulty)}</td>
      <td>${b.parents}</td>
    </tr>
  `).join('');
}

async function loadPool(){
  const p=await fetchJson('/api/pool');
  const el=document.getElementById('poolSection');
  if(p.status==='active'){
    el.style.display='block';
    el.innerHTML=`<h3>Mining Pool (Stratum)</h3><div class="pool-grid">
      <div class="pool-item"><div class="label">Status</div><div class="val">${p.status}</div></div>
      <div class="pool-item"><div class="label">Workers</div><div class="val">${p.workers}</div></div>
      <div class="pool-item"><div class="label">Blocks Found</div><div class="val">${p.blocks_found}</div></div>
      <div class="pool-item"><div class="label">Pool Fee</div><div class="val">${p.pool_fee_pct}%</div></div>
    </div>`;
  }else{el.style.display='none'}
}

async function showBlock(id){
  const b=await fetchJson('/api/block/'+id);
  if(b.error){alert('Block not found: '+id);return}
  document.getElementById('dashboard').style.display='none';
  document.getElementById('addressDetail').style.display='none';
  const el=document.getElementById('blockDetail');
  el.style.display='block';
  el.innerHTML=`
    <a class="back-btn" href="#" onclick="showDashboard();return false">Back to Dashboard</a>
    <div class="block-detail"><h2>Block #${b.height}</h2>
    <div class="detail-grid">
      <div class="detail-row"><span class="dk">Hash</span><span class="dv hash">${b.hash}</span></div>
      <div class="detail-row"><span class="dk">Height</span><span class="dv">${b.height}</span></div>
      <div class="detail-row"><span class="dk">Timestamp</span><span class="dv">${new Date(b.timestamp*1000).toLocaleString()} (${formatTime(b.timestamp)})</span></div>
      <div class="detail-row"><span class="dk">Difficulty</span><span class="dv">${fmtNum(b.difficulty)}</span></div>
      <div class="detail-row"><span class="dk">Version</span><span class="dv">${b.version}</span></div>
      <div class="detail-row"><span class="dk">Nonce</span><span class="dv">${b.nonce}</span></div>
      <div class="detail-row"><span class="dk">Merkle Root</span><span class="dv hash">${truncHash(b.merkle_root,16)}</span></div>
      <div class="detail-row"><span class="dk">Parents</span><span class="dv">${(b.parents||[]).map(p=>'<a href="#" onclick="showBlock(\''+p+'\');return false" class="hash">'+truncHash(p,8)+'</a>').join(', ')||'Genesis'}</span></div>
    </div></div>
    <div class="section"><h2>Transactions <span class="badge">${b.tx_count}</span></h2>
    <table><thead><tr><th>Hash</th><th>Inputs</th><th>Outputs</th><th>Fee</th></tr></thead><tbody>
    ${(b.transactions||[]).map(tx=>`<tr><td class="hash truncate">${truncHash(tx.hash,12)}</td><td>${tx.inputs}</td><td>${tx.outputs}</td><td>${tx.fee}</td></tr>`).join('')}
    </tbody></table></div>`;
}

async function showAddress(addr){
  const a=await fetchJson('/api/address/'+addr);
  if(a.error){alert('Address not found');return}
  document.getElementById('dashboard').style.display='none';
  document.getElementById('blockDetail').style.display='none';
  const el=document.getElementById('addressDetail');
  el.style.display='block';
  el.innerHTML=`
    <a class="back-btn" href="#" onclick="showDashboard();return false">Back to Dashboard</a>
    <div class="block-detail"><h2>Address</h2>
    <div class="detail-grid">
      <div class="detail-row"><span class="dk">Address</span><span class="dv hash">${a.address}</span></div>
      <div class="detail-row"><span class="dk">Balance</span><span class="dv"><strong>${a.balance_sdag} SDAG</strong> (${fmtNum(a.balance)} sat)</span></div>
    </div></div>`;
}

function showDashboard(){
  document.getElementById('dashboard').style.display='block';
  document.getElementById('blockDetail').style.display='none';
  document.getElementById('addressDetail').style.display='none';
  refresh();
}

function doSearch(){
  const q=document.getElementById('searchInput').value.trim();
  if(!q)return;
  if(q.startsWith('S')||q.startsWith('s'))showAddress(q);
  else if(/^\d+$/.test(q))showBlock(q);
  else showBlock(q);
}

async function refresh(){
  await Promise.all([loadStats(),loadBlocks(),loadPool()]);
}

refresh();
refreshTimer=setInterval(refresh,5000);
</script>
</body>
</html>"##;
