// Embedded HTML/CSS/JS for the ShadowDAG Smart Contract IDE.

pub const IDE_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShadowDAG Contract IDE</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--dim:#8b949e;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--orange:#d29922;--editor-bg:#0d1117;--line-bg:#161b22}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;min-height:100vh}
a{color:var(--accent);text-decoration:none}
header{background:var(--card);border-bottom:1px solid var(--border);padding:10px 0}
header .c{max-width:1400px;margin:0 auto;padding:0 16px;display:flex;align-items:center;gap:16px}
.logo{font-size:18px;font-weight:700;color:#fff}.logo span{color:var(--accent)}
nav{display:flex;gap:4px;flex:1}
nav button{background:none;border:1px solid transparent;padding:6px 14px;border-radius:6px;color:var(--dim);cursor:pointer;font-size:13px;transition:all .15s}
nav button:hover{color:var(--text);background:var(--bg)}
nav button.active{color:var(--accent);border-color:var(--accent);background:rgba(88,166,255,.1)}
.main{max-width:1400px;margin:0 auto;padding:16px}
.tab{display:none}.tab.active{display:block}
.panel{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px}
.panel h3{color:#fff;margin-bottom:12px;font-size:14px}
.row{display:flex;gap:12px;margin-bottom:12px;flex-wrap:wrap}
.col{flex:1;min-width:200px}
label{display:block;font-size:12px;color:var(--dim);margin-bottom:4px}
input,select{width:100%;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;font-family:inherit}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent)}
textarea{width:100%;padding:12px;background:var(--editor-bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:'SF Mono',SFMono-Regular,Consolas,'Liberation Mono',Menlo,monospace;font-size:13px;line-height:1.5;resize:vertical;tab-size:2}
.editor-area{position:relative}
.editor-area textarea{min-height:350px}
.line-nums{position:absolute;top:0;left:0;width:40px;height:100%;padding:12px 4px;text-align:right;color:var(--dim);font-family:'SF Mono',monospace;font-size:13px;line-height:1.5;pointer-events:none;border-right:1px solid var(--border);user-select:none;overflow:hidden}
.editor-area textarea.with-lines{padding-left:50px}
.btn{padding:8px 18px;border:none;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600;transition:all .15s}
.btn-primary{background:var(--accent);color:#fff}.btn-primary:hover{opacity:.9}
.btn-green{background:var(--green);color:#fff}.btn-green:hover{opacity:.9}
.btn-orange{background:var(--orange);color:#fff}.btn-orange:hover{opacity:.9}
.btn-sm{padding:5px 12px;font-size:12px}
.btn-outline{background:none;border:1px solid var(--border);color:var(--text)}.btn-outline:hover{border-color:var(--accent);color:var(--accent)}
.output{background:#010409;border:1px solid var(--border);border-radius:6px;padding:12px;font-family:'SF Mono',monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto;min-height:60px}
.output.success{border-color:var(--green)}.output.error{border-color:var(--red)}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.badge-green{background:rgba(63,185,80,.2);color:var(--green)}
.badge-red{background:rgba(248,81,73,.2);color:var(--red)}
.badge-blue{background:rgba(88,166,255,.2);color:var(--accent)}
.examples-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.example-card{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:16px;cursor:pointer;transition:all .15s}
.example-card:hover{border-color:var(--accent);transform:translateY(-1px)}
.example-card h4{color:#fff;margin-bottom:4px}.example-card p{color:var(--dim);font-size:12px}
.opcodes-table{width:100%;font-size:12px;border-collapse:collapse}
.opcodes-table th{text-align:left;padding:6px 8px;background:#1c2128;color:var(--dim);border-bottom:1px solid var(--border)}
.opcodes-table td{padding:6px 8px;border-bottom:1px solid var(--border);font-family:'SF Mono',monospace}
.status{margin-top:8px;padding:8px 12px;border-radius:6px;font-size:12px}
.status.ok{background:rgba(63,185,80,.1);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.status.err{background:rgba(248,81,73,.1);color:var(--red);border:1px solid rgba(248,81,73,.3)}
footer{text-align:center;padding:20px;color:var(--dim);font-size:11px;border-top:1px solid var(--border);margin-top:32px}
@media(max-width:768px){.row{flex-direction:column}.editor-area textarea{min-height:250px}}
</style>
</head>
<body>
<header><div class="c">
<div class="logo"><span>Shadow</span>DAG IDE</div>
<nav>
<button class="active" onclick="showTab('editor')">Editor</button>
<button onclick="showTab('deploy')">Deploy</button>
<button onclick="showTab('interact')">Interact</button>
<button onclick="showTab('examples')">Examples</button>
<button onclick="showTab('tools')">Tools</button>
</nav>
</div></header>

<div class="main">

<!-- ═══ EDITOR TAB ═══ -->
<div id="tab-editor" class="tab active">
<div class="panel">
<h3>ShadowASM Editor</h3>
<div class="row" style="margin-bottom:8px">
<button class="btn btn-primary" onclick="compileCode()">Compile</button>
<button class="btn btn-outline btn-sm" onclick="clearEditor()">Clear</button>
<span id="compileStatus" style="line-height:32px;margin-left:12px;font-size:12px"></span>
</div>
<div class="editor-area">
<textarea id="codeEditor" class="with-lines" spellcheck="false" placeholder=";; Write your ShadowASM contract here...
;; @fn myFunction():uint64
;; @event MyEvent(address,uint64)

PUSH1 0
SLOAD
PUSH1 1
ADD
PUSH1 0
SSTORE
STOP" oninput="updateLines()" onscroll="syncScroll()"></textarea>
<div class="line-nums" id="lineNums">1</div>
</div>
</div>
<div class="panel" id="compileOutput" style="display:none">
<h3>Compilation Result</h3>
<div class="output" id="compileResult"></div>
</div>
</div>

<!-- ═══ DEPLOY TAB ═══ -->
<div id="tab-deploy" class="tab">
<div class="panel">
<h3>Deploy Contract</h3>
<div class="row">
<div class="col"><label>Bytecode (hex)</label><input id="deployBytecode" placeholder="Paste compiled bytecode or compile from Editor"></div>
</div>
<div class="row">
<div class="col"><label>Deployer Address</label><input id="deployAddr" placeholder="SD0..."></div>
<div class="col"><label>Gas Limit</label><input id="deployGas" type="number" value="10000000"></div>
<div class="col"><label>Value (satoshi)</label><input id="deployValue" type="number" value="0"></div>
</div>
<button class="btn btn-green" onclick="deployContract()">Deploy Contract</button>
</div>
<div class="panel" id="deployOutput" style="display:none">
<h3>Deploy Result</h3>
<div class="output" id="deployResult"></div>
</div>
</div>

<!-- ═══ INTERACT TAB ═══ -->
<div id="tab-interact" class="tab">
<div class="panel">
<h3>Interact with Contract</h3>
<div class="row">
<div class="col"><label>Contract Address</label><input id="contractAddr" placeholder="SD1c_..."></div>
<button class="btn btn-outline btn-sm" style="align-self:end" onclick="getCode()">Get Code</button>
</div>
<div class="row">
<div class="col"><label>Calldata (hex)</label><input id="calldata" placeholder="Function calldata in hex (empty for default)"></div>
<div class="col"><label>Caller Address</label><input id="callerAddr" placeholder="SD0..."></div>
</div>
<div class="row">
<div class="col"><label>Gas Limit</label><input id="callGas" type="number" value="1000000"></div>
<div class="col"><label>Value (satoshi)</label><input id="callValue" type="number" value="0"></div>
</div>
<div class="row">
<button class="btn btn-primary" onclick="callContract()">Call Contract</button>
<button class="btn btn-orange" onclick="estimateGas()">Estimate Gas</button>
</div>
</div>
<div class="panel">
<h3>Storage Viewer</h3>
<div class="row">
<div class="col"><label>Slot</label><input id="storageSlot" placeholder="0" value="0"></div>
<button class="btn btn-outline btn-sm" style="align-self:end" onclick="readStorage()">Read Storage</button>
</div>
<div class="output" id="storageResult" style="min-height:30px">Enter a contract address above and click Read Storage</div>
</div>
<div class="panel" id="interactOutput" style="display:none">
<h3>Result</h3>
<div class="output" id="interactResult"></div>
</div>
</div>

<!-- ═══ EXAMPLES TAB ═══ -->
<div id="tab-examples" class="tab">
<div class="panel">
<h3>Example Contracts</h3>
<p style="color:var(--dim);margin-bottom:16px;font-size:13px">Click an example to load it into the editor.</p>
<div class="examples-grid" id="examplesGrid">Loading...</div>
</div>
</div>

<!-- ═══ TOOLS TAB ═══ -->
<div id="tab-tools" class="tab">
<div class="panel">
<h3>Transaction Receipt</h3>
<div class="row">
<div class="col"><label>TX Hash</label><input id="receiptHash" placeholder="Transaction hash..."></div>
<button class="btn btn-outline btn-sm" style="align-self:end" onclick="getReceipt()">Lookup</button>
</div>
<div class="output" id="receiptResult" style="min-height:30px"></div>
</div>
<div class="panel">
<h3>ShadowASM V1 Opcode Reference</h3>
<table class="opcodes-table">
<thead><tr><th>Category</th><th>Opcodes</th></tr></thead>
<tbody>
<tr><td>Control</td><td>STOP NOP</td></tr>
<tr><td>Stack</td><td>PUSH1 PUSH2 PUSH4 PUSH8 PUSH16 PUSH32 POP DUP SWAP DUP2-8 SWAP2-4</td></tr>
<tr><td>Arithmetic</td><td>ADD SUB MUL DIV MOD EXP ADDMOD MULMOD</td></tr>
<tr><td>Comparison</td><td>EQ LT GT ISZERO</td></tr>
<tr><td>Bitwise</td><td>AND OR XOR NOT SHL SHR</td></tr>
<tr><td>Storage</td><td>SLOAD SSTORE SDELETE</td></tr>
<tr><td>Memory</td><td>MLOAD MSTORE MSTORE8 MSIZE</td></tr>
<tr><td>Crypto</td><td>SHA256 KECCAK</td></tr>
<tr><td>Context</td><td>CALLER CALLVALUE TIMESTAMP BLOCKHASH BALANCE ADDRESS PC GAS GASLIMIT</td></tr>
<tr><td>Flow</td><td>JUMP JUMPI JUMPDEST</td></tr>
<tr><td>Logging</td><td>LOG0 LOG1 LOG2 LOG3 LOG4</td></tr>
<tr><td>System</td><td>CALL CALLCODE DELEGATECALL STATICCALL CREATE CREATE2 RETURN REVERT SELFDESTRUCT</td></tr>
<tr><td>Call Data</td><td>CALLDATALOAD CALLDATASIZE CALLDATACOPY CODESIZE CODECOPY EXTCODESIZE RETURNDATASIZE RETURNDATACOPY</td></tr>
</tbody>
</table>
</div>
</div>

</div>
<footer>ShadowDAG Contract IDE &mdash; ShadowVM V1 &mdash; 47 Opcodes</footer>

<script>
const API='';
let compiledBytecode='';

function showTab(name){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  document.querySelector('nav button[onclick*="'+name+'"]').classList.add('active');
  if(name==='examples')loadExamples();
}

function updateLines(){
  const ta=document.getElementById('codeEditor');
  const ln=document.getElementById('lineNums');
  const lines=ta.value.split('\n').length;
  ln.innerHTML=Array.from({length:lines},(_, i)=>i+1).join('<br>');
}

function syncScroll(){
  const ta=document.getElementById('codeEditor');
  document.getElementById('lineNums').style.top=-ta.scrollTop+'px';
}

function clearEditor(){
  document.getElementById('codeEditor').value='';
  updateLines();
}

async function compileCode(){
  const source=document.getElementById('codeEditor').value;
  if(!source.trim()){alert('Write some code first');return}
  const status=document.getElementById('compileStatus');
  status.innerHTML='<span style="color:var(--orange)">Compiling...</span>';
  try{
    const r=await fetch(API+'/api/compile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source})});
    const d=await r.json();
    const el=document.getElementById('compileOutput');
    el.style.display='block';
    const res=document.getElementById('compileResult');
    if(d.success){
      compiledBytecode=d.bytecode;
      document.getElementById('deployBytecode').value=d.bytecode;
      res.className='output success';
      let txt='Compilation successful!\n\n';
      txt+='Bytecode: '+d.bytecode.substring(0,80)+(d.bytecode.length>80?'...':'')+'\n';
      txt+='Size: '+d.size+' bytes\n';
      if(d.abi&&d.abi.functions&&d.abi.functions.length>0)txt+='\nABI Functions:\n'+d.abi.functions.map(f=>'  '+f).join('\n')+'\n';
      if(d.abi&&d.abi.events&&d.abi.events.length>0)txt+='\nABI Events:\n'+d.abi.events.map(e=>'  '+e).join('\n')+'\n';
      res.textContent=txt;
      status.innerHTML='<span class="badge badge-green">Compiled ('+d.size+' bytes)</span>';
    }else{
      res.className='output error';
      res.textContent='Compilation Error:\n'+d.error;
      status.innerHTML='<span class="badge badge-red">Error</span>';
    }
  }catch(e){status.innerHTML='<span class="badge badge-red">Failed: '+e.message+'</span>'}
}

async function deployContract(){
  const bytecode=document.getElementById('deployBytecode').value;
  const deployer=document.getElementById('deployAddr').value;
  const gas=parseInt(document.getElementById('deployGas').value)||10000000;
  const value=parseInt(document.getElementById('deployValue').value)||0;
  if(!bytecode||!deployer){alert('Fill bytecode and deployer address');return}
  try{
    const r=await fetch(API+'/api/deploy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({bytecode,deployer,gas,value})});
    const d=await r.json();
    const el=document.getElementById('deployOutput');el.style.display='block';
    const res=document.getElementById('deployResult');
    if(d.result){
      res.className='output success';
      res.textContent=JSON.stringify(d.result,null,2);
      if(d.result.address)document.getElementById('contractAddr').value=d.result.address;
    }else{
      res.className='output error';
      res.textContent=JSON.stringify(d,null,2);
    }
  }catch(e){document.getElementById('deployResult').textContent='Error: '+e.message}
}

async function callContract(){
  const contract=document.getElementById('contractAddr').value;
  const calldata=document.getElementById('calldata').value;
  const caller=document.getElementById('callerAddr').value;
  const gas=parseInt(document.getElementById('callGas').value)||1000000;
  const value=parseInt(document.getElementById('callValue').value)||0;
  if(!contract){alert('Enter contract address');return}
  try{
    const r=await fetch(API+'/api/call',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({contract,calldata,caller,gas,value})});
    const d=await r.json();
    const el=document.getElementById('interactOutput');el.style.display='block';
    document.getElementById('interactResult').textContent=JSON.stringify(d.result||d,null,2);
  }catch(e){document.getElementById('interactResult').textContent='Error: '+e.message}
}

async function estimateGas(){
  const contract=document.getElementById('contractAddr').value;
  const calldata=document.getElementById('calldata').value;
  const caller=document.getElementById('callerAddr').value;
  if(!contract){alert('Enter contract address');return}
  try{
    const r=await fetch(API+'/api/estimate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({contract,calldata,caller})});
    const d=await r.json();
    const el=document.getElementById('interactOutput');el.style.display='block';
    document.getElementById('interactResult').textContent='Gas Estimate:\n'+JSON.stringify(d.result||d,null,2);
  }catch(e){document.getElementById('interactResult').textContent='Error: '+e.message}
}

async function getCode(){
  const addr=document.getElementById('contractAddr').value;
  if(!addr){alert('Enter contract address');return}
  try{
    const r=await fetch(API+'/api/code/'+addr);
    const d=await r.json();
    const el=document.getElementById('interactOutput');el.style.display='block';
    document.getElementById('interactResult').textContent='Contract Code:\n'+JSON.stringify(d.result||d,null,2);
  }catch(e){document.getElementById('interactResult').textContent='Error: '+e.message}
}

async function readStorage(){
  const addr=document.getElementById('contractAddr').value;
  const slot=document.getElementById('storageSlot').value||'0';
  if(!addr){alert('Enter contract address first');return}
  try{
    const r=await fetch(API+'/api/storage/'+addr+'/'+slot);
    const d=await r.json();
    document.getElementById('storageResult').textContent=JSON.stringify(d.result||d,null,2);
  }catch(e){document.getElementById('storageResult').textContent='Error: '+e.message}
}

async function getReceipt(){
  const hash=document.getElementById('receiptHash').value;
  if(!hash){alert('Enter TX hash');return}
  try{
    const r=await fetch(API+'/api/receipt/'+hash);
    const d=await r.json();
    document.getElementById('receiptResult').textContent=JSON.stringify(d.result||d,null,2);
  }catch(e){document.getElementById('receiptResult').textContent='Error: '+e.message}
}

async function loadExamples(){
  try{
    const r=await fetch(API+'/api/examples');
    const d=await r.json();
    const grid=document.getElementById('examplesGrid');
    grid.innerHTML=(d.examples||[]).map(ex=>`
      <div class="example-card" onclick="loadExample('${ex.name}')">
        <h4>${ex.file}</h4>
        <p>${ex.description}</p>
      </div>
    `).join('');
  }catch(e){document.getElementById('examplesGrid').textContent='Failed to load examples'}
}

async function loadExample(name){
  try{
    const r=await fetch(API+'/api/example/'+name);
    const d=await r.json();
    if(d.source){
      document.getElementById('codeEditor').value=d.source;
      updateLines();
      showTab('editor');
    }
  }catch(e){alert('Failed to load: '+e.message)}
}

updateLines();
</script>
</body>
</html>"##;
