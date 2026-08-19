// Self-verifying test for fault-proxy.mjs (run: node stack/fault-proxy.test.mjs) — validates each fault action
// deterministically against a loopback echo-ish HTTP server.
import net from "node:net";
import http from "node:http";
import { startFaultProxy } from "./fault-proxy.mjs";

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? " — " + detail : ""}`);
}

// Upstream: HTTP server answering a fixed 200-byte body.
const BODY = "x".repeat(200);
const upstream = http.createServer((req, res) => {
  res.writeHead(200, { "content-length": String(BODY.length) });
  res.end(BODY);
});
await new Promise((r) => upstream.listen(0, "127.0.0.1", r));
const upstreamPort = upstream.address().port;

const proxy = await startFaultProxy({
  upstreamPort,
  schedule: [
    { connection: 1, action: "reset" },
    { connection: 2, action: "black-hole" },
    { connection: 3, action: "cut-after", bytes: 50 },
    { connection: 4, action: "delay", ms: 400 },
    // connection 5: pass-through
  ],
});

function rawRequest(port, { timeoutMs = 2000 } = {}) {
  return new Promise((resolve) => {
    const sock = net.connect(port, "127.0.0.1");
    const chunks = [];
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) { settled = true; sock.destroy(); resolve({ outcome: "timeout", bytes: Buffer.concat(chunks).length }); }
    }, timeoutMs);
    sock.on("connect", () => sock.write("GET / HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n"));
    sock.on("data", (c) => chunks.push(c));
    sock.on("error", (e) => {
      if (!settled) { settled = true; clearTimeout(timer); resolve({ outcome: "error:" + e.code, bytes: Buffer.concat(chunks).length }); }
    });
    sock.on("close", () => {
      if (!settled) { settled = true; clearTimeout(timer); resolve({ outcome: "closed", bytes: Buffer.concat(chunks).length, data: Buffer.concat(chunks).toString() }); }
    });
  });
}

// 1: reset — expect ECONNRESET with zero bytes
const r1 = await rawRequest(proxy.port);
check("reset", r1.outcome === "error:ECONNRESET" && r1.bytes === 0, JSON.stringify(r1));

// 2: black-hole — expect timeout with zero bytes
const r2 = await rawRequest(proxy.port, { timeoutMs: 800 });
check("black-hole", r2.outcome === "timeout" && r2.bytes === 0, JSON.stringify(r2));

// 3: cut-after 50 — expect exactly 50 bytes then reset/close
const r3 = await rawRequest(proxy.port);
check("cut-after", (r3.outcome === "error:ECONNRESET" || r3.outcome === "closed") && r3.bytes === 50, JSON.stringify({ outcome: r3.outcome, bytes: r3.bytes }));

// 4: delay 400ms — expect full response, first byte >= ~380ms after request
const t0 = Date.now();
const r4 = await rawRequest(proxy.port, { timeoutMs: 3000 });
const elapsed = Date.now() - t0;
check("delay", r4.outcome === "closed" && r4.data.endsWith(BODY) && elapsed >= 380, JSON.stringify({ outcome: r4.outcome, elapsed }));

// 5: pass-through — full clean response, fast
const r5 = await rawRequest(proxy.port);
check("pass-through", r5.outcome === "closed" && r5.data.endsWith(BODY), JSON.stringify({ outcome: r5.outcome, bytes: r5.bytes }));

// report() must show applied flags for 1-4 and pass-through for 5
const rep = proxy.report();
const repOk =
  rep.length === 5 &&
  rep[0].action === "reset" && rep[0].applied &&
  rep[1].action === "black-hole" && rep[1].applied &&
  rep[2].action === "cut-after" && rep[2].applied &&
  rep[3].action === "delay" && rep[3].applied &&
  rep[4].action === "pass-through" && !rep[4].applied;
check("report", repOk, JSON.stringify(rep));

// schedule validation rejections
let rejects = 0;
for (const bad of [
  [{ connection: 0, action: "reset" }],
  [{ connection: 1, action: "reset" }, { connection: 1, action: "delay", ms: 5 }],
  [{ connection: 1, action: "cut-after" }],
  [{ connection: 1, action: "frobnicate" }],
  "not-an-array",
]) {
  try { await startFaultProxy({ upstreamPort, schedule: bad }); }
  catch { rejects += 1; }
}
check("schedule-validation", rejects === 5, `${rejects}/5 rejected`);

await proxy.close();
upstream.close();
const failed = results.filter((r) => !r.ok);
console.log(failed.length === 0 ? "SMOKE: ALL PASS" : `SMOKE: ${failed.length} FAILURES`);
process.exit(failed.length === 0 ? 0 : 1);
