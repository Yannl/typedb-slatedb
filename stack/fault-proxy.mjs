// Deterministic TCP fault proxy for the native-fidelity lane (round-4
// §6.6 step 7 / R4-STACK-03 groundwork).
//
// Sits between a client (TypeDB/SlateDB object_store, the remote-WAL
// client, a test driver) and a loopback upstream (MinIO/RustFS, workerd)
// and injects EXACTLY the faults a schedule names — never random ones:
//
//   { connection: N, action: "reset" }         RST the Nth connection at accept
//   { connection: N, action: "black-hole" }    accept, read, never respond
//   { connection: N, action: "cut-after", bytes: B }
//                                              forward B upstream bytes of the
//                                              response, then cut (the
//                                              timeout-after-commit /
//                                              torn-response shape)
//   { connection: N, action: "delay", ms: M }  hold the first upstream byte M ms
//
// Connections are counted from 1 in accept order; unlisted connections
// pass through untouched. The schedule is immutable after start — a
// deterministic run is replayable by its schedule alone, which is what
// makes a fault result EVIDENCE instead of an anecdote.
//
// Loopback-only by construction: both listen and upstream addresses must
// be 127.0.0.1 (a fault proxy must never be able to sit in front of a
// real remote service).
//
// Usage (library):
//   const proxy = await startFaultProxy({ upstreamPort, schedule: [...] });
//   ... point the client at proxy.port ...
//   proxy.report()  -> per-connection {applied, action} log (evidence)
//   await proxy.close();
//
// CLI (manual experiments):
//   node fault-proxy.mjs <listenPort> <upstreamPort> '<schedule JSON>'

import net from "node:net";
import { setTimeout as delay } from "node:timers/promises";

const LOOPBACK = "127.0.0.1";

function validateSchedule(schedule) {
  if (!Array.isArray(schedule)) throw new Error("fault schedule must be an array");
  const seen = new Set();
  for (const entry of schedule) {
    if (!Number.isInteger(entry.connection) || entry.connection < 1) {
      throw new Error(`fault entry needs a 1-based connection ordinal: ${JSON.stringify(entry)}`);
    }
    if (seen.has(entry.connection)) {
      throw new Error(`duplicate fault for connection ${entry.connection} — a deterministic schedule names each connection once`);
    }
    seen.add(entry.connection);
    const action = entry.action;
    if (action === "cut-after") {
      if (!Number.isInteger(entry.bytes) || entry.bytes < 0) throw new Error("cut-after needs bytes >= 0");
    } else if (action === "delay") {
      if (!Number.isInteger(entry.ms) || entry.ms <= 0) throw new Error("delay needs ms > 0");
    } else if (action !== "reset" && action !== "black-hole") {
      throw new Error(`unknown fault action ${JSON.stringify(action)}`);
    }
  }
  return schedule.map((e) => Object.freeze({ ...e }));
}

export async function startFaultProxy({ upstreamPort, listenPort = 0, schedule = [] }) {
  const plan = new Map(validateSchedule(schedule).map((e) => [e.connection, e]));
  const report = [];
  let ordinal = 0;

  const server = net.createServer((client) => {
    ordinal += 1;
    const n = ordinal;
    const fault = plan.get(n) ?? null;
    const entry = { connection: n, action: fault?.action ?? "pass-through", applied: false };
    report.push(entry);

    if (fault?.action === "reset") {
      entry.applied = true;
      client.resetAndDestroy();
      return;
    }
    if (fault?.action === "black-hole") {
      entry.applied = true;
      client.on("data", () => {}); // swallow the request, answer nothing
      client.on("error", () => {});
      return;
    }

    const upstream = net.connect(upstreamPort, LOOPBACK);
    client.on("error", () => upstream.destroy());
    upstream.on("error", () => client.destroy());
    client.pipe(upstream);

    if (fault?.action === "cut-after") {
      entry.applied = true;
      let forwarded = 0;
      upstream.on("data", (chunk) => {
        const remaining = fault.bytes - forwarded;
        if (remaining <= 0) {
          client.resetAndDestroy();
          upstream.destroy();
          return;
        }
        const slice = chunk.subarray(0, Math.min(chunk.length, remaining));
        forwarded += slice.length;
        client.write(slice);
        if (forwarded >= fault.bytes) {
          client.resetAndDestroy();
          upstream.destroy();
        }
      });
      upstream.on("end", () => client.end());
      return;
    }
    if (fault?.action === "delay") {
      entry.applied = true;
      // Hold the response until the timer fires; the upstream may END
      // before the hold elapses, so the client-side end must wait for
      // the flush (otherwise the fault degenerates into an empty close).
      let held = true;
      let upstreamEnded = false;
      const buffered = [];
      const flush = () => {
        held = false;
        for (const b of buffered.splice(0)) client.write(b);
        if (upstreamEnded) client.end();
      };
      upstream.on("data", (chunk) => {
        if (held) {
          buffered.push(chunk);
          if (buffered.length === 1) delay(fault.ms).then(flush);
          return;
        }
        client.write(chunk);
      });
      upstream.on("end", () => {
        upstreamEnded = true;
        if (!held) client.end();
      });
      return;
    }
    upstream.pipe(client);
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(listenPort, LOOPBACK, resolve);
  });
  const port = server.address().port;
  return {
    port,
    report: () => report.map((r) => ({ ...r })),
    close: () =>
      new Promise((resolve) => {
        server.close(() => resolve());
      }),
  };
}

// CLI
import { fileURLToPath } from "node:url";
import path from "node:path";
const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  const [listen, upstream, scheduleJson] = process.argv.slice(2);
  if (!listen || !upstream) {
    console.error("usage: node fault-proxy.mjs <listenPort> <upstreamPort> '<schedule JSON>'");
    process.exit(2);
  }
  const proxy = await startFaultProxy({
    listenPort: Number(listen),
    upstreamPort: Number(upstream),
    schedule: scheduleJson ? JSON.parse(scheduleJson) : [],
  });
  console.log(`fault-proxy: 127.0.0.1:${proxy.port} -> 127.0.0.1:${upstream}`);
}
