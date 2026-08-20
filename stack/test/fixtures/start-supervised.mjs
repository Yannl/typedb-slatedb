// Fixture: start a supervised child in ONE process invocation, print the
// record, and exit. A second, completely separate invocation is expected to
// stop it. This is the exact agent workflow R6-LOCAL-02 says is broken
// today, so the test drives it across a real process boundary rather than
// simulating it in-process.
//
//   node start-supervised.mjs <runDir> <port>

import net from "node:net";
import path from "node:path";
import { writeFileAtomic } from "../../minio.mjs";
import { startSupervised } from "../../supervisor.mjs";

const [runDir, portArg] = process.argv.slice(2);
const port = Number(portArg);

const readiness = () =>
  new Promise((resolve, reject) => {
    const c = net.connect({ port, host: "127.0.0.1" });
    const t = setTimeout(() => {
      c.destroy();
      reject(new Error("timeout"));
    }, 1000);
    c.on("error", (e) => {
      clearTimeout(t);
      reject(e);
    });
    c.on("data", (d) => {
      clearTimeout(t);
      c.destroy();
      d.toString().includes("ok") ? resolve() : reject(new Error("bad banner"));
    });
  });

const { record } = await startSupervised({
  runDir,
  component: "fixture",
  command: process.execPath,
  args: [
    "-e",
    `const net=require("node:net");net.createServer(c=>c.end("ok\\n")).listen(${port},"127.0.0.1");setInterval(()=>{},1<<30);`,
  ],
  env: { PATH: process.env.PATH },
  readiness,
  readyTimeoutMs: 20_000,
  port,
});

writeFileAtomic(path.join(runDir, "record.json"), `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify(record));
process.exit(0);
