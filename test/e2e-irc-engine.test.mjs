// E2E: OVH → k3s SigNoz log centralization.
//
// Proves the full path an ircfiber-engine-ovh log record takes:
//   OTLP/HTTP POST → Tailscale VIP svc:otel-collector (otel-collector.tail544547.ts.net:4319)
//   → signoz-otel-collector receiver otlp/ovh → pipeline logs/ovh → clickhouselogsexporter
//   → ClickHouse signoz_logs.distributed_logs_v2 (+ SigNoz query API v5).
//
// Run:  node --test engine/test/e2e-irc-engine.test.mjs
// Env:  OTLP_LOGS_URL   (default http://otel-collector.tail544547.ts.net:4319/v1/logs)
//       KUBE_CONTEXT    (default ubuntu-docker)
//       SIGNOZ_URL      (default https://signoz.ubuntu-docker.tail544547.ts.net)
//       SIGNOZ_EMAIL / SIGNOZ_PASSWORD / SIGNOZ_ORG_ID (query-API assertion; skipped when unset)
// Needs: tailnet access (ACL autogroup:member -> svc:otel-collector), kubectl context ubuntu-docker.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

const OTLP_LOGS_URL = process.env.OTLP_LOGS_URL ?? "http://otel-collector.tail544547.ts.net:4319/v1/logs";
const KUBE_CONTEXT = process.env.KUBE_CONTEXT ?? "ubuntu-docker";
const SIGNOZ_URL = process.env.SIGNOZ_URL ?? "https://signoz.ubuntu-docker.tail544547.ts.net";
const CH_POD = "chi-signoz-clickhouse-cluster-0-0-0";

const SERVICE = "ircfiber-engine-ovh";
const CLUSTER = "ovh-prod";
const NETWORK = "irc.rizon.net";
const CHANNEL = "#superbowl";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function clickhouse(query) {
  return execFileSync(
    "kubectl",
    ["--context", KUBE_CONTEXT, "exec", "-n", "signoz", "-c", "clickhouse", CH_POD, "--", "clickhouse-client", "--query", query],
    { encoding: "utf8", timeout: 60_000 },
  ).trim();
}

function otlpPayload(body, tsNano) {
  const str = (v) => ({ stringValue: v });
  return {
    resourceLogs: [
      {
        resource: {
          attributes: [
            { key: "service.name", value: str(SERVICE) },
            { key: "k8s.cluster.name", value: str(CLUSTER) },
            { key: "host.name", value: str(CLUSTER) },
          ],
        },
        scopeLogs: [
          {
            scope: { name: "ircfiber.logging", version: "0.3.0" },
            logRecords: [
              {
                timeUnixNano: tsNano,
                severityText: "INFO",
                severityNumber: 9,
                attributes: [
                  { key: "network", value: str(NETWORK) },
                  { key: "channel", value: str(CHANNEL) },
                  { key: "event", value: str("join") },
                ],
                body: str(body),
              },
            ],
          },
        ],
      },
    ],
  };
}

test("OVH-style engine log lands in ClickHouse with resource + attributes intact", async () => {
  const marker = `E2E_${Date.now()}_RIZON_JOIN_TEST`;
  const body = `${marker} ${CHANNEL} ${NETWORK} FULL CONN`;
  const tsNano = String(BigInt(Date.now()) * 1_000_000n);

  const res = await fetch(OTLP_LOGS_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(otlpPayload(body, tsNano)),
    signal: AbortSignal.timeout(10_000),
  });
  assert.equal(res.status, 200, `OTLP POST ${OTLP_LOGS_URL} → ${res.status}`);
  assert.deepEqual(await res.json(), { partialSuccess: {} });

  // batch processor timeout is 5s; poll up to 30s.
  let row = "";
  for (let i = 0; i < 15 && !row; i++) {
    await sleep(2000);
    row = clickhouse(
      `SELECT body, resources_string['service.name'], resources_string['k8s.cluster.name'], ` +
        `attributes_string['network'], attributes_string['channel'], severity_text ` +
        `FROM signoz_logs.distributed_logs_v2 WHERE position(body, '${marker}') > 0 LIMIT 1 FORMAT TSV`,
    );
  }
  assert.ok(row, `no row with ${marker} in signoz_logs.distributed_logs_v2 after 30s`);
  const [gotBody, svc, cluster, network, channel, sev] = row.split("\t");
  assert.equal(gotBody, body);
  assert.equal(svc, SERVICE, "resource service.name must survive the logs/ovh pipeline");
  assert.equal(cluster, CLUSTER, "resource k8s.cluster.name must not be rewritten to ubuntu-docker");
  assert.equal(network, NETWORK);
  assert.equal(channel, CHANNEL);
  assert.equal(sev, "INFO");

  const maxTs = BigInt(clickhouse("SELECT max(timestamp) FROM signoz_logs.distributed_logs_v2 FORMAT TSV"));
  assert.ok(maxTs >= BigInt(tsNano), "max(timestamp) must have advanced to the E2E record");
});

// Real engine traffic (not the synthetic E2E_ rows): the OVH engine's own OTLP
// logs for https://ircfiber.com/irc/Supernets/channel/superbowl and
// https://ircfiber.com/irc/irc.rizon.net, shipped through the same VIP path.
function liveCount(where) {
  return Number(
    clickhouse(
      `SELECT count() FROM signoz_logs.distributed_logs_v2 ` +
        `WHERE resources_string['service.name'] = '${SERVICE}' AND resources_string['k8s.cluster.name'] = '${CLUSTER}' ` +
        `AND position(body, 'E2E_') = 0 AND timestamp > toUnixTimestamp64Nano(now64(9)) - 86400000000000 AND ${where} FORMAT TSV`,
    ),
  );
}

test("live ircfiber-engine-ovh JOIN for Supernets #superbowl is queryable", () => {
  const n = liveCount(`attributes_string['network'] = 'Supernets' AND attributes_string['channel'] = '${CHANNEL}' AND attributes_string['event'] = 'join'`);
  assert.ok(n > 0, `expected a self JOIN log for Supernets ${CHANNEL} in the last 24h, got ${n}`);
});

test("live ircfiber-engine-ovh connection logs for irc.rizon.net are queryable", () => {
  const n = liveCount(`attributes_string['network'] = '${NETWORK}' AND attributes_string['component'] IN ('connection', 'protocol')`);
  assert.ok(n > 0, `expected connection/protocol logs for ${NETWORK} in the last 24h, got ${n}`);
});

test("SigNoz query API (v5) returns ircfiber-engine-ovh #superbowl logs", { skip: !process.env.SIGNOZ_PASSWORD }, async () => {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // traefik default cert on the tailnet
  const login = await fetch(`${SIGNOZ_URL}/api/v2/sessions/email_password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: process.env.SIGNOZ_EMAIL ?? "kevindpostal@gmail.com",
      password: process.env.SIGNOZ_PASSWORD,
      orgId: process.env.SIGNOZ_ORG_ID ?? "01a038b5-9d35-71ee-b9cd-05d96221a804",
    }),
  });
  assert.equal(login.status, 200, "SigNoz login");
  const token = (await login.json()).data.accessToken;

  const now = Date.now();
  const q = {
    schemaVersion: "v1",
    start: now - 24 * 3600_000,
    end: now,
    requestType: "raw",
    compositeQuery: {
      queries: [
        {
          type: "builder_query",
          spec: {
            name: "A",
            signal: "logs",
            limit: 5,
            order: [{ key: { name: "timestamp" }, direction: "desc" }],
            filter: { expression: `service.name = '${SERVICE}' AND channel = '${CHANNEL}'` },
          },
        },
      ],
    },
  };
  const resp = await fetch(`${SIGNOZ_URL}/api/v5/query_range`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(q),
  });
  assert.equal(resp.status, 200, `query_range → ${resp.status}`);
  const data = await resp.json();
  const rows = data?.data?.data?.results?.[0]?.rows ?? [];
  assert.ok(rows.length > 0, "SigNoz query API returned no rows");
  for (const r of rows) {
    assert.equal(r.data?.resources_string?.["service.name"] ?? r.data?.resource?.["service.name"], SERVICE);
  }
});
