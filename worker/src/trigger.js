// Pipeline trigger: this worker's cron is reliable, GitHub's schedule
// is not (it missed most ticks on 2026-11-04) — so every ~30 minutes the
// worker itself asks GitHub to run the pipeline via workflow_dispatch.
// Needs env.GH_DISPATCH_TOKEN (fine-grained PAT: this repo only,
// Actions read/write). Without the secret this is a silent no-op.
// Attempts are stamped in KV (dispatch:last) BEFORE calling out, so a
// bad token or a GitHub outage can never turn the */5 cron into a
// hammer; the cadence self-limits to one attempt per ~30 minutes.
const DISPATCH_URL =
  "https://api.github.com/repos/ILIV007/Proxiv3/actions/workflows/pipeline.yml/dispatches";
const CADENCE_S = 30 * 60;

export function shouldDispatch(nowUnix, lastUnix) {
  return !lastUnix || nowUnix - lastUnix >= CADENCE_S - 60;
}

export async function maybeDispatchPipeline(env, now = Date.now()) {
  if (!env.GH_DISPATCH_TOKEN) return "no-token";
  const nowUnix = Math.floor(now / 1000);
  const last = Number(await env.POOL.get("dispatch:last")) || 0;
  if (!shouldDispatch(nowUnix, last)) return "throttled";
  await env.POOL.put("dispatch:last", String(nowUnix));
  const res = await fetch(DISPATCH_URL, {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.GH_DISPATCH_TOKEN}`,
      accept: "application/vnd.github+json",
      "user-agent": "proxiv3-worker",
      "content-type": "application/json",
    },
    body: JSON.stringify({ ref: "main", inputs: { rounds: "3" } }),
  });
  return res.status === 204 ? "dispatched" : `http-${res.status}`;
}
