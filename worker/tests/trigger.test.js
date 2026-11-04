import { test } from "node:test";
import assert from "node:assert/strict";
import { shouldDispatch, maybeDispatchPipeline } from "../src/trigger.js";

test("shouldDispatch: first run and cadence", () => {
  const now = 1_000_000;
  assert.equal(shouldDispatch(now, 0), true);
  assert.equal(shouldDispatch(now, null), true);
  assert.equal(shouldDispatch(now, now - 10 * 60), false);
  assert.equal(shouldDispatch(now, now - 29 * 60), true);
  assert.equal(shouldDispatch(now, now - 31 * 60), true);
});

function stubEnv({ token = "t", last = null } = {}) {
  const store = new Map(last === null ? [] : [["dispatch:last", String(last)]]);
  return {
    store,
    env: {
      GH_DISPATCH_TOKEN: token,
      POOL: {
        get: async (k) => store.get(k) ?? null,
        put: async (k, v) => store.set(k, v),
      },
    },
  };
}

test("maybeDispatchPipeline: no token is a silent no-op (KV untouched)", async () => {
  const { env, store } = stubEnv({ token: "" });
  assert.equal(await maybeDispatchPipeline(env, 1_000_000_000), "no-token");
  assert.equal(store.size, 0);
});

test("maybeDispatchPipeline: throttled inside the cadence", async () => {
  const now = 1_000_000_000;
  const { env } = stubEnv({ last: Math.floor(now / 1000) - 600 });
  assert.equal(await maybeDispatchPipeline(env, now), "throttled");
});

test("maybeDispatchPipeline: dispatches on 204 and stamps the attempt", async () => {
  const realFetch = globalThis.fetch;
  let called = null;
  globalThis.fetch = async (url, opts) => {
    called = { url, opts };
    return { status: 204 };
  };
  try {
    const now = 1_000_000_000;
    const { env, store } = stubEnv({});
    assert.equal(await maybeDispatchPipeline(env, now), "dispatched");
    assert.match(called.url, /actions\/workflows\/pipeline\.yml\/dispatches$/);
    assert.equal(called.opts.headers.authorization, "Bearer t");
    assert.equal(JSON.parse(called.opts.body).ref, "main");
    assert.equal(store.get("dispatch:last"), String(Math.floor(now / 1000)));
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("maybeDispatchPipeline: http error is reported, attempt still stamped", async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ status: 401 });
  try {
    const now = 1_000_000_000;
    const { env, store } = stubEnv({});
    assert.equal(await maybeDispatchPipeline(env, now), "http-401");
    assert.equal(store.get("dispatch:last"), String(Math.floor(now / 1000)));
  } finally {
    globalThis.fetch = realFetch;
  }
});
