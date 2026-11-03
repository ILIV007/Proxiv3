// Minimal Telegram Bot API client. Every call has a timeout — a hung
// Telegram request must never stall the worker (lesson from AI-admin).

export async function tgApi(env, method, payload = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 15000);
  try {
    const res = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || !data?.ok) {
      console.error(`tgApi ${method} failed`, res.status, data?.description ?? "");
      return null;
    }
    return data.result;
  } catch (e) {
    console.error(`tgApi ${method} error`, e.name === "AbortError" ? "timeout" : e.message);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export const sendMessage = (env, chat_id, text, extra = {}) =>
  tgApi(env, "sendMessage", { chat_id, text, parse_mode: "HTML", disable_web_page_preview: true, ...extra });
export const editMessageText = (env, chat_id, message_id, text, extra = {}) =>
  tgApi(env, "editMessageText", { chat_id, message_id, text, parse_mode: "HTML", disable_web_page_preview: true, ...extra });
export const answerCallback = (env, id, text = "", alert = false) =>
  tgApi(env, "answerCallbackQuery", { callback_query_id: id, text, show_alert: alert });
