export async function summarize(record: string, token: string) {
  return fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify({ model: "gpt-4", messages: [{ content: record }] }),
  });
}
