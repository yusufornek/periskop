// Known gap: the destination is assembled at runtime.
export async function summarize(record: string) {
  const endpoint = `${process.env.MODEL_ENDPOINT}/v1/chat/completions`;
  return fetch(endpoint, { method: "POST", body: JSON.stringify({ record }) });
}
