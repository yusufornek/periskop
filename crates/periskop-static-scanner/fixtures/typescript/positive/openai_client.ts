import OpenAI from "openai";

const client = new OpenAI();

export async function summarize(record: string) {
  return client.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: record }],
  });
}
