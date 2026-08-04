import OpenAI from "openai";

const client = new OpenAI();

export async function Summary({ record }: { record: string }) {
  const reply = await client.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: record }],
  });
  return <div>{reply.choices[0].message.content}</div>;
}
