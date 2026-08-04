const OpenAI = require("openai");

const client = new OpenAI();

async function summarize(record) {
  return client.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: record }],
  });
}

module.exports = { summarize };
