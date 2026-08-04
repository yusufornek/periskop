from openai import OpenAI

client = OpenAI()


def summarize(record):
    return client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": record}],
    )
