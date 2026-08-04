from anthropic import Anthropic

client = Anthropic()


def summarize(record):
    return client.messages.create(
        model="claude-3-5-sonnet",
        messages=[{"role": "user", "content": record}],
    )
