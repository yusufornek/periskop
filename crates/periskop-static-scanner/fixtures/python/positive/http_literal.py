import requests


def summarize(record, token):
    return requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "gpt-4", "messages": [{"role": "user", "content": record}]},
    )
