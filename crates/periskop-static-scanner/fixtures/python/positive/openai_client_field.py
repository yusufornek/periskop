"""The client kept in an instance field rather than a module level name.

This is how the same call is written once it lives in a class, which is to say
most of the time. The import and the constructor are one step apart from the call
site, and a resolver that only followed plain assignments reported nothing here.
"""

from openai import OpenAI


class Summarizer:
    def __init__(self):
        self.client = OpenAI()

    def summarize(self, record):
        return self.client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": record}],
        )
