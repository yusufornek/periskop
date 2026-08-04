"""Known gap: the method name is not in the syntax tree.

Static analysis cannot resolve `action` without executing the program. The call is
invisible to the scanner, which is why runtime instrumentation exists as a second
source rather than as a nicety.

Catalogued as KG-001 in the known gaps list.
"""

from openai import OpenAI

client = OpenAI()


def summarize(record, action="create"):
    target = getattr(client.chat.completions, action)
    return target(model="gpt-4", messages=[{"role": "user", "content": record}])
