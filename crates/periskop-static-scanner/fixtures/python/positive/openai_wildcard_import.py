# A star import, which binds no name the file writes down.
#
# `from openai import *` used to fall through every branch of the import
# collector: the module was recorded for coverage, so a rule claimed it and it
# stayed out of `undetected_libraries`, while `OpenAI` resolved to nothing and no
# finding was produced. Neither detected nor declared, which is the one outcome
# this scanner is not allowed to have.
#
# The finding is `suspect` rather than `confirmed` on purpose. The file says a
# name arrived from somewhere in `openai`; it does not say this name did, and a
# class defined further down would satisfy the same reading.
from openai import *

client = OpenAI()


def summarize(text):
    return client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": text}],
    )
