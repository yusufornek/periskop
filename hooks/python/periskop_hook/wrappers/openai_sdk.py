"""OpenAI python SDK.

The table names the v1 resource classes. Both the sync and async pairs are
listed because they are separate classes rather than one class with two entry
points, and a version that ships only some of them loses only those rows.

Path templates are written here rather than read from the SDK: they are the
documented endpoints of the API, and the alternative would be to inspect private
attributes that change between releases.
"""

from . import sdk_client

MODULE = "openai"

ENTRIES = (
    ("resources.chat.completions.Completions.create",
     "chat.completions.create", "/v1/chat/completions"),
    ("resources.chat.completions.AsyncCompletions.create",
     "chat.completions.create", "/v1/chat/completions"),
    ("resources.responses.Responses.create",
     "responses.create", "/v1/responses"),
    ("resources.responses.AsyncResponses.create",
     "responses.create", "/v1/responses"),
    ("resources.embeddings.Embeddings.create",
     "embeddings.create", "/v1/embeddings"),
    ("resources.embeddings.AsyncEmbeddings.create",
     "embeddings.create", "/v1/embeddings"),
)


def install(module):
    return sdk_client.install(module, MODULE, ENTRIES)
