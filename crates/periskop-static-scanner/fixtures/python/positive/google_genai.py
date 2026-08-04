from google import genai

client = genai.Client()


def summarize(record):
    return client.models.generate_content(model="gemini-2.0-flash", contents=record)
