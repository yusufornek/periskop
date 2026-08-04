import assert from "node:assert/strict";
import test from "node:test";

import { classifyHost, UNKNOWN_PROVIDER } from "./provider-ref";

test("known provider hosts are classified", () => {
  assert.equal(classifyHost("api.openai.com"), "openai");
  assert.equal(classifyHost("api.anthropic.com"), "anthropic");
  assert.equal(classifyHost("generativelanguage.googleapis.com"), "google-gemini");
  assert.equal(classifyHost("contoso.openai.azure.com"), "azure-openai");
  assert.equal(classifyHost("us-central1-aiplatform.googleapis.com"), "google-vertex");
  assert.equal(classifyHost("bedrock-runtime.eu-west-1.amazonaws.com"), "aws-bedrock");
  assert.equal(classifyHost("my-index.pinecone.io"), "pinecone");
});

test("classification is case insensitive, because a host name is", () => {
  assert.equal(classifyHost("API.OpenAI.COM"), "openai");
});

test("an unclassified host is recorded as unknown, never dropped", () => {
  // The inverse-list principle: an internal gateway proxying a model is exactly
  // the call that a known-providers-only list would lose.
  assert.equal(classifyHost("llm-gateway.internal.corp"), UNKNOWN_PROVIDER);
  assert.equal(classifyHost("127.0.0.1"), UNKNOWN_PROVIDER);
  assert.equal(classifyHost(undefined), UNKNOWN_PROVIDER);
  assert.equal(classifyHost(""), UNKNOWN_PROVIDER);
});

test("a host that merely ends in a provider name is not that provider", () => {
  assert.equal(classifyHost("notapi.openai.com.evil.test"), UNKNOWN_PROVIDER);
  assert.equal(classifyHost("bedrock-runtime.amazonaws.com.attacker.test"), UNKNOWN_PROVIDER);
});

test("every classification matches the pattern the schema allows", () => {
  const hosts = [
    "api.openai.com",
    "api.anthropic.com",
    "contoso.openai.azure.com",
    "bedrock-runtime.eu-west-1.amazonaws.com",
    "anything.else",
  ];
  for (const host of hosts) assert.match(classifyHost(host), /^[a-z0-9][a-z0-9-]*$/);
});
