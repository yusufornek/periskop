import assert from "node:assert/strict";
import test from "node:test";

import { pathTemplate } from "./path-template";

test("a plain endpoint path is left as it is", () => {
  assert.equal(pathTemplate("/v1/chat/completions"), "/v1/chat/completions");
  assert.equal(pathTemplate("/v1/messages"), "/v1/messages");
});

test("the query string is removed whole", () => {
  // It is the part of a URL most likely to carry a value and the part least
  // likely to identify an endpoint.
  assert.equal(pathTemplate("/v1/models?key=AIzaSyDsecret"), "/v1/models");
  assert.equal(pathTemplate("/search?q=patient+records"), "/search");
});

test("identifiers in the path become a placeholder, so two calls compare equal", () => {
  assert.equal(pathTemplate("/v1/threads/12345/messages"), "/v1/threads/{id}/messages");
  assert.equal(
    pathTemplate("/v1/files/550e8400-e29b-41d4-a716-446655440000"),
    "/v1/files/{id}",
  );
  assert.equal(pathTemplate("/v1/assistants/asst_abc123XYZ890"), "/v1/assistants/{id}");
});

test("an empty or missing path becomes root", () => {
  assert.equal(pathTemplate(undefined), "/");
  assert.equal(pathTemplate(""), "/");
  assert.equal(pathTemplate("?a=b"), "/");
});

test("a version segment is not mistaken for an identifier", () => {
  assert.equal(pathTemplate("/v1/embeddings"), "/v1/embeddings");
  assert.equal(pathTemplate("/api/v2/chat"), "/api/v2/chat");
});
