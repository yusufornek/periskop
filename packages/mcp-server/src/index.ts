#!/usr/bin/env node
// periskop MCP server.
//
// Exposes the scanner to an editor. The server holds no analysis of its own: it
// starts the engine, forwards requests and shapes the answers for a reader with
// a limited context window.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { EngineBridge } from "./bridge.js";
import { TOOLS } from "./registry.js";

/**
 * Locates the engine binary.
 *
 * Nothing is downloaded at run time. A tool whose purpose is telling you where
 * your data goes cannot itself reach out to the network on startup, so the
 * binary is expected to be installed alongside the package or named explicitly.
 */
function resolveBinary(): string {
  return process.env["PERISKOP_BINARY"] ?? "periskop";
}

async function main(): Promise<void> {
  const bridge = new EngineBridge({
    binary: resolveBinary(),
    ...(process.env["PERISKOP_RULES"] ? { rulesDir: process.env["PERISKOP_RULES"] } : {}),
  });

  const server = new McpServer({ name: "periskop", version: "0.1.0" });

  // Registration reads the list rather than repeating it. What is served and
  // what `schemas/mcp-tools.schema.json` checks are then the same array, so a
  // tool cannot reach a caller without also reaching the gate.
  for (const tool of TOOLS) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema.shape,
      },
      async (args) => ({
        content: [{ type: "text", text: JSON.stringify(await tool.run(bridge, args), null, 2) }],
      }),
    );
  }

  const shutdown = async (): Promise<void> => {
    await bridge.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());

  await server.connect(new StdioServerTransport());
}

main().catch((error: unknown) => {
  process.stderr.write(`periskop-mcp: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
