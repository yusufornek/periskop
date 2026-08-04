#!/usr/bin/env node
// periskop MCP server.
//
// Exposes the scanner to an editor. The server holds no analysis of its own: it
// starts the engine, forwards requests and shapes the answers for a reader with
// a limited context window.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { EngineBridge } from "./bridge.js";
import {
  coverageInput,
  detailInput,
  getCoverage,
  getDetail,
  runScan,
  scanInput,
} from "./tools.js";

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

  server.registerTool(
    "scan_project",
    {
      title: "Scan a project for model provider egress",
      description:
        "Walks a project and reports call sites that send data to an LLM provider. " +
        "Returns a summary with a first page of findings, plus what the scan could not read. " +
        "A result with no findings is not the same as a project with no egress; read the coverage block.",
      inputSchema: scanInput.shape,
    },
    async (args) => ({
      content: [
        { type: "text", text: JSON.stringify(await runScan(bridge, scanInput.parse(args)), null, 2) },
      ],
    }),
  );

  server.registerTool(
    "get_finding_detail",
    {
      title: "Full record for one finding",
      description:
        "Returns the complete finding, including its evidence and the rule that produced it. " +
        "Use after scan_project, with an identifier from that result.",
      inputSchema: detailInput.shape,
    },
    async (args) => ({
      content: [
        {
          type: "text",
          text: JSON.stringify(await getDetail(bridge, detailInput.parse(args)), null, 2),
        },
      ],
    }),
  );

  server.registerTool(
    "get_coverage_report",
    {
      title: "What the scan could not see",
      description:
        "Files that could not be read, libraries with no detector, and which observation " +
        "layers were running. Answers whether a clean scan means clean or means unread.",
      inputSchema: coverageInput.shape,
    },
    async (args) => ({
      content: [
        {
          type: "text",
          text: JSON.stringify(await getCoverage(bridge, coverageInput.parse(args)), null, 2),
        },
      ],
    }),
  );

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
