#!/usr/bin/env node
// periskop MCP server.
//
// Exposes the scanner to an editor. The server holds no analysis of its own: it
// starts the engine, forwards requests and shapes the answers for a reader with
// a limited context window.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { EngineBridge } from "./bridge.js";
import { traceInput, traceReconciliation } from "./reconciliation.js";
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
        "A result with no findings is not the same as a project with no egress; read the coverage block. " +
        "summary.reconciliation_mode says which sources fed the run, and every count is only as " +
        "strong as that; summary.unmatched_wire_traffic counts findings where data left the machine " +
        "and no code explains it, and is null when the findings do not state their kind. " +
        "Confirmed and suspected findings are two separate lists and are never merged: one call " +
        "pages one of them, filter.confidence chooses which, and page.other says how many " +
        "are in the other. summary.by_provider counts findings per provider and keeps that " +
        "same split, so a provider seen only in suspected findings is still named. " +
        "On a project with no runtime hooks installed the unmatched wire " +
        "findings are suspected, so a caller that never asks for that list never sees them.",
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
        "layers were running. Answers whether a clean scan means clean or means unread. " +
        "network_sensor is one of running, not running or unknown, and the third means the " +
        "report did not say rather than that nothing was watching. flow_buckets counts the " +
        "observed flows that produced no finding, next to in_scope_flows, the count they are " +
        "read against; a bucket without that denominator states no proportion, and none of " +
        "them is readable away from the sensor state.",
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

  server.registerTool(
    "trace_reconciliation",
    {
      title: "Where a derived finding came from",
      description:
        "Returns the join steps, the contributing sources and the difference behind a finding " +
        "whose source is reconciled. Use when a finding says the code and the run disagree and " +
        "you need to see what tied the two together. Declared and observed findings have no " +
        "reconciliation trace; get_finding_detail is what covers those.",
      inputSchema: traceInput.shape,
    },
    async (args) => ({
      content: [
        {
          type: "text",
          text: JSON.stringify(
            await traceReconciliation(bridge, traceInput.parse(args)),
            null,
            2,
          ),
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
