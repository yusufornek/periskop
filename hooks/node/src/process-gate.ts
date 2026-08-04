// Whether this process is one we were meant to observe.
//
// NODE_OPTIONS spreads down the whole process tree. Set it once for a service
// and every npm, npx and tsc that service ever spawns inherits the hook too.
// ADR-009 lists this as a known cost of environment based installation and asks
// for a list that keeps the hook out of processes nobody wanted instrumented.
//
// The decision is deliberately made from three cheap reads: an environment
// variable, the runtime version and the basename of argv[1]. Nothing here loads
// another module, so a process that is not a target pays a handful of string
// comparisons and then nothing at all.

import { basename, extname } from "node:path";

import type { DisableReason } from "./hook-status";

export type GateDecision =
  | { readonly instrument: true }
  | { readonly instrument: false; readonly reason: DisableReason };

/** Node versions below this lack the APIs the patches are written against. */
const MINIMUM_NODE_MAJOR = 20;

// Package managers and build tools. Kept tight on purpose: this list is the one
// place where the inverse-list principle is suspended, and every name added to
// it is a class of egress the hook agrees not to see.
const NON_TARGET_ENTRYPOINTS: ReadonlySet<string> = new Set([
  "npm",
  "npm-cli",
  "npx",
  "npx-cli",
  "pnpm",
  "pnpx",
  "yarn",
  "yarnpkg",
  "corepack",
  "tsc",
  "tsserver",
  "node-gyp",
  "node-pre-gyp",
  "prebuild-install",
]);

/** argv[1] without directory or extension, which is how a script names itself. */
export function entrypointName(argv: readonly string[]): string {
  const script = argv[1];
  if (script === undefined || script.length === 0) return "node";
  const name = basename(script, extname(script));
  return name.length === 0 ? "node" : name;
}

export function isNonTargetEntrypoint(argv: readonly string[]): boolean {
  return NON_TARGET_ENTRYPOINTS.has(entrypointName(argv));
}

function majorVersion(nodeVersion: string): number {
  const major = Number.parseInt(nodeVersion.replace(/^v/, ""), 10);
  return Number.isNaN(major) ? 0 : major;
}

export function decideInstrumentation(
  env: NodeJS.ProcessEnv,
  argv: readonly string[],
  nodeVersion: string,
): GateDecision {
  // The off switch is checked first so that setting it costs one lookup and
  // reaches every later decision, including the ones that would report a status.
  if (env["PERISKOP_HOOK"] === "0") return { instrument: false, reason: "disabled_by_env" };
  if (majorVersion(nodeVersion) < MINIMUM_NODE_MAJOR) {
    return { instrument: false, reason: "unsupported_runtime" };
  }
  if (isNonTargetEntrypoint(argv)) return { instrument: false, reason: "non_target_process" };
  return { instrument: true };
}
