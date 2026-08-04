// The contract gate.
//
// `schemas/mcp-tools.schema.json` states what this server's tool surface is.
// This program derives what the surface actually is, from the registrations and
// the handlers, and validates one against the other. It exits non zero when they
// disagree.
//
// It is a program rather than a test case on purpose. `npm test` runs a glob, and
// a glob answers "the suites that exist passed", which is the honest answer for a
// suite and the wrong one for a gate: a gate has to say whether it ran. So this
// has its own command in package.json and its own step in CI, and every way it
// can fail to do its job ends in a non zero exit rather than in silence. A schema
// that is not on disk, a surface with no tools in it, a zod type the describer
// has not been taught: all of them stop here (CLAUDE.md O6b).
//
// It also states its own reach. "Four tools and four codes checked" says how much
// ran and not how much is covered, and that difference is where this gate was
// weakest: it derived every value from one reference report, so a three valued
// enum was checked against the single value that report produced and a broken
// constant went through green. The value sets are now proven state by state
// (`value-domains.ts`), and the enums that still rest on a sampled value are
// printed by name rather than left to be assumed covered. A gate that reports
// only what it did leaves the reader to guess the rest, and the guess is always
// generous.
//
// `--print` writes the derived document instead of checking it. That is how a
// reader sees what the code claims before arguing with what the contract says.

import { readFileSync } from "node:fs";

import Ajv2020, { type ErrorObject } from "ajv/dist/2020.js";

import { buildSurface, type ToolSurface } from "./surface.js";
import { VALUE_DOMAINS } from "./value-domains.js";

/**
 * From `dist/contract/contract-gate.js` and from `src/contract/contract-gate.ts`
 * alike, four levels up is the repository root. Read rather than imported so a
 * missing file throws here, where the message can say which file and why it
 * matters.
 */
const CONTRACT = new URL("../../../../schemas/mcp-tools.schema.json", import.meta.url);

/**
 * Schemas the contract points at.
 *
 * The detail tool's response references the canonical Finding rather than
 * restating it, so ajv needs that file loaded before the reference resolves. A
 * missing one is a broken toolchain rather than a broken surface, and it fails
 * here with a message that says so.
 */
const REFERENCED = [new URL("../../../../schemas/finding.schema.json", import.meta.url)];

/** How many complaints are printed before the rest are counted. */
const QUOTED_ERRORS = 20;

/**
 * Enum sites this document proves somewhere other than a value domain.
 *
 * One entry, and it is the error code table: `error_codes` is built by running
 * every failing call every tool declares, so the codes in it are produced rather
 * than sampled, and the contract requires each of the four by name. Naming it
 * here keeps the scope report mechanical. The alternative, deciding case by case
 * in prose which enums are "fine really", is how a gate comes to claim coverage
 * nobody rechecked.
 */
const PROVEN_ELSEWHERE: ReadonlyMap<string, string> = new Map([
  ["/$defs/errorCode", "the error_codes list, produced by running every declared failing call"],
]);

function load(location: URL, why: string): object {
  let text: string;
  try {
    text = readFileSync(location, "utf8");
  } catch (cause) {
    throw new Error(
      `${location.pathname} is not readable, and ${why}. Nothing was compared, which is a failure ` +
        `and not a pass.`,
      { cause },
    );
  }
  return JSON.parse(text) as object;
}

function report(errors: readonly ErrorObject[]): string {
  const shown = errors.slice(0, QUOTED_ERRORS).map((error) => {
    const where = error.instancePath.length > 0 ? error.instancePath : "the document itself";
    return `  ${where} ${error.message ?? "is not what the contract states"}`;
  });
  const rest = errors.length - shown.length;
  if (rest > 0) shown.push(`  and ${rest} further disagreement${rest === 1 ? "" : "s"}`);
  return shown.join("\n");
}

/**
 * Every place the contract closes a set of string values, by JSON pointer.
 *
 * Read out of the contract rather than listed here, so an enum written into the
 * schema tomorrow appears in the scope report on its own. A list kept by hand
 * would go stale in the direction that flatters the gate: the new enum would be
 * missing from it, and the report would not mention that nothing proves it.
 */
function enumSites(node: unknown, pointer: string, into: Map<string, readonly string[]>): void {
  if (Array.isArray(node)) {
    node.forEach((item, index) => enumSites(item, `${pointer}/${index}`, into));
    return;
  }
  if (typeof node !== "object" || node === null) return;

  for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
    if (
      key === "enum" &&
      Array.isArray(value) &&
      value.length > 0 &&
      value.every((item) => typeof item === "string")
    ) {
      into.set(`${pointer}/${key}`, value as string[]);
      continue;
    }
    enumSites(value, `${pointer}/${key}`, into);
  }
}

/**
 * What this gate protects, and what it only samples.
 *
 * A stale claim stops the gate rather than printing a line. A domain naming a
 * pointer the contract no longer carries would otherwise report a field as
 * covered while the enum it was written for sat unguarded, which is the exact
 * shape of the defect this scope report exists to make visible.
 */
function scope(contract: object, surface: ToolSurface): string[] {
  const sites = new Map<string, readonly string[]>();
  enumSites(contract, "", sites);

  const claimed = new Set<string>();
  for (const domain of VALUE_DOMAINS) {
    for (const site of domain.contractSites) claimed.add(`${site}/enum`);
  }
  for (const site of PROVEN_ELSEWHERE.keys()) claimed.add(`${site}/enum`);

  const stale = [...claimed].filter((site) => !sites.has(site)).sort();
  if (stale.length > 0) {
    throw new Error(
      `the contract carries no enum at ${stale.join(", ")}, and this gate claims to prove ` +
        `${stale.length === 1 ? "it" : "them"}. The claim is what the scope report is built from, ` +
        `so a stale one reports a field as covered while nothing covers it.`,
    );
  }

  const proven = Object.entries(surface.value_domains).map(([name, domain]) => {
    const count = domain.values.length;
    return (
      `       ${name} ${count}/${count} values (${domain.values.join(", ")}) ` +
      `over ${domain.fields.length} answer field(s)`
    );
  });

  const lines = [
    `ok   ${proven.length} enum(s) proven value by value against the code that produces them:`,
    ...proven,
    `ok   ${PROVEN_ELSEWHERE.size} enum(s) proven elsewhere in this document:`,
    ...[...PROVEN_ELSEWHERE].map(([site, how]) => `       ${site} by ${how}`),
  ];

  const sampled = [...sites.keys()].filter((site) => !claimed.has(site)).sort();
  if (sampled.length > 0) {
    lines.push(
      `note ${sampled.length} enum(s) in the contract rest on one sampled value, so there the`,
      `     contract holds the spelling the reference report happened to produce and not the set.`,
      `     None of them is a reduction this package computes: the engine writes these values and`,
      `     this server passes them through, except the confidence words, which are literals the`,
      `     compiler ties to the filter.confidence input enum the contract pins as a whole list.`,
      ...sampled.map((site) => `       ${site} (${(sites.get(site) ?? []).join(", ")})`),
    );
  }
  return lines;
}

async function main(): Promise<void> {
  const surface = await buildSurface();

  if (process.argv.includes("--print")) {
    process.stdout.write(`${JSON.stringify(surface, null, 2)}\n`);
    return;
  }

  // `strict: false` for the same reason the repository's other validator passes
  // `--strict=false`: the schemas use keyword combinations ajv's strict mode
  // warns about and the specification allows.
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  for (const referenced of REFERENCED) {
    ajv.addSchema(load(referenced, "the contract points at it"));
  }
  const contract = load(CONTRACT, "this gate compares the served tool surface against it");
  const validate = ajv.compile(contract);

  const names = Object.keys(surface.tools);
  if (validate(surface)) {
    process.stdout.write(
      `ok   ${names.length} registered tool(s) match schemas/mcp-tools.schema.json: ${names.join(", ")}\n` +
        `ok   ${surface.error_codes.length} error code(s) produced, all in the contract's table: ${surface.error_codes.join(", ")}\n` +
        `${scope(contract, surface).join("\n")}\n`,
    );
    return;
  }

  process.stderr.write(
    `FAIL the served tool surface disagrees with schemas/mcp-tools.schema.json.\n` +
      `The contract is above the implementation (CLAUDE.md document hierarchy), so unless the\n` +
      `contract itself was changed on purpose, the code is what moved. Run\n` +
      `  npm run gate:contract -- --print\n` +
      `to see the surface this server actually serves.\n` +
      `${report(validate.errors ?? [])}\n`,
  );
  process.exitCode = 1;
}

main().catch((error: unknown) => {
  process.stderr.write(
    `FAIL the tool surface could not be derived, so nothing was checked: ` +
      `${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exit(1);
});
