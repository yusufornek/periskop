// The tool surface, described by the code that serves it.
//
// This module produces one document: what tools exist, what each one accepts,
// what each one answers, and how each one refuses. `schemas/mcp-tools.schema.json`
// is the contract that document is checked against.
//
// Nothing here is written twice. The tool list comes from `registry.ts`, which
// is the same array `index.ts` registers from. The input description is read off
// the zod schemas those registrations carry. The responses are produced by
// running the real handlers. A hand maintained copy of any of that would be a
// new place for the surface to drift from the contract, which is the failure the
// gate exists to catch rather than to reproduce.
//
// One rule runs through the whole file: anything this module cannot describe
// stops it. A zod type it has not been taught, a reference call that answers the
// wrong way, a tool with no failing call declared. Each of those would otherwise
// leave a hole in the document, and a hole in the document is a field the
// contract cannot check while the gate still reports green.
//
// The document has two kinds of evidence in it and they are not interchangeable.
// A response is sampled: it is what a handler produced over one report, which is
// the only way a shape can be produced at all. A closed value set is not sampled,
// because one report puts one branch of one function into the document and the
// contract then checks a three valued enum against the single value it happened
// to see. Those sets come from `value-domains.ts`, which runs each producing
// function into every state it has.

import { z } from "zod";

import type { ReportSource } from "../bridge.js";
import { TOOLS, type ReferenceCall, type ToolRegistration } from "../registry.js";
import { referenceReport } from "./reference-report.js";
import { proveValueDomains, type ProvenDomain } from "./value-domains.js";

/** MAJOR.MINOR, as every schema in this repository versions itself. */
export const SURFACE_SCHEMA_VERSION = "1.0";

/** One accepted argument, in the terms the contract states arguments in. */
export interface FieldDescription {
  type: "string" | "integer" | "number" | "boolean" | "object";
  required: boolean;
  enum?: readonly string[];
  minimum?: number;
  maximum?: number;
  properties?: Readonly<Record<string, FieldDescription>>;
}

export interface ToolDescription {
  input: Readonly<Record<string, FieldDescription>>;
  response: Record<string, unknown>;
  error_responses: Record<string, unknown>[];
}

export interface ToolSurface {
  schema_version: string;
  tools: Readonly<Record<string, ToolDescription>>;
  error_codes: string[];
  /**
   * Fields whose accepted values the contract closes, with every value the code
   * can actually produce. Sampled responses state a shape; this states a set.
   */
  value_domains: Record<string, ProvenDomain>;
}

/**
 * The parts of a zod definition this module reads.
 *
 * Declared rather than imported because zod does not publish its internals as a
 * type. Reading them is the point: the alternative is a second description of
 * every argument, kept in step by hand.
 */
interface ZodInternals {
  typeName?: string;
  innerType?: z.ZodTypeAny;
  values?: readonly string[];
  checks?: readonly { kind: string; value?: number }[];
}

function internals(schema: z.ZodTypeAny): ZodInternals {
  return schema._def as unknown as ZodInternals;
}

/**
 * Sorts an object's keys.
 *
 * The document is compared byte for byte in tests and read by a human in review,
 * and neither survives a field order that follows however the source happens to
 * be arranged today. Determinism is a stated property of every answer this
 * package produces (CLAUDE.md); the description of those answers is held to it
 * too.
 */
function sortedKeys<T>(entries: Iterable<readonly [string, T]>): Record<string, T> {
  const rows = [...entries].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return Object.fromEntries(rows);
}

/** Describes one argument, unwrapping the optional marker into a flag. */
function describeField(schema: z.ZodTypeAny): FieldDescription {
  const outer = internals(schema);
  const optional = outer.typeName === "ZodOptional";
  const inner = optional && outer.innerType ? outer.innerType : schema;
  return { ...describeType(inner), required: !optional };
}

function describeType(schema: z.ZodTypeAny): Omit<FieldDescription, "required"> {
  const def = internals(schema);

  switch (def.typeName) {
    case "ZodString":
      return { type: "string" };

    case "ZodBoolean":
      return { type: "boolean" };

    case "ZodEnum": {
      const values = def.values;
      if (!values || values.length === 0) {
        throw new Error("an enum argument carries no values, so its accepted set cannot be stated");
      }
      // Declaration order, not sorted: for an enum the order is part of what the
      // contract names, and the contract lists confirmed before suspect.
      return { type: "string", enum: [...values] };
    }

    case "ZodNumber": {
      const checks = def.checks ?? [];
      const integer = checks.some((check) => check.kind === "int");
      const minimum = checks.find((check) => check.kind === "min")?.value;
      const maximum = checks.find((check) => check.kind === "max")?.value;
      return {
        type: integer ? "integer" : "number",
        ...(minimum === undefined ? {} : { minimum }),
        ...(maximum === undefined ? {} : { maximum }),
      };
    }

    case "ZodObject": {
      const object = schema as z.ZodObject<z.ZodRawShape>;
      return { type: "object", properties: describeInput(object) };
    }

    default:
      // Not a fallback. A type this module has not been taught would be dropped
      // from the document, and a dropped argument is one the contract cannot
      // check while the gate still passes: exactly the silence this gate was
      // built to end.
      throw new Error(
        `the tool surface uses the zod type ${def.typeName ?? "with no type name"}, which this ` +
          `describer cannot state as a contract field. Teach describeType about it rather than ` +
          `leaving the field out of the document.`,
      );
  }
}

/** Every argument of one tool, keyed by name. */
export function describeInput(schema: z.ZodObject<z.ZodRawShape>): Record<string, FieldDescription> {
  const shape = schema.shape;
  const described = Object.entries(shape).map(
    ([name, field]) => [name, describeField(field as z.ZodTypeAny)] as const,
  );
  if (described.length === 0) {
    // A parameterless tool is legitimate, but none exists today, and an empty
    // object here is far more likely to mean the shape was read off the wrong
    // value. Saying so beats writing an empty input block into the contract.
    throw new Error("a registered tool describes no arguments at all; its schema shape read empty");
  }
  return sortedKeys(described);
}

/** An engine that always answers the same thing. */
function fixedSource(answer: unknown): ReportSource {
  return { call: () => Promise.resolve(answer) };
}

function isEnvelope(answer: Record<string, unknown>): boolean {
  const error = answer["error"];
  return typeof error === "object" && error !== null && "code" in error;
}

function codeOf(name: string, answer: Record<string, unknown>): string {
  const error = answer["error"];
  const code = (error as Record<string, unknown> | undefined)?.["code"];
  if (typeof code !== "string" || code.length === 0) {
    throw new Error(
      `the failing reference call for ${name} did not answer with the shared error envelope, so ` +
        `the code it produces cannot be checked against the contract's table`,
    );
  }
  return code;
}

/**
 * An answer that is not a scan report.
 *
 * The one engine failure every tool has to turn into the shared envelope: the
 * subprocess replied, so nothing threw, and what it replied is not a report.
 */
const NOT_A_REPORT = { result: "ok" };

async function answer(tool: ToolRegistration, call: ReferenceCall): Promise<Record<string, unknown>> {
  const engine = call.engine === "report" ? referenceReport() : NOT_A_REPORT;
  return tool.run(fixedSource(engine), call.args);
}

/**
 * Builds the document the contract is checked against.
 *
 * Every response in it came out of the handler that serves the tool, over the
 * report in `reference-report.ts`. That is what makes the document evidence
 * about the code rather than a statement about it.
 */
export async function buildSurface(): Promise<ToolSurface> {
  const tools = TOOLS;
  if (tools.length === 0) {
    // A gate with nothing to check must fail rather than pass (CLAUDE.md O6b).
    throw new Error("no tools are registered, so there is no surface to compare with the contract");
  }

  const described: [string, ToolDescription][] = [];
  const codes = new Set<string>();

  for (const tool of tools) {
    if (tool.referenceFailures.length === 0) {
      throw new Error(
        `${tool.name} declares no failing call, so the error code it produces would never reach ` +
          `the contract's table`,
      );
    }

    const success = await answer(tool, tool.reference);
    if (isEnvelope(success)) {
      // The successful call is the only thing that puts the response shape into
      // the document. If it fails, the document describes a refusal and the
      // contract's response block is checked against nothing.
      throw new Error(
        `the reference call for ${tool.name} answered with an error envelope, so its response ` +
          `shape never entered the document: ${JSON.stringify(success)}`,
      );
    }

    const refusals: Record<string, unknown>[] = [];
    for (const failure of tool.referenceFailures) {
      const refused = await answer(tool, failure);
      codes.add(codeOf(tool.name, refused));
      refusals.push(refused);
    }

    described.push([tool.name, { input: describeInput(tool.inputSchema), response: success, error_responses: refusals }]);
  }

  const byName = sortedKeys(described);

  return {
    schema_version: SURFACE_SCHEMA_VERSION,
    tools: byName,
    error_codes: [...codes].sort(),
    // Derived last, and over the document rather than beside it: each domain
    // names the answer fields it guards and they are resolved here, so a
    // response field that is renamed stops the gate instead of leaving a domain
    // that guards a path nothing serves.
    value_domains: proveValueDomains(byName),
  };
}
