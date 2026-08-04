// Validates every example under schemas/examples against its schema.
//
// Two things separate this from a plain "run ajv over the directory" step.
//
// First, negative examples are checked for the error they produce, not only for
// the fact that they fail. An example that fails for the wrong reason is as much
// a bug as one that passes, and the plain exit code cannot tell the difference.
//
// Second, a missing $ref target is reported as a tooling error rather than a
// schema violation. Those two failures look alike on the surface and lead to
// very different fixes.

import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, basename } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const schemaDir = join(repoRoot, "schemas");
const exampleDir = join(schemaDir, "examples");

// Schemas that other schemas reference. ajv needs every one of them loaded with
// -r before it can resolve a $ref, otherwise it aborts with a resolution error.
const REFERENCED_SCHEMAS = ["finding.schema.json", "coverage-statement.schema.json"];

const AJV_ARGS = ["--spec=draft2020", "-c", "ajv-formats", "--strict=false"];

function ajvValidate(schemaFile, dataFile) {
  const args = ["ajv", "validate", ...AJV_ARGS, "-s", join(schemaDir, schemaFile)];
  for (const ref of REFERENCED_SCHEMAS) {
    if (ref !== schemaFile) args.push("-r", join(schemaDir, ref));
  }
  args.push("-d", dataFile);

  const run = spawnSync("npx", ["--no-install", ...args], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  return {
    ok: run.status === 0,
    output: `${run.stdout ?? ""}${run.stderr ?? ""}`,
  };
}

// A reference that cannot be resolved is a broken toolchain, not a broken example.
// Reporting it as a validation failure sends the reader to the wrong file.
function looksLikeRefFailure(output) {
  return /can't resolve reference|no schema with key or ref/i.test(output);
}

function schemaForExample(name) {
  // finding.valid.json and finding.invalid.json both belong to finding.schema.json.
  // Anything before the first dot names the schema.
  const stem = basename(name).split(".")[0];
  const candidate = `${stem}.schema.json`;
  return existsSync(join(schemaDir, candidate)) ? candidate : null;
}

const expectationsPath = join(exampleDir, "invalid-expectations.json");
const expectations = JSON.parse(readFileSync(expectationsPath, "utf8"));
const expectedByFile = new Map(expectations.cases.map((c) => [c.file, c]));

const examples = readdirSync(exampleDir)
  .filter((f) => f.endsWith(".json") && f !== "invalid-expectations.json")
  .sort();

let failures = 0;
let checked = 0;

for (const file of examples) {
  const full = join(exampleDir, file);
  const isNegative = file.includes(".invalid.");
  const expectation = expectedByFile.get(file);

  if (isNegative && !expectation) {
    console.error(`FAIL ${file}: negative example has no entry in invalid-expectations.json`);
    failures++;
    continue;
  }

  const schemaFile = expectation?.schema ?? schemaForExample(file);
  if (!schemaFile) {
    console.error(`FAIL ${file}: cannot determine which schema this example belongs to`);
    failures++;
    continue;
  }

  const { ok, output } = ajvValidate(schemaFile, full);
  checked++;

  if (looksLikeRefFailure(output)) {
    console.error(
      `TOOLING ${file}: ajv could not resolve a $ref while loading ${schemaFile}. ` +
        `Every referenced schema must be passed with -r. This is a CI configuration ` +
        `problem, not a problem with the example.`
    );
    failures++;
    continue;
  }

  if (isNegative) {
    if (ok) {
      console.error(`FAIL ${file}: expected to be rejected by ${schemaFile}, but it validated`);
      failures++;
      continue;
    }
    const needle = expectation.expected_error_contains;
    if (!output.includes(needle)) {
      console.error(
        `FAIL ${file}: rejected, but not for the declared reason. ` +
          `Expected the error to mention "${needle}" (${expectation.violates}).`
      );
      failures++;
      continue;
    }
    console.log(`ok   ${file} rejected as expected (${expectation.violates})`);
  } else {
    if (!ok) {
      console.error(`FAIL ${file}: expected to validate against ${schemaFile}\n${output}`);
      failures++;
      continue;
    }
    console.log(`ok   ${file} valid against ${schemaFile}`);
  }
}

// Every negative example listed in the manifest must actually exist. A stale entry
// would otherwise let a deleted example pass unnoticed.
for (const [file] of expectedByFile) {
  if (!examples.includes(file)) {
    console.error(`FAIL invalid-expectations.json lists ${file}, which does not exist`);
    failures++;
  }
}

console.log(`\n${checked} example(s) checked, ${failures} failure(s)`);
process.exit(failures > 0 ? 1 : 0);
