// What an install of this package actually gets.
//
// `files: ["dist"]` published everything the compiler emitted, and two of those
// files import `ajv`, which is a devDependency. The tarball therefore carried
// modules that cannot resolve on a machine that installed the package: the
// contract gate and the test suites, neither of which a consumer runs, both of
// which would throw ERR_MODULE_NOT_FOUND if anything touched them. Nothing said
// so, because nothing looked at the tarball.
//
// So the tarball is looked at here rather than reasoned about. npm is asked what
// it would publish, and the answer is checked, which is the only version of this
// check that cannot be wrong about npm's own glob rules. The rule the exclusions
// encode is a directory rather than a list of names: `dist/contract` is the gate
// and never ships, so a module added to the gate tomorrow is excluded by the rule
// that is already there instead of by a line somebody has to remember to write.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

/** Where the package root is from `dist/publish.test.js`. */
const PACKAGE_ROOT = new URL("..", import.meta.url);

interface PackedFile {
  path: string;
}

/**
 * The file list npm would publish.
 *
 * `--dry-run` so nothing is written, `--json` so the answer is the list itself
 * rather than a notice log that changes format between npm versions.
 */
function published(): string[] {
  const output = execFileSync("npm", ["pack", "--dry-run", "--json"], {
    cwd: PACKAGE_ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  const packed = JSON.parse(output) as { files: PackedFile[] }[];
  assert.equal(packed.length, 1, "npm described something other than one tarball");
  return (packed[0]?.files ?? []).map((file) => file.path);
}

/** Package names imported by a file, ignoring relative and node builtins. */
function bareImports(relative: string): string[] {
  const source = readFileSync(new URL(relative, PACKAGE_ROOT), "utf8");
  const specifiers = [...source.matchAll(/from\s+"([^"]+)"/g)].map((match) => match[1] ?? "");
  return specifiers
    .filter((specifier) => !specifier.startsWith(".") && !specifier.startsWith("node:"))
    .map((specifier) =>
      specifier.startsWith("@") ? specifier.split("/").slice(0, 2).join("/") : specifier.split("/")[0] ?? "",
    );
}

test("nothing in the published tarball imports a package the install does not get", () => {
  const manifest = JSON.parse(
    readFileSync(new URL("package.json", PACKAGE_ROOT), "utf8"),
  ) as Record<string, Record<string, string>>;
  const runtime = new Set(Object.keys(manifest["dependencies"] ?? {}));

  const offenders: string[] = [];
  for (const file of published().filter((path) => path.endsWith(".js"))) {
    for (const dependency of bareImports(file)) {
      // A published file importing something outside `dependencies` is an import
      // that throws on a consumer's machine. It is worth catching whether the
      // package is unused (dead weight) or used (a broken install).
      if (!runtime.has(dependency)) offenders.push(`${file} imports ${dependency}`);
    }
  }

  assert.deepEqual(
    offenders,
    [],
    `the tarball carries imports that will not resolve after npm install:\n${offenders.join("\n")}`,
  );
});

test("the gate and the suites stay out of the tarball", () => {
  const files = published();
  assert.ok(files.length > 0, "npm reported an empty tarball, so this test compared nothing");

  const shipped = files.filter(
    (path) => path.startsWith("dist/contract/") || /\/[^/]+\.test\./.test(path),
  );
  assert.deepEqual(
    shipped,
    [],
    `the contract gate or a test suite reached the tarball:\n${shipped.join("\n")}`,
  );
});
