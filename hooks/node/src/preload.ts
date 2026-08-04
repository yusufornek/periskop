// The file node --require loads, and the only file in this package that runs on
// its own.
//
// It runs before the application's first line, which makes it the riskiest code
// here: a throw at this point does not degrade the hook, it stops the process
// from starting. So the whole body sits in a try block, every module is required
// lazily inside it, and the failure path does nothing more ambitious than set an
// environment variable.
//
// The gate is checked before install is required. That is what makes the exit
// from an npm or tsc process cheap: those processes load one small module that
// compares a few strings, and never touch the patches, the hash or the writer.

try {
  const gate = require("./process-gate") as typeof import("./process-gate");
  const decision = gate.decideInstrumentation(process.env, process.argv, process.version);

  if (decision.instrument) {
    const installer = require("./install") as typeof import("./install");
    installer.install();
  } else {
    const status = require("./hook-status") as typeof import("./hook-status");
    status.markDisabled(decision.reason);
  }
} catch {
  // Anything at all went wrong: a missing build output, an incompatible runtime,
  // a module that failed to parse. The application starts un-hooked, which is
  // the outcome spec section 5 asks for, and the reason is left where an
  // operator can find it.
  try {
    process.env["PERISKOP_HOOK_STATUS"] = "disabled:load_failed";
  } catch {
    // There is nothing below this.
  }
}
