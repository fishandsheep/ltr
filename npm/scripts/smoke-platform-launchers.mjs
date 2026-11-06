import {
  chmodSync,
  cpSync,
  mkdtempSync,
  mkdirSync,
  rmSync,
  writeFileSync
} from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../..", import.meta.url));
const ltrPackages = [
  "ltr-darwin-arm64",
  "ltr-darwin-x64",
  "ltr-linux-arm64-musl",
  "ltr-linux-x64-musl",
  "ltr-win32-x64-msvc"
];
const cases = [
  ["darwin", "arm64", null, "ltr-darwin-arm64"],
  ["darwin", "x64", null, "ltr-darwin-x64"],
  ["linux", "arm64", [true, null], "ltr-linux-arm64-musl"],
  ["linux", "x64", [true, null], "ltr-linux-x64-musl"],
  ["win32", "x64", null, "ltr-win32-x64-msvc"]
];

const smokeRoot = mkdtempSync(join(tmpdir(), "ltr-launcher-smoke-"));
const scope = join(smokeRoot, "node_modules", "@qinshower");
mkdirSync(scope, { recursive: true });

try {
  for (const packageDir of ["ltr", ...ltrPackages]) {
    cpSync(join(root, "npm", packageDir), join(scope, packageDir), { recursive: true });
  }

  for (const packageDir of ltrPackages) {
    const binDir = join(scope, packageDir, "bin");
    mkdirSync(binDir, { recursive: true });
    const executable = packageDir.includes("win32") ? "ltr.exe" : "ltr";
    const path = join(binDir, executable);
    writeFileSync(
      path,
      "#!/bin/sh\nprintf '%s' " + JSON.stringify(packageDir) + "\n"
    );
    chmodSync(path, 0o755);
  }

  for (const [platform, arch, libcAndArmVersion, expectedPackage] of cases) {
    const libc = libcAndArmVersion ? libcAndArmVersion[0] : false;
    const armVersion = libcAndArmVersion ? libcAndArmVersion[1] : null;
    const run = (launcher, label) => {
      const code = [
        "Object.defineProperty(process, 'platform', { value: " + JSON.stringify(platform) + " });",
        "Object.defineProperty(process, 'arch', { value: " + JSON.stringify(arch) + " });",
        "Object.defineProperty(process, 'report', { value: { getReport: () => ({ header: { glibcVersionRuntime: " +
          JSON.stringify(libc ? undefined : "2.35") +
          " } }) } });",
        armVersion === null
          ? ""
          : "Object.defineProperty(process, 'config', { value: { variables: { arm_version: " + armVersion + " } } });",
        "const childProcess = require('node:child_process');",
        "childProcess.spawnSync = (binary) => { if (!binary.includes(" +
          JSON.stringify(expectedPackage) +
          ")) throw new Error('wrong binary: ' + binary); process.stdout.write(" +
          JSON.stringify(expectedPackage) +
          "); return { status: 0, signal: null, error: null, stdout: " +
          JSON.stringify(expectedPackage + "\n") +
          ", stderr: '' }; };",
        "require(" + JSON.stringify(launcher) + ");"
      ].join("\n");
      const result = spawnSync(process.execPath, ["-e", code, "--", "--help"], {
        cwd: smokeRoot,
        encoding: "utf8"
      });
      if (result.status !== 0 || result.stdout.trim() !== expectedPackage) {
        throw new Error(
          label +
            " expected " +
            expectedPackage +
            " but got " +
            result.stdout.trim() +
            " (exit " +
            result.status +
            "): " +
            result.stderr
        );
      }
    };

    run(join(scope, "ltr", "bin", "ltr.js"), "LTR " + platform + "/" + arch);
  }
} finally {
  rmSync(smokeRoot, { recursive: true, force: true });
}

console.log("All 5 LTR platform launcher selections passed");
