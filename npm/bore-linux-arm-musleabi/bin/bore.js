#!/usr/bin/env node

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const packageName = "@qinshower/ltr-linux-arm-musleabi";
let packageJson;
try {
  packageJson = require.resolve(`${packageName}/package.json`);
} catch (error) {
  const localPackage = path.join(__dirname, "..", "..", packageName.replace("@qinshower/", ""), "package.json");
  if (!fs.existsSync(localPackage)) throw error;
  packageJson = localPackage;
}
const extension = process.platform === "win32" ? ".exe" : "";
const binary = path.join(path.dirname(packageJson), "bin", `ltr${extension}`);
console.error("Warning: @qinshower/bore-linux-arm-musleabi is deprecated; migrate to @qinshower/ltr-linux-arm-musleabi.");
if (!fs.existsSync(binary)) {
  console.error(`Missing LTR binary at ${binary}`);
  process.exit(1);
}
const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}
if (result.signal) {
  process.kill(process.pid, result.signal);
} else {
  process.exit(result.status === null ? 1 : result.status);
}

