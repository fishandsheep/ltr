#!/usr/bin/env node

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const packages = {
  "darwin arm64": "@qinshower/ltr-darwin-arm64",
  "darwin x64": "@qinshower/ltr-darwin-x64",
  "linux arm64": "@qinshower/ltr-linux-arm64-musl",
  "linux x64": "@qinshower/ltr-linux-x64-musl",
  "win32 x64": "@qinshower/ltr-win32-x64-msvc"
};

function selectedPackage() {
  const key = `${process.platform} ${process.arch}`;
  const value = packages[key];

  if (typeof value !== "string") {
    return null;
  }

  return value;
}

function packageBinary(packageName) {
  let packageJson;
  try {
    packageJson = require.resolve(`${packageName}/package.json`);
  } catch (error) {
    const localPackage = path.join(__dirname, "..", "..", packageName.replace("@qinshower/", ""), "package.json");
    if (!fs.existsSync(localPackage)) {
      throw error;
    }
    packageJson = localPackage;
  }
  const extension = process.platform === "win32" ? ".exe" : "";
  return path.join(path.dirname(packageJson), "bin", `ltr${extension}`);
}

const packageName = selectedPackage();

if (!packageName) {
  console.error(`Unsupported platform for @qinshower/ltr: ${process.platform}/${process.arch}`);
  console.error(`Supported platforms: ${Object.keys(packages).join(", ")}`);
  process.exit(1);
}

let binary;

try {
  binary = packageBinary(packageName);
} catch (error) {
  console.error(`Missing optional dependency ${packageName}.`);
  console.error("Install @qinshower/ltr with optional dependencies enabled, or run npm install again.");
  process.exit(1);
}

if (!fs.existsSync(binary)) {
  console.error(`Missing ltr binary at ${binary}`);
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
