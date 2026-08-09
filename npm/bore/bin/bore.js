#!/usr/bin/env node

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const packages = {
  "darwin arm64": "@qinshower/ltr-darwin-arm64",
  "darwin x64": "@qinshower/ltr-darwin-x64",
  "linux arm": {
    glibc: {
      6: "@qinshower/ltr-linux-arm-gnueabi",
      7: "@qinshower/ltr-linux-armv7-gnueabihf",
      default: "@qinshower/ltr-linux-arm-gnueabi"
    },
    musl: {
      6: "@qinshower/ltr-linux-arm-musleabi",
      7: "@qinshower/ltr-linux-armv7-musleabihf",
      default: "@qinshower/ltr-linux-arm-musleabi"
    }
  },
  "linux arm64": "@qinshower/ltr-linux-arm64-musl",
  "linux ia32": "@qinshower/ltr-linux-ia32-musl",
  "linux x64": "@qinshower/ltr-linux-x64-musl",
  "win32 ia32": "@qinshower/ltr-win32-ia32-msvc",
  "win32 x64": "@qinshower/ltr-win32-x64-msvc"
};

function isMuslLinux() {
  if (process.platform !== "linux") {
    return false;
  }
  if (!process.report || typeof process.report.getReport !== "function") {
    return true;
  }
  try {
    return !process.report.getReport().header.glibcVersionRuntime;
  } catch {
    return true;
  }
}

function selectedPackage() {
  const value = packages[`${process.platform} ${process.arch}`];
  if (!value) return null;
  if (typeof value === "string") return value;
  const family = isMuslLinux() ? value.musl : value.glibc;
  const armVersion = Number(process.config?.variables?.arm_version);
  return family[armVersion] || family.default;
}

function packageBinary(packageName) {
  let packageJson;
  try {
    packageJson = require.resolve(`${packageName}/package.json`);
  } catch (error) {
    const localPackage = path.join(__dirname, "..", "..", packageName.replace("@qinshower/", ""), "package.json");
    if (!fs.existsSync(localPackage)) throw error;
    packageJson = localPackage;
  }
  const extension = process.platform === "win32" ? ".exe" : "";
  return path.join(path.dirname(packageJson), "bin", `ltr${extension}`);
}

console.error("Warning: @qinshower/bore is deprecated; migrate to @qinshower/ltr.");

const packageName = selectedPackage();
if (!packageName) {
  console.error(`Unsupported platform for @qinshower/bore: ${process.platform}/${process.arch}`);
  console.error(`Supported platforms: ${Object.keys(packages).join(", ")}`);
  process.exit(1);
}

let binary;
try {
  binary = packageBinary(packageName);
} catch (error) {
  console.error(`Missing optional dependency ${packageName}.`);
  console.error("Install @qinshower/bore with optional dependencies enabled, or run npm install again.");
  process.exit(1);
}

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
