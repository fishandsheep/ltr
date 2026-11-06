import { chmodSync, copyFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../..", import.meta.url));
const assetDir = process.argv[2] || join(root, "npm-dist");
const requestedPackageDirs = new Set(process.argv.slice(3));
const tag = process.env.GITHUB_REF_NAME || process.env.TAG_NAME;

if (!tag) {
  throw new Error("Set GITHUB_REF_NAME or TAG_NAME to the release tag");
}

const assets = [
  ["aarch64-apple-darwin", "ltr-darwin-arm64", "tar.gz", "ltr"],
  ["x86_64-apple-darwin", "ltr-darwin-x64", "tar.gz", "ltr"],
  ["aarch64-unknown-linux-musl", "ltr-linux-arm64-musl", "tar.gz", "ltr"],
  ["x86_64-unknown-linux-musl", "ltr-linux-x64-musl", "tar.gz", "ltr"],
  ["x86_64-pc-windows-msvc", "ltr-win32-x64-msvc", "zip", "ltr.exe"]
];

function run(command, args) {
  const result = spawnSync(command, args, { stdio: "inherit" });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed`);
  }
}

for (const [target, packageDir, extension, executable] of assets) {
  if (requestedPackageDirs.size > 0 && !requestedPackageDirs.has(packageDir)) {
    continue;
  }

  const asset = join(assetDir, `ltr-${tag}-${target}.${extension}`);
  if (!existsSync(asset)) {
    throw new Error(`Missing release asset: ${asset}`);
  }

  const extractDir = join(tmpdir(), `ltr-npm-${target}`);
  rmSync(extractDir, { recursive: true, force: true });
  mkdirSync(extractDir, { recursive: true });

  if (extension === "zip") {
    run("unzip", ["-q", asset, "-d", extractDir]);
  } else {
    run("tar", ["-xzf", asset, "-C", extractDir]);
  }

  const source = join(extractDir, executable);
  if (!existsSync(source)) {
    throw new Error(`Missing binary in ${asset}: ${executable}`);
  }

  const binDir = join(root, "npm", packageDir, "bin");
  rmSync(binDir, { recursive: true, force: true });
  mkdirSync(binDir, { recursive: true });

  const destination = join(binDir, executable);
  copyFileSync(source, destination);

  if (executable === "ltr") {
    chmodSync(destination, 0o755);
  }
}

console.log(`Prepared npm platform packages from ${assetDir}`);
