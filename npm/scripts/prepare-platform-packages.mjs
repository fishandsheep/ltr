import { copyFileSync, chmodSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../..", import.meta.url));

const targets = [
  ["aarch64-apple-darwin", "ltr-darwin-arm64", "ltr"],
  ["x86_64-apple-darwin", "ltr-darwin-x64", "ltr"],
  ["aarch64-unknown-linux-musl", "ltr-linux-arm64-musl", "ltr"],
  ["x86_64-unknown-linux-musl", "ltr-linux-x64-musl", "ltr"],
  ["x86_64-pc-windows-msvc", "ltr-win32-x64-msvc", "ltr.exe"]
];

for (const [target, packageDir, executable] of targets) {
  const source = join(root, "target", target, "release", executable);
  if (!existsSync(source)) {
    throw new Error(`Missing release binary for ${target}: ${source}`);
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

console.log("Prepared platform npm packages");
