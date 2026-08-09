import { spawnSync } from "node:child_process";
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../..", import.meta.url));
const npmDir = join(root, "npm");

for (const entry of readdirSync(npmDir)) {
  const dir = join(npmDir, entry);
  if (!statSync(dir).isDirectory() || entry === "scripts") {
    continue;
  }

  const result = spawnSync("npm", ["pack", "--dry-run"], {
    cwd: dir,
    stdio: "inherit"
  });

  if (result.status !== 0) {
    process.exit(result.status || 1);
  }
}
