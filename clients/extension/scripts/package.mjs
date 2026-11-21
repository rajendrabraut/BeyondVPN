// Copies the extension into dist/<target>/ with the right manifest (zip it for store upload).
import { cpSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const target = process.argv[2] ?? "chrome";
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "dist", target);
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
for (const f of ["background.js", "lib.js", "popup.html", "popup.css", "popup.js"]) cpSync(join(root, f), join(out, f));
cpSync(join(root, target === "firefox" ? "manifest.firefox.json" : "manifest.json"), join(out, "manifest.json"));
console.log(`packaged ${target} extension -> ${out}`);
