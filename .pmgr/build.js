import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const pmgrDir = path.dirname(fileURLToPath(import.meta.url));
const srcDir = path.resolve(pmgrDir, "../project/src");
const distDir = path.resolve(pmgrDir, "dist");
const depDir = path.resolve(distDir, "dependencies");
const nodeModulesDir = path.resolve(pmgrDir, "node_modules");

// 1. Copy external npm dependencies into /dependencies
async function bundleDependencies() {
  fs.mkdirSync(depDir, { recursive: true });

  // FontAwesome assets & CSS (if installed)
  const faSrc = path.join(nodeModulesDir, "@fortawesome/fontawesome-free");
  if (fs.existsSync(faSrc)) {
    const faDest = path.join(depDir, "fontawesome");
    fs.mkdirSync(path.join(faDest, "css"), { recursive: true });
    fs.mkdirSync(path.join(faDest, "webfonts"), { recursive: true });

    fs.copyFileSync(
      path.join(faSrc, "css/fontawesome.min.css"),
      path.join(faDest, "css/fontawesome.min.css")
    );
    fs.copyFileSync(
      path.join(faSrc, "css/solid.min.css"),
      path.join(faDest, "css/solid.min.css")
    );

    const webfonts = fs.readdirSync(path.join(faSrc, "webfonts"));
    for (const font of webfonts) {
      fs.copyFileSync(
        path.join(faSrc, "webfonts", font),
        path.join(faDest, "webfonts", font)
      );
    }
  }
}

// 2. Transform individual file contents (only rewriting paths, preserving formatting)
function transformContent(filePath, content) {
  const ext = path.extname(filePath);

  if (ext === ".js") {
    return content
      .replace(/import\s+["'][^"']+\.css["'];?\r?\n?/g, "")
      .replace(/from\s+["']@\//g, 'from "/')
      .replace(/import\s+["']@\//g, 'import "/');
  }

  if (ext === ".css") {
    return content.replace(/@import\s+(url\()?["']@\//g, '@import $1"/');
  }

  if (ext === ".html") {
    return content
      .replace(/href=["']@\//g, 'href="/')
      .replace(/src=["']@\//g, 'src="/');
  }

  return content;
}

// 3. Copy & transform a single file
function processFile(srcFilePath) {
  const relPath = path.relative(srcDir, srcFilePath);
  const targetFilePath = path.join(distDir, relPath);

  fs.mkdirSync(path.dirname(targetFilePath), { recursive: true });

  const ext = path.extname(srcFilePath);
  if ([".js", ".css", ".html", ".json"].includes(ext)) {
    const raw = fs.readFileSync(srcFilePath, "utf8");
    const transformed = transformContent(srcFilePath, raw);
    fs.writeFileSync(targetFilePath, transformed, "utf8");
  } else {
    fs.copyFileSync(srcFilePath, targetFilePath);
  }
}

// 4. Recursive build
function syncDirectory(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      syncDirectory(fullPath);
    } else {
      processFile(fullPath);
    }
  }
}

// 5. Main build & watch runner
export async function build() {
  fs.rmSync(distDir, { recursive: true, force: true });
  console.log("[builder] Bundling external dependencies...");
  await bundleDependencies();
  console.log("[builder] Mirroring source files (1:1 unbundled)...");
  syncDirectory(srcDir);
  console.log("[builder] Done!");
}

export async function watch() {
  await build();
  console.log(`[builder] Watching ${srcDir} for changes...`);

  fs.watch(srcDir, { recursive: true }, (eventType, filename) => {
    if (!filename) return;
    const fullSrc = path.join(srcDir, filename);

    if (fs.existsSync(fullSrc)) {
      const stat = fs.statSync(fullSrc);
      if (!stat.isDirectory()) {
        try {
          processFile(fullSrc);
          console.log(`[builder] Updated: ${filename}`);
        } catch (err) {
          console.error(`[builder] Error processing ${filename}:`, err);
        }
      }
    } else {
      const fullDist = path.join(distDir, filename);
      if (fs.existsSync(fullDist)) {
        fs.rmSync(fullDist, { force: true, recursive: true });
        console.log(`[builder] Removed: ${filename}`);
      }
    }
  });
}

// If executed directly: bun build.js [--watch]
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.includes("--watch")) {
    await watch();
  } else {
    await build();
  }
}

