const fs = require("fs");
const path = require("path");
const { normalizeMarkdownDocument } = require("./lib/markdown");

const ROOT = path.resolve(__dirname, "..");
const POSTS_DIR = path.join(ROOT, "data", "content", "posts");

function normalizePosts() {
  if (!fs.existsSync(POSTS_DIR)) {
    console.log("No data/content/posts directory found.");
    return;
  }

  let changed = 0;
  const files = fs.readdirSync(POSTS_DIR).filter((file) => file.endsWith(".md")).sort();
  for (const file of files) {
    const full = path.join(POSTS_DIR, file);
    const current = fs.readFileSync(full, "utf8");
    const normalized = normalizeMarkdownDocument(current);
    if (normalized === current) continue;
    fs.writeFileSync(full, normalized, "utf8");
    changed += 1;
    console.log(`normalized ${path.relative(ROOT, full).replace(/\\/g, "/")}`);
  }

  console.log(`markdown normalization complete: ${changed}/${files.length} files changed`);
}

normalizePosts();
