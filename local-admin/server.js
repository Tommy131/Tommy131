const http = require("http");
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const { URL } = require("url");
const {
  excerpt,
  normalizeMarkdownBody,
  normalizeMarkdownDocument,
  parseFrontMatter,
} = require("../scripts/lib/markdown");

const ROOT = path.resolve(__dirname, "..");
const ADMIN_ROOT = __dirname;
const PUBLIC_ROOT = path.join(ROOT, "public");
const PORT = Number(process.env.PORT || 4173);

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
};

function safeJoin(base, requestPath) {
  const normalized = path.normalize(requestPath).replace(/^(\.\.[/\\])+/, "");
  const full = path.join(base, normalized);
  if (!full.startsWith(base)) throw new Error("Invalid path");
  return full;
}

function readJson(file, fallback) {
  const full = path.join(ROOT, file);
  if (!fs.existsSync(full)) return fallback;
  return JSON.parse(fs.readFileSync(full, "utf8"));
}

function writeJson(file, value) {
  writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}

function writeFile(file, content) {
  const full = path.join(ROOT, file);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, "utf8");
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 8 * 1024 * 1024) {
        reject(new Error("Request body too large"));
        req.destroy();
      }
    });
    req.on("end", () => resolve(body ? JSON.parse(body) : {}));
    req.on("error", reject);
  });
}

function send(res, status, data, contentType = "application/json; charset=utf-8") {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
  });
  if (Buffer.isBuffer(data)) {
    res.end(data);
    return;
  }
  res.end(typeof data === "string" ? data : JSON.stringify(data));
}

function slugify(value, fallback = "post") {
  const slug = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9\u4e00-\u9fa5_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return slug || fallback;
}

function makeExcerpt(value, size = 200) {
  return excerpt(value, size);
}

function buildFrontMatter(post, body) {
  return normalizeMarkdownDocument(`---\ntitle: ${post.title}\ndate: ${post.date}\ndescription: ${post.description || post.excerpt || ""}\ntags: ${(post.categorySlugs || []).join(", ")}\n---\n\n${body.replace(/^\s+/, "")}`);
}

function deriveCategories(posts) {
  const bySlug = new Map();
  const saved = readJson("data/categories.json", []);
  for (const cat of saved) {
    if (cat && cat.slug) bySlug.set(cat.slug, { ...cat, count: 0 });
  }
  for (const post of posts) {
    for (const cat of post.categories || []) {
      if (!cat || !cat.slug) continue;
      if (!bySlug.has(cat.slug)) bySlug.set(cat.slug, { ...cat, count: 0 });
      bySlug.get(cat.slug).count += 1;
    }
  }
  return Array.from(bySlug.values()).sort((a, b) => String(a.name).localeCompare(String(b.name), "zh-Hans-CN"));
}

function loadPosts() {
  const posts = readJson("data/posts.json", []);
  return posts.map((post) => ({
    ...post,
    slug: post.slug || slugify(post.title, post.cid || "post"),
    categories: post.categories || [],
  }));
}

function savePosts(posts, categories = deriveCategories(posts)) {
  const catBySlug = new Map(categories.map((cat) => [cat.slug, { ...cat, count: 0 }]));
  const normalized = posts
    .map((post) => {
      const categorySlugs = post.categorySlugs || (post.categories || []).map((cat) => cat.slug);
      const categoriesForPost = categorySlugs
        .map((slug) => catBySlug.get(slug))
        .filter(Boolean)
        .map((cat) => ({ ...cat }));
      for (const cat of categoriesForPost) catBySlug.get(cat.slug).count += 1;
      return {
        ...post,
        categories: categoriesForPost,
        categorySlugs: undefined,
      };
    })
    .sort((a, b) => String(b.date || "").localeCompare(String(a.date || "")) || String(b.slug).localeCompare(String(a.slug)));

  const savedCategories = Array.from(catBySlug.values());
  writeJson("data/categories.json", savedCategories);
  writeJson("data/posts.json", normalized);
  execFileSync(process.execPath, ["scripts/build-site.js"], { cwd: ROOT, stdio: "inherit" });
}

function postSource(post) {
  if (post.source) return post.source.replace(/^content\/posts\//, "data/content/posts/");
  return `data/content/posts/${post.slug}.md`;
}

function moveMarkdownSource(from, to) {
  if (from === to) return;
  const fromFull = path.join(ROOT, from);
  const toFull = path.join(ROOT, to);
  if (!fs.existsSync(fromFull)) return;
  fs.mkdirSync(path.dirname(toFull), { recursive: true });
  fs.renameSync(fromFull, toFull);
}

function readPostContent(post) {
  const source = postSource(post);
  const full = path.join(ROOT, source);
  if (!fs.existsSync(full)) return "";
  const raw = fs.readFileSync(full, "utf8");
  return normalizeMarkdownBody(parseFrontMatter(raw).body);
}

function serveFile(res, base, requestPath) {
  try {
    let file = safeJoin(base, requestPath === "/" ? "index.html" : requestPath.replace(/^\/+/, ""));
    if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, "index.html");
    if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) return false;
    const ext = path.extname(file).toLowerCase();
    send(res, 200, fs.readFileSync(file), MIME[ext] || "application/octet-stream");
    return true;
  } catch {
    return false;
  }
}

function getState() {
  const posts = loadPosts();
  const categories = deriveCategories(posts);
  return { posts, categories };
}

function uniqueSlug(posts, desired, currentSlug) {
  let slug = slugify(desired);
  let index = 2;
  const used = new Set(posts.filter((post) => post.slug !== currentSlug).map((post) => post.slug));
  while (used.has(slug)) slug = `${slugify(desired)}-${index++}`;
  return slug;
}

async function handleApi(req, res, url) {
  const posts = loadPosts();
  const categories = deriveCategories(posts);

  if (req.method === "GET" && url.pathname === "/api/state") {
    return send(res, 200, getState());
  }

  if (req.method === "GET" && url.pathname === "/api/post") {
    const slug = url.searchParams.get("slug");
    const post = posts.find((item) => item.slug === slug);
    if (!post) return send(res, 404, { error: "Post not found" });
    return send(res, 200, { post, format: "markdown", body: readPostContent(post) });
  }

  if (req.method === "POST" && url.pathname === "/api/post") {
    const payload = await readBody(req);
    const isCreate = !payload.originalSlug;
    const original = posts.find((item) => item.slug === payload.originalSlug);
    if (!isCreate && !original) return send(res, 404, { error: "Post not found" });

    const slug = uniqueSlug(posts, payload.slug || payload.title, payload.originalSlug);
    const categorySlugs = payload.categorySlugs || [];
    const categoryMap = new Map(categories.map((cat) => [cat.slug, cat]));
    const body = String(payload.body || "");
    const date = payload.date || new Date().toISOString().slice(0, 10);
    const post = {
      ...(original || {}),
      cid: original?.cid || `local-${Date.now()}`,
      slug,
      title: payload.title || "Untitled",
      date,
      modified: new Date().toISOString().slice(0, 10),
      commentsNum: original?.commentsNum || "0",
      categorySlugs,
      categories: categorySlugs.map((catSlug) => categoryMap.get(catSlug)).filter(Boolean),
      excerpt: makeExcerpt(body),
      description: payload.description || makeExcerpt(body),
    };

    const mdPath = `data/content/posts/${slug}.md`;
    if (original) {
      const oldPath = postSource(original);
      moveMarkdownSource(oldPath, mdPath);
    }
    post.source = mdPath;
    post.url = `post.html?slug=${encodeURIComponent(slug)}`;
    writeFile(mdPath, buildFrontMatter(post, body));

    const nextPosts = isCreate ? [post, ...posts] : posts.map((item) => (item.slug === payload.originalSlug ? post : item));
    savePosts(nextPosts, categories);
    return send(res, 200, { ok: true, post });
  }

  if (req.method === "DELETE" && url.pathname === "/api/post") {
    const slug = url.searchParams.get("slug");
    const post = posts.find((item) => item.slug === slug);
    if (!post) return send(res, 404, { error: "Post not found" });
    const source = postSource(post);
    const full = path.join(ROOT, source);
    if (fs.existsSync(full)) fs.rmSync(full, { force: true });
    savePosts(posts.filter((item) => item.slug !== slug), categories);
    return send(res, 200, { ok: true });
  }

  if (req.method === "POST" && url.pathname === "/api/category") {
    const payload = await readBody(req);
    const originalSlug = payload.originalSlug;
    const slug = slugify(payload.slug || payload.name, "category");
    let next = categories.filter((cat) => cat.slug !== originalSlug && cat.slug !== slug);
    const existing = categories.find((cat) => cat.slug === originalSlug || cat.slug === slug);
    const category = {
      ...(existing || {}),
      slug,
      name: payload.name || slug,
      description: payload.description || "",
      type: "category",
      count: 0,
    };
    next.push(category);
    const nextPosts = posts.map((post) => {
      const slugs = (post.categories || []).map((cat) => (cat.slug === originalSlug ? slug : cat.slug));
      return { ...post, categorySlugs: Array.from(new Set(slugs)) };
    });
    savePosts(nextPosts, next);
    return send(res, 200, { ok: true, category });
  }

  if (req.method === "DELETE" && url.pathname === "/api/category") {
    const slug = url.searchParams.get("slug");
    const nextCategories = categories.filter((cat) => cat.slug !== slug);
    const nextPosts = posts.map((post) => ({
      ...post,
      categorySlugs: (post.categories || []).filter((cat) => cat.slug !== slug).map((cat) => cat.slug),
    }));
    savePosts(nextPosts, nextCategories);
    return send(res, 200, { ok: true });
  }

  return send(res, 404, { error: "Not found" });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  try {
    if (url.pathname.startsWith("/api/")) return await handleApi(req, res, url);
    if (url.pathname.startsWith("/site/")) {
      const requestPath = decodeURIComponent(url.pathname.replace(/^\/site\//, ""));
      if (serveFile(res, PUBLIC_ROOT, requestPath || "index.html")) return;
      return send(res, 404, "Not found", "text/plain; charset=utf-8");
    }
    if (url.pathname.startsWith("/public/")) {
      if (serveFile(res, ROOT, decodeURIComponent(url.pathname))) return;
      return send(res, 404, "Not found", "text/plain; charset=utf-8");
    }
    if (url.pathname.startsWith("/assets/") || url.pathname.startsWith("/data/")) {
      const requestPath = decodeURIComponent(url.pathname);
      if (serveFile(res, ADMIN_ROOT, requestPath)) return;
      if (serveFile(res, PUBLIC_ROOT, requestPath)) return;
      return send(res, 404, "Not found", "text/plain; charset=utf-8");
    }
    if (serveFile(res, ADMIN_ROOT, decodeURIComponent(url.pathname))) return;
    return send(res, 404, "Not found", "text/plain; charset=utf-8");
  } catch (error) {
    send(res, 500, { error: error.message });
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`OwO Blog local admin: http://127.0.0.1:${PORT}`);
});
