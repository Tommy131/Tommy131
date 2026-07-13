const fs = require("fs");
const path = require("path");
const { excerpt, normalizeMarkdownDocument, parseFrontMatter } = require("./lib/markdown");

const ROOT = path.resolve(__dirname, "..");
const SITE_DOMAIN = "https://owoblog.com";
const PUBLIC_ROOT = "public";
const PUBLIC_DATA = "public/data/site.json";
const PRISM = `<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-core.min.js" defer></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/autoloader/prism-autoloader.min.js" defer></script>`;

function readJson(file, fallback = []) {
  const full = path.join(ROOT, file);
  if (!fs.existsSync(full)) return fallback;
  return JSON.parse(fs.readFileSync(full, "utf8"));
}

function write(file, content) {
  const full = path.join(ROOT, file);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, "utf8");
}

function escapeXml(value = "") {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function normalizeMarkdownFile(source, fallbackTitle) {
  const full = path.join(ROOT, source);
  if (!fs.existsSync(full)) {
    const created = normalizeMarkdownDocument(`---\ntitle: ${fallbackTitle}\n---\n\n# ${fallbackTitle}\n`);
    write(source, created);
    return created;
  }
  const current = fs.readFileSync(full, "utf8");
  const normalized = normalizeMarkdownDocument(current);
  if (normalized !== current) write(source, normalized);
  return normalized;
}

function activeCategories(posts, categories) {
  const used = new Set(posts.flatMap((post) => (post.categories || []).map((cat) => cat.slug)));
  return categories.filter((cat) => used.has(cat.slug));
}

function normalizePosts(posts, categories) {
  return posts
    .map((post) => {
      const slug = post.slug || path.basename(post.url || "", ".html");
      const source = post.source || `data/content/posts/${slug}.md`;
      const markdown = normalizeMarkdownFile(source, post.title || slug);
      const { meta, body } = parseFrontMatter(markdown);
      const postCategories = (post.categories || []).filter(Boolean);
      return {
        ...post,
        slug,
        source,
        url: `post.html?slug=${encodeURIComponent(slug)}`,
        title: meta.title || post.title || slug,
        date: meta.date || post.date || "",
        modified: post.modified || meta.date || post.date || "",
        description: meta.description || post.description || post.excerpt || excerpt(body),
        excerpt: excerpt(body),
        categories: postCategories,
        tags: postCategories.map((cat) => cat.slug),
        body,
      };
    })
    .sort((a, b) => String(b.date || "").localeCompare(String(a.date || "")) || String(b.slug).localeCompare(String(a.slug)));
}

function publicPosts(posts) {
  return posts.map(({ cid, title, slug, date, modified, description, excerpt: postExcerpt, categories, tags, body, url }) => ({
    cid,
    title,
    slug,
    date,
    modified,
    description,
    excerpt: postExcerpt,
    categories,
    tags,
    body,
    url,
  }));
}

function buildSiteJson(posts, categories) {
  return {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    site: {
      title: "OwO Blog",
      owner: "Tommy131 / HanskiJay",
      domain: SITE_DOMAIN,
      description: "Tommy131 / HanskiJay 的个人博客，记录全栈开发、系统工具、安全实践与生活碎片。",
      hero: {
        eyebrow: "Full-stack developer · Tool builder · Digital garden",
        title: "用代码锻造工具，用工具创造世界。",
        lead: `这里收录了 ${posts.length} 篇文章，并继续记录 Go、PHP、JavaScript、系统工具、网络服务与安全实践。`,
      },
      projects: [
        ["OwO-Tool-Box", "个人万能工具箱，集成网络性能测试、系统优化脚本与开发辅助工具。", "https://github.com/Tommy131/OwO-Tool-Box"],
        ["KuaishouParser", "短视频解析工具，注重稳定 API、清晰边界和可维护的服务结构。", "https://github.com/Tommy131/KuaishouParser"],
        ["OpenSSL-Windows-Issuer", "用于自签发 Windows RDP 加密证书的脚本库，简化证书生成流程。", "https://github.com/Tommy131/OpenSSL-Windows-Issuer"],
        ["OwO-WinDeployer", "基于 WinPE 的离线 Windows 部署方案，关注批量部署和无人值守体验。", "https://github.com/Tommy131/OwO-WinDeployer"],
        ["OwO-FlightAssistant", "跨平台命令行工具与 AI 助手，面向自动化任务、通知和批量操作。", "https://github.com/Tommy131/OwO-FlightAssistant"],
      ].map(([title, description, url], index) => ({ id: String(index + 1).padStart(2, "0"), title, description, url })),
      about: {
        eyebrow: "About",
        title: "你好，我是 Tommy131 / HanskiJay。",
        body: [
          "这里是我的个人数字花园，用来沉淀工具开发、系统维护、网络服务、安全实践和生活观察。",
          "这个博客现在使用 GitHub Pages 静态托管，文章内容由 JSON 数据驱动，页面只在浏览器中按需渲染。",
        ],
      },
    },
    categories: activeCategories(posts, categories),
    posts: publicPosts(posts),
  };
}

function shell({ title, description, page, body }) {
  return `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="${description}">
    <meta name="theme-color" content="#101820">
    <meta property="og:title" content="${title}">
    <meta property="og:description" content="${description}">
    <meta property="og:type" content="website">
    <title>${title}</title>
    <link rel="stylesheet" href="assets/css/styles.css">
    ${PRISM}
  </head>
  <body data-page="${page}">
    <a class="skip-link" href="#main">跳到正文</a>
    <header class="site-header">
      <nav class="nav-shell" aria-label="主导航">
        <a class="brand" href="index.html"><img class="brand-logo" src="assets/img/logo.png" alt="OwO Blog logo"><span class="brand-text">OwOBlog</span></a>
        <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="site-menu"><span></span><span></span><span></span><span class="sr-only">打开菜单</span></button>
        <div class="site-menu" id="site-menu"><a href="index.html#blog">文章</a><a href="index.html#archive">归档</a><a href="index.html#projects">项目</a><a href="about.html">关于</a><button class="theme-toggle" type="button" aria-label="切换主题">Dark</button></div>
      </nav>
    </header>
    ${body}
    <button class="back-to-top" type="button" aria-label="返回顶部">↑</button>
    <footer class="site-footer"><p>© 2026 Tommy131 / HanskiJay. Built for GitHub Pages.</p></footer>
    <script src="assets/js/site.js" defer></script>
  </body>
</html>
`;
}

function renderHome() {
  return shell({
    title: "OwO Blog | Tommy131 / HanskiJay",
    description: "Tommy131 / HanskiJay 的个人博客，记录全栈开发、系统工具、安全实践与生活碎片。",
    page: "home",
    body: `<main id="main" data-home-root><p class="markdown-status">正在加载博客数据...</p></main>`,
  });
}

function renderPost() {
  return shell({
    title: "文章 | OwO Blog",
    description: "OwO Blog article",
    page: "post",
    body: `<main class="article-main" id="main" data-post-root><p class="markdown-status">正在加载文章...</p></main>`,
  });
}

function renderAbout() {
  return shell({
    title: "关于 | OwO Blog",
    description: "关于 Tommy131 / HanskiJay 与 OwO Blog。",
    page: "about",
    body: `<main class="article-main" id="main" data-about-root><p class="markdown-status">正在加载关于页面...</p></main>`,
  });
}

function renderNotFound() {
  return shell({
    title: "页面不存在 | OwO Blog",
    description: "页面不存在",
    page: "not-found",
    body: `<main class="article-main" id="main" data-404-root><section class="article-shell reveal in-view"><p class="eyebrow">404</p><h1>这页还没有被锻造出来。</h1><p>链接可能已经移动，或文章正在整理中。</p><a class="button primary" href="index.html">返回首页</a></section></main>`,
  });
}

function renderSitemap(posts) {
  const latest = posts[0]?.modified || posts[0]?.date || "2026-07-11";
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${SITE_DOMAIN}/</loc><lastmod>${latest}</lastmod></url>
  <url><loc>${SITE_DOMAIN}/about.html</loc><lastmod>${latest}</lastmod></url>
${posts.map((post) => `  <url><loc>${SITE_DOMAIN}/post.html?slug=${escapeXml(post.slug)}</loc><lastmod>${post.modified || post.date}</lastmod></url>`).join("\n")}
</urlset>
`;
}

function updatePublicMetadata(posts) {
  const metadata = posts.map(({ body, ...post }) => post);
  write("data/posts.json", `${JSON.stringify(metadata, null, 2)}\n`);
}

function build() {
  const posts = readJson("data/posts.json", []);
  const categories = readJson("data/categories.json", []);
  const normalized = normalizePosts(posts, categories);
  const siteJson = buildSiteJson(normalized, categories);

  write(PUBLIC_DATA, `${JSON.stringify(siteJson, null, 2)}\n`);
  write(`${PUBLIC_ROOT}/index.html`, renderHome());
  write(`${PUBLIC_ROOT}/post.html`, renderPost());
  write(`${PUBLIC_ROOT}/about.html`, renderAbout());
  write(`${PUBLIC_ROOT}/404.html`, renderNotFound());
  write(`${PUBLIC_ROOT}/sitemap.xml`, renderSitemap(normalized));
  write(`${PUBLIC_ROOT}/robots.txt`, "User-agent: *\nAllow: /\nSitemap: https://owoblog.com/sitemap.xml\n");
  write(`${PUBLIC_ROOT}/.nojekyll`, "");
  updatePublicMetadata(normalized);

  console.log(`built JSON-driven site with ${normalized.length} posts`);
}

build();
