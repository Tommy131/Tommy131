const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const { normalizeMarkdownDocument } = require("./lib/markdown");

const site = {
  title: "OwO Blog",
  owner: "Tommy131 / HanskiJay",
  domain: "https://owoblog.com",
  description: "Tommy131 / HanskiJay 的个人博客，记录全栈开发、系统工具、安全实践与生活碎片。",
  github: "https://github.com/Tommy131",
  instagram: "https://www.instagram.com/jay.jay2045",
};

const source = process.argv[2] || "20260711_owoblog.com_6a515d55e2f33.dat";
const root = process.cwd();

function write(file, content) {
  const full = path.join(root, file);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, "utf8");
}

function parseBackup(file) {
  const buf = fs.readFileSync(path.join(root, file));
  const header = Buffer.from("%TYPECHO_BACKUP_0001%");
  const startAt = buf.indexOf(header);
  if (startAt < 0) throw new Error("未找到 Typecho 备份文件头");

  let pos = startAt + header.length;
  const rows = [];
  while (pos < buf.length) {
    const start = buf.indexOf(0x7b, pos);
    if (start < 0) break;
    const end = buf.indexOf(0x7d, start);
    if (end < 0) break;

    let schema;
    try {
      schema = JSON.parse(buf.subarray(start, end + 1).toString("utf8"));
    } catch {
      pos = start + 1;
      continue;
    }

    pos = end + 1;
    const row = {};
    let ok = true;
    for (const [key, len] of Object.entries(schema)) {
      if (len === null) {
        row[key] = null;
        continue;
      }
      const size = Number(len);
      if (!Number.isFinite(size) || pos + size > buf.length) {
        ok = false;
        break;
      }
      row[key] = buf.subarray(pos, pos + size).toString("utf8");
      pos += size;
    }
    if (!ok) break;
    rows.push(row);
  }
  return rows;
}

function decodeEntities(value = "") {
  const map = { quot: '"', apos: "'", amp: "&", lt: "<", gt: ">" };
  return String(value)
    .replace(/&(quot|apos|amp|lt|gt);/g, (_, key) => map[key])
    .replace(/&#34;/g, '"')
    .replace(/&#39;/g, "'");
}

function esc(value = "") {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function slugify(value, fallback) {
  const slug = decodeEntities(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9\u4e00-\u9fa5_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return slug || String(fallback || "post");
}

function dateOf(value) {
  const date = new Date(Number(value) * 1000);
  return Number.isNaN(date.getTime()) ? "1970-01-01" : date.toISOString().slice(0, 10);
}

function plainText(markdown = "") {
  return decodeEntities(markdown)
    .replace(/<!--markdown-->/g, "")
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/!\[[^\]]*]\([^)]*\)/g, " ")
    .replace(/\[([^\]]+)]\([^)]*\)/g, "$1")
    .replace(/[#>*_`~\-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function excerpt(markdown) {
  const text = plainText(markdown);
  return text.length > 200 ? `${text.slice(0, 200)}...` : text;
}

function inlineMarkdown(line) {
  return line
    .replace(/!\[([^\]]*)]\(([^\s)]+)(?:\s+"([^"]*)")?\)/g, '<img src="$2" alt="$1" title="$3">')
    .replace(/\[([^\]]+)]\(([^\s)]+)(?:\s+"([^"]*)")?\)/g, '<a href="$2">$1</a>')
    .replace(/`([^`]+)`/g, (_, code) => `<code>${esc(code)}</code>`)
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/__([^_]+)__/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>");
}

function markdownToHtml(markdown = "") {
  const lines = decodeEntities(markdown).replace(/^<!--markdown-->/, "").replace(/\r\n/g, "\n").split("\n");
  const out = [];
  let paragraph = [];
  let list = null;
  let code = null;

  const closeParagraph = () => {
    if (!paragraph.length) return;
    out.push(`<p>${inlineMarkdown(paragraph.join(" "))}</p>`);
    paragraph = [];
  };
  const closeList = () => {
    if (!list) return;
    out.push(`</${list}>`);
    list = null;
  };

  for (const raw of lines) {
    const line = raw.trim();
    if (code) {
      if (/^```/.test(line)) {
        out.push(`${esc(code.join("\n"))}</code></pre>`);
        code = null;
      } else {
        code.push(raw);
      }
      continue;
    }
    if (/^```/.test(line)) {
      closeParagraph();
      closeList();
      out.push("<pre><code>");
      code = [];
      continue;
    }
    if (!line) {
      closeParagraph();
      closeList();
      continue;
    }
    if (/^#{1,6}\s+/.test(line)) {
      closeParagraph();
      closeList();
      const level = line.match(/^#+/)[0].length;
      out.push(`<h${level}>${inlineMarkdown(line.replace(/^#{1,6}\s+/, ""))}</h${level}>`);
      continue;
    }
    if (/^>\s?/.test(line)) {
      closeParagraph();
      closeList();
      out.push(`<blockquote>${inlineMarkdown(line.replace(/^>\s?/, ""))}</blockquote>`);
      continue;
    }
    const ul = line.match(/^[-*+]\s+(.+)/);
    const ol = line.match(/^\d+[.)]\s+(.+)/);
    if (ul || ol) {
      closeParagraph();
      const type = ul ? "ul" : "ol";
      if (list && list !== type) closeList();
      if (!list) {
        list = type;
        out.push(`<${type}>`);
      }
      out.push(`<li>${inlineMarkdown((ul || ol)[1])}</li>`);
      continue;
    }
    if (/^<(div|p|table|thead|tbody|tr|td|th|ul|ol|li|pre|blockquote|h[1-6]|img|figure|iframe|hr|br|center)\b/i.test(line)) {
      closeParagraph();
      closeList();
      out.push(line);
      continue;
    }
    paragraph.push(line);
  }
  if (code) out.push(`${esc(code.join("\n"))}</code></pre>`);
  closeParagraph();
  closeList();
  return out.join("\n");
}

function assetPrefix(current = "") {
  return current === "post" ? "../" : "";
}

function shell({ title, description, body, canonical, current = "" }) {
  const prefix = assetPrefix(current);
  return `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="${esc(description || site.description)}">
    <meta name="theme-color" content="#101820">
    <meta property="og:title" content="${esc(title)}">
    <meta property="og:description" content="${esc(description || site.description)}">
    <meta property="og:type" content="website">
    <meta property="og:url" content="${esc(canonical)}">
    <link rel="canonical" href="${esc(canonical)}">
    <title>${esc(title)}</title>
    <link rel="stylesheet" href="assets/css/styles.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-core.min.js" defer></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/autoloader/prism-autoloader.min.js" defer></script>
  </head>
  <body>
    <a class="skip-link" href="#main">跳到正文</a>
    <header class="site-header">
      <nav class="nav-shell" aria-label="主导航">
        <a class="brand" href="${prefix}index.html"><img class="brand-logo" src="assets/img/logo.png" alt="OwO Blog logo"><span class="brand-text">Blog</span></a>
        <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="site-menu"><span></span><span></span><span></span><span class="sr-only">打开菜单</span></button>
        <div class="site-menu" id="site-menu">
          <a href="${prefix}index.html#blog">文章</a>
          <a href="${prefix}index.html#archive">归档</a>
          <a href="${prefix}index.html#projects">项目</a>
          <a href="${prefix}about.html">关于</a>
          <button class="theme-toggle" type="button" aria-label="切换主题">☾</button>
        </div>
      </nav>
    </header>
${body}
    <button class="back-to-top" type="button" aria-label="返回顶部">↑</button>
    <footer class="site-footer"><p>© 2026 ${esc(site.owner)}. Built for GitHub Pages.</p></footer>
    <script src="assets/js/site.js" defer></script>
  </body>
</html>
`;
}

function article(post) {
  const tags = post.categories.map((cat) => `<span>${esc(cat.name)}</span>`).join("");
  return shell({
    title: `${post.title} | ${site.title}`,
    description: post.excerpt,
    canonical: `${site.domain}/${post.url}`,
    current: "post",
    body: `<main class="article-main" id="main">
      <article class="article-shell reveal">
        <a class="breadcrumb" href="../index.html#archive">← 返回文章归档</a>
        <header class="article-header">
          <p class="eyebrow">${esc(post.date)} · ${esc(post.categories[0]?.name || "Blog")}</p>
          <h1>${esc(post.title)}</h1>
          <p class="article-meta">${esc(post.date)} · 评论数: ${esc(post.commentsNum || "0")}</p>
          <div class="article-tags">${tags}</div>
        </header>
        <div class="article-content">${markdownToHtml(post.text)}</div>
      </article>
    </main>`,
  });
}

function redirect(to) {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="refresh" content="0; url=../../${esc(to)}"><link rel="canonical" href="../../${esc(to)}"><title>正在跳转 | OwO Blog</title></head><body><p>正在跳转到 <a href="../../${esc(to)}">${esc(to)}</a>。</p></body></html>`;
}

function indexPage(posts, categories) {
  const activeCategorySlugs = new Set(posts.flatMap((post) => post.categories.map((cat) => cat.slug)));
  const chips = categories
    .filter((cat) => activeCategorySlugs.has(cat.slug))
    .map((cat) => `<button class="filter-chip" type="button" data-filter="${esc(cat.slug)}">${esc(cat.name)}</button>`)
    .join("\n          ");
  const cards = posts
    .slice(0, 6)
    .map(
      (post) => `<article class="post-card reveal" data-tags="${post.categories.map((cat) => esc(cat.slug)).join(" ")}"><a href="${esc(post.url)}"><time class="post-date" datetime="${esc(post.date)}">${esc(post.date)}</time><div class="post-summary"><h3>${esc(post.title)}</h3><p>${esc(post.excerpt || "暂无摘要")}</p></div><span class="post-link">阅读全文 →</span></a></article>`
    )
    .join("\n");
  const archive = posts
    .map(
      (post) => `<a class="archive-item reveal" href="${esc(post.url)}" data-tags="${post.categories.map((cat) => esc(cat.slug)).join(" ")}"><time datetime="${esc(post.date)}">${esc(post.date)}</time><span>${esc(post.title)}</span><small>${esc(post.categories.map((cat) => cat.name).join(" / ") || "未分类")}</small></a>`
    )
    .join("\n");

  return shell({
    title: `${site.title} | ${site.owner}`,
    description: site.description,
    canonical: `${site.domain}/`,
    body: `<main id="main">
      <section class="hero section-frame" id="top">
        <div class="hero-copy reveal">
          <p class="eyebrow">Full-stack developer · Tool builder · Digital garden</p>
          <h1>用代码锻造工具，用工具创造世界。</h1>
          <p class="hero-lead">这里收录了 ${posts.length} 篇文章，并继续记录 Go、PHP、JavaScript、系统工具、网络服务与安全实践。</p>
          <div class="hero-actions"><a class="button primary" href="#blog">阅读文章</a><a class="button ghost" href="${site.github}" rel="me">GitHub</a></div>
        </div>
        <aside class="hero-card reveal">
          <div class="orbital-card"><span class="status-dot"></span><p>${esc(site.owner)}</p><strong>China ↔ Germany</strong><small>UTC+02:00 · building useful things</small></div>
          <div class="metric-grid"><div><strong>${posts.length}</strong><span>历史文章</span></div><div><strong>${categories.filter((cat) => cat.count > 0).length}</strong><span>分类</span></div><div><strong>∞</strong><span>Ideas in progress</span></div></div>
        </aside>
      </section>
      <section class="section-frame" id="blog"><div class="section-heading reveal"><p class="eyebrow">Notebook</p><h2>最新文章</h2><p>这里会持续整理项目复盘、工程踩坑、工具设计和系统实践。</p></div><div class="filter-row reveal"><button class="filter-chip active" type="button" data-filter="all">全部</button>${chips ? "\n          " + chips : ""}</div><div class="blog-grid">${cards}</div></section>
      <section class="section-frame" id="archive"><div class="section-heading reveal"><p class="eyebrow">Archive</p><h2>全部归档</h2><p>按发布时间倒序排列，共 ${posts.length} 篇。</p></div><div class="archive-list">${archive}</div></section>
      <section class="section-frame" id="projects"><div class="section-heading reveal"><p class="eyebrow">Forge</p><h2>精选项目</h2></div><div class="project-list">
        <a class="project-card reveal" href="https://github.com/Tommy131/OwO-Tool-Box"><span>01</span><div><h3>OwO-Tool-Box</h3><p>个人万能工具箱，集成网络性能测试、系统优化脚本与开发辅助工具。</p></div></a>
        <a class="project-card reveal" href="https://github.com/Tommy131/KuaishouParser"><span>02</span><div><h3>KuaishouParser</h3><p>短视频解析工具，注重稳定 API、清晰边界和可维护的服务结构。</p></div></a>
        <a class="project-card reveal" href="https://github.com/Tommy131/OpenSSL-Windows-Issuer"><span>03</span><div><h3>OpenSSL-Windows-Issuer</h3><p>用于自签发 Windows RDP 加密证书的脚本库，简化证书生成流程。</p></div></a>
        <a class="project-card reveal" href="https://github.com/Tommy131/OwO-WinDeployer"><span>04</span><div><h3>OwO-WinDeployer</h3><p>基于 WinPE 的离线 Windows 部署方案，关注批量部署和无人值守体验。</p></div></a>
        <a class="project-card reveal" href="https://github.com/Tommy131/OwO-FlightAssistant"><span>05</span><div><h3>OwO-FlightAssistant</h3><p>跨平台命令行工具与 AI 助手，面向自动化任务、通知和批量操作。</p></div></a>
      </div></section>
      <section class="section-frame contact-band reveal" id="contact"><div><p class="eyebrow">Connect</p><h2>有技术问题或合作想法？</h2><p>欢迎通过 GitHub Issues、项目讨论或社交账号联系我。</p></div><div class="contact-actions"><a class="button primary" href="${site.github}">GitHub Profile</a><a class="button ghost" href="${site.instagram}">Instagram</a></div></section>
    </main>`,
  });
}

function aboutPage(page) {
  return shell({
    title: `关于 | ${site.title}`,
    description: `关于 ${site.owner}`,
    canonical: `${site.domain}/about.html`,
    body: `<main class="article-main" id="main"><article class="article-shell reveal"><a class="breadcrumb" href="index.html">← 返回首页</a><header class="article-header"><p class="eyebrow">About</p><h1>关于我</h1></header><div class="article-content">${page ? markdownToHtml(page.text) : "<p>这里是关于页面，未来可以补充更完整的个人介绍。</p>"}<div class="stack-cloud"><span>Go</span><span>PHP</span><span>Dart</span><span>JavaScript</span><span>Java</span><span>Shell</span><span>OpenSSL</span><span>Docker</span><span>Nginx</span><span>MySQL</span><span>Redis</span><span>MongoDB</span></div></div></article></main>`,
  });
}

function notFoundPage() {
  return shell({
    title: `页面不存在 | ${site.title}`,
    description: "页面不存在",
    canonical: `${site.domain}/404.html`,
    body: `<main class="article-main" id="main"><section class="article-shell reveal in-view"><p class="eyebrow">404</p><h1>这页还没有被锻造出来。</h1><p>链接可能已经移动，或者文章还在构思中。回到首页继续探索吧。</p><a class="button primary" href="index.html">返回首页</a></section></main>`,
  });
}

function main() {
  const rows = parseBackup(source);
  const categories = rows
    .filter((row) => row.type === "category")
    .map((row) => ({ ...row, name: decodeEntities(row.name), slug: slugify(row.slug || row.name, row.mid), count: Number(row.count || 0) }));
  const categoryByMid = new Map(categories.map((cat) => [cat.mid, cat]));
  const byCid = new Map();
  for (const relation of rows.filter((row) => Object.keys(row).length === 2 && row.cid && row.mid)) {
    const cat = categoryByMid.get(relation.mid);
    if (!cat) continue;
    if (!byCid.has(relation.cid)) byCid.set(relation.cid, []);
    byCid.get(relation.cid).push(cat);
  }

  const used = new Set();
  const posts = rows
    .filter((row) => row.type === "post" && row.status === "publish")
    .map((row) => {
      const title = decodeEntities(row.title || `Post ${row.cid}`);
      let slug = slugify(row.slug, row.cid);
      if (used.has(slug)) slug = `${slug}-${row.cid}`;
      used.add(slug);
      return {
        cid: row.cid,
        slug,
        url: `post.html?slug=${encodeURIComponent(slug)}`,
        source: `data/content/posts/${slug}.md`,
        title,
        text: row.text || "",
        date: dateOf(row.created),
        modified: dateOf(row.modified || row.created),
        commentsNum: row.commentsNum || "0",
        categories: byCid.get(row.cid) || [],
        excerpt: excerpt(row.text || ""),
      };
    })
    .sort((a, b) => b.date.localeCompare(a.date) || Number(b.cid) - Number(a.cid));

  for (const post of posts) {
    const tags = post.categories.map((cat) => cat.slug).join(", ");
    write(
      post.source,
      normalizeMarkdownDocument(`---\ntitle: ${post.title}\ndate: ${post.date}\ndescription: ${post.excerpt}\ntags: ${tags}\n---\n\n${post.text}\n`)
    );
  }

  write("data/categories.json", `${JSON.stringify(categories, null, 2)}\n`);
  write("data/posts.json", `${JSON.stringify(posts.map(({ text, ...post }) => post), null, 2)}\n`);
  execFileSync(process.execPath, ["scripts/build-site.js"], { cwd: root, stdio: "inherit" });
  console.log(`Migrated ${posts.length} posts, ${categories.length} categories from ${source}`);
}

main();
