(function () {
  const root = document.documentElement;
  const savedTheme = localStorage.getItem("owo-theme");
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;

  const syncThemeColor = () => {
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", root.dataset.theme === "dark" ? "#12182a" : "#f3f5f8");
  };

  if (savedTheme) root.dataset.theme = savedTheme;
  else if (prefersDark) root.dataset.theme = "dark";
  syncThemeColor();

  if (window.Prism?.plugins?.autoloader) {
    window.Prism.plugins.autoloader.languages_path =
      "https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/";
  }

  const escapeHtml = (value) =>
    String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");

  const normalizeLanguage = (lang) => {
    const key = String(lang || "").trim().toLowerCase();
    const aliases = {
      bat: "batch",
      cmd: "batch",
      js: "javascript",
      mjs: "javascript",
      cjs: "javascript",
      ts: "typescript",
      rs: "rust",
      py: "python",
      rb: "ruby",
      sh: "bash",
      shell: "bash",
      zsh: "bash",
      ps1: "powershell",
      pwsh: "powershell",
      yml: "yaml",
      dockerfile: "docker",
      html: "markup",
      xml: "markup",
      svg: "markup",
      nginxconf: "nginx",
      conf: "ini",
      cfg: "ini",
      cnf: "ini",
      env: "properties",
      props: "properties",
    };
    return aliases[key] || key || "text";
  };

  const TOKEN_OPEN = "\uE000";
  const TOKEN_CLOSE = "\uE001";
  const MARKDOWN_ESCAPABLE = new Set("\\`*{}[]()#+-.!_|>~".split(""));

  const makeToken = (type, index) => `${TOKEN_OPEN}${type}${index}${TOKEN_CLOSE}`;
  const tokenPattern = (type) => new RegExp(`${TOKEN_OPEN}${type}(\\d+)${TOKEN_CLOSE}`, "g");

  const isEscaped = (text, index) => {
    let slashCount = 0;
    for (let i = index - 1; i >= 0 && text[i] === "\\"; i -= 1) slashCount += 1;
    return slashCount % 2 === 1;
  };

  const protectMarkdownEscapes = (value) => {
    const replacements = [];
    let output = "";
    const text = String(value ?? "");

    for (let i = 0; i < text.length; i += 1) {
      const current = text[i];
      const next = text[i + 1];
      if (current === "\\" && MARKDOWN_ESCAPABLE.has(next)) {
        replacements.push(escapeHtml(next));
        output += makeToken("e", replacements.length - 1);
        i += 1;
      } else {
        output += current;
      }
    }

    return {
      text: output,
      restore: (html) => String(html).replace(tokenPattern("e"), (_, index) => replacements[Number(index)] ?? ""),
    };
  };

  const renderInlineMarkdown = (text) => {
    const escaped = protectMarkdownEscapes(text);
    const codeTokens = [];
    let html = escapeHtml(escaped.text);
    html = html.replace(/`([^`]+)`/g, (_, code) => {
      codeTokens.push(`<code>${escaped.restore(code)}</code>`);
      return makeToken("c", codeTokens.length - 1);
    });
    html = html.replace(/!\[([^\]]*)\]\(([^)\s]+)(?:\s+"([^"]*)")?\)/g, '<img src="$2" alt="$1" title="$3">');
    html = html.replace(/\[([^\]]+)\]\(([^)\s]+)(?:\s+"([^"]*)")?\)/g, '<a href="$2">$1</a>');
    html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    html = html.replace(/__([^_]+)__/g, "<strong>$1</strong>");
    html = html.replace(/\*([^*]+)\*/g, "<em>$1</em>");
    html = html.replace(/_([^_]+)_/g, "<em>$1</em>");
    html = html.replace(tokenPattern("c"), (_, index) => codeTokens[Number(index)] ?? "");
    html = escaped.restore(html);
    return html;
  };

  const hasUnescapedPipe = (line) => {
    const text = String(line ?? "");
    for (let index = text.indexOf("|"); index !== -1; index = text.indexOf("|", index + 1)) {
      if (!isEscaped(text, index)) return true;
    }
    return false;
  };

  const trimTableEdgePipes = (row) => {
    let value = String(row ?? "").trim();
    if (value[0] === "|" && !isEscaped(value, 0)) value = value.slice(1);
    const lastIndex = value.length - 1;
    if (lastIndex >= 0 && value[lastIndex] === "|" && !isEscaped(value, lastIndex)) value = value.slice(0, -1);
    return value;
  };

  const splitTableRow = (row) => {
    const value = trimTableEdgePipes(row);
    const cells = [];
    let cell = "";

    for (let i = 0; i < value.length; i += 1) {
      if (value[i] === "|" && !isEscaped(value, i)) {
        cells.push(cell.trim());
        cell = "";
      } else {
        cell += value[i];
      }
    }
    cells.push(cell.trim());
    return cells;
  };

  const isTableSeparator = (line) => {
    const text = String(line ?? "").trim();
    if (!hasUnescapedPipe(text)) return false;
    const cells = splitTableRow(text);
    return cells.length > 0 && cells.every((cell) => /^:?-{3,}:?$/.test(cell.trim()));
  };

  const renderMarkdownTable = (rows) => {
    const cells = rows.map(splitTableRow);
    const header = cells[0] || [];
    const body = cells.slice(2);
    return `<div class="table-scroll"><table><thead><tr>${header.map((cell) => `<th>${renderInlineMarkdown(cell)}</th>`).join("")}</tr></thead><tbody>${body
      .map((row) => `<tr>${row.map((cell) => `<td>${renderInlineMarkdown(cell)}</td>`).join("")}</tr>`)
      .join("")}</tbody></table></div>`;
  };

  const renderCodeBlock = (lang, source) => {
    const safeLang = String(normalizeLanguage(lang)).replace(/[^a-z0-9-]/g, "") || "text";
    const label = safeLang === "text" ? "" : `<span class="code-lang">${escapeHtml(safeLang)}</span>`;
    return `<div class="code-block">${label}<pre class="language-${safeLang}"><code class="language-${safeLang}">${escapeHtml(source)}</code></pre></div>`;
  };

  const markdownToHtml = (markdown) => {
    const lines = String(markdown || "").replace(/\r\n/g, "\n").split("\n");
    const out = [];
    let paragraph = [];
    let list = null;
    let code = null;
    let table = [];

    const closeParagraph = () => {
      if (!paragraph.length) return;
      out.push(`<p>${renderInlineMarkdown(paragraph.join(" "))}</p>`);
      paragraph = [];
    };
    const closeList = () => {
      if (!list) return;
      out.push(`</${list}>`);
      list = null;
    };
    const closeTable = () => {
      if (!table.length) return;
      out.push(renderMarkdownTable(table));
      table = [];
    };

    lines.forEach((raw, index) => {
      const line = raw.trim();
      if (code) {
        if (/^```/.test(line)) {
          out.push(renderCodeBlock(code.lang, code.lines.join("\n")));
          code = null;
        } else {
          code.lines.push(raw);
        }
        return;
      }
      if (/^```/.test(line)) {
        closeParagraph();
        closeList();
        closeTable();
        code = { lang: line.replace(/^```/, "").trim(), lines: [] };
        return;
      }
      if (table.length && !hasUnescapedPipe(line)) closeTable();
      if (!line) {
        closeParagraph();
        closeList();
        closeTable();
        return;
      }
      if (hasUnescapedPipe(line) && isTableSeparator(lines[index + 1] || "")) {
        closeParagraph();
        closeList();
        table.push(line);
        return;
      }
      if (table.length) {
        table.push(line);
        return;
      }
      const heading = line.match(/^(#{1,6})\s+(.+)$/);
      if (heading) {
        closeParagraph();
        closeList();
        const level = heading[1].length;
        out.push(`<h${level}>${renderInlineMarkdown(heading[2].trim())}</h${level}>`);
        return;
      }
      if (/^>\s?/.test(line)) {
        closeParagraph();
        closeList();
        out.push(`<blockquote>${renderInlineMarkdown(line.replace(/^>\s?/, ""))}</blockquote>`);
        return;
      }
      if (/^---+$/.test(line)) {
        closeParagraph();
        closeList();
        out.push("<hr>");
        return;
      }
      const unordered = line.match(/^[-*+]\s+(.+)/);
      const ordered = line.match(/^\d+[.)]\s+(.+)/);
      if (unordered || ordered) {
        closeParagraph();
        const type = unordered ? "ul" : "ol";
        if (list && list !== type) closeList();
        if (!list) {
          list = type;
          out.push(`<${type}>`);
        }
        out.push(`<li>${renderInlineMarkdown((unordered || ordered)[1])}</li>`);
        return;
      }
      paragraph.push(line);
    });

    if (code) out.push(renderCodeBlock(code.lang, code.lines.join("\n")));
    closeParagraph();
    closeList();
    closeTable();
    return out.join("\n");
  };

  const loadSiteData = async () => {
    const response = await fetch("data/site.json", { cache: "no-cache" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  };

  const postUrl = (post) => `post.html?slug=${encodeURIComponent(post.slug)}`;

  const heroTitleHtml = (title) => {
    const text = String(title || "");
    const parts = text.split(/(?<=[，,])/).map((part) => part.trim()).filter(Boolean);
    const lines = parts.length > 1 ? parts : [text];
    return lines.map((line) => `<span class="hero-line">${escapeHtml(line)}</span>`).join("");
  };

  const renderHome = (data) => {
    const main = document.querySelector("[data-home-root]");
    if (!main) return;
    const { site, posts, categories } = data;
    const chips = categories
      .map((cat) => `<button class="filter-chip" type="button" data-filter="${escapeHtml(cat.slug)}">${escapeHtml(cat.name)}</button>`)
      .join("");
    const cards = posts
      .slice(0, 6)
      .map(
        (post) => `<article class="post-card" data-tags="${(post.tags || []).map(escapeHtml).join(" ")}"><a href="${postUrl(post)}"><time class="post-date" datetime="${escapeHtml(post.date)}">${escapeHtml(post.date)}</time><div class="post-summary"><h3>${escapeHtml(post.title)}</h3><p>${escapeHtml(post.excerpt || "暂无摘要")}</p></div><span class="post-link">阅读全文</span></a></article>`
      )
      .join("");
    const archive = posts
      .map(
        (post) => `<a class="archive-item" href="${postUrl(post)}" data-tags="${(post.tags || []).map(escapeHtml).join(" ")}"><time datetime="${escapeHtml(post.date)}">${escapeHtml(post.date)}</time><span>${escapeHtml(post.title)}</span><small>${escapeHtml((post.categories || []).map((cat) => cat.name).join(" / ") || "未分类")}</small></a>`
      )
      .join("");
    const projects = site.projects
      .map(
        (project) => `<a class="project-card" href="${escapeHtml(project.url)}"><div><h3>${escapeHtml(project.title)}</h3><p>${escapeHtml(project.description)}</p></div><span class="project-open">打开</span></a>`
      )
      .join("");
    const newestYear = String(posts[0]?.date || "").slice(0, 4);
    const oldestYear = String(posts[posts.length - 1]?.date || "").slice(0, 4);
    const archiveEyebrow = newestYear && oldestYear ? (newestYear === oldestYear ? newestYear : `${oldestYear}–${newestYear}`) : `${posts.length} 篇`;

    main.innerHTML = `
      <section class="hero section-frame" id="top">
        <div class="hero-copy">
          <p class="eyebrow">${escapeHtml(site.hero.eyebrow)}</p>
          <h1 class="display">${heroTitleHtml(site.hero.title)}</h1>
          <p class="hero-lead">${escapeHtml(site.hero.lead)}</p>
          <div class="hero-actions"><a class="button primary" href="#blog">阅读文章</a><a class="button ghost" href="https://github.com/Tommy131" rel="me">GitHub</a></div>
        </div>
        <aside class="stamp-card">
          <div class="stamp" aria-hidden="true"><img src="assets/img/logo.png" alt=""><span class="stamp-ring"></span></div>
          <p class="stamp-owner">${escapeHtml(site.owner)}</p>
          <ul class="meridians"><li>China</li><li>Germany</li></ul>
          <p class="stamp-meta">UTC+02</p>
        </aside>
      </section>
      <section class="section-frame" id="blog"><div class="section-heading"><p class="eyebrow">${posts.length} notes</p><h2>最新文章</h2><p>这里会持续整理项目复盘、工程踩坑、工具设计和系统实践。</p></div><div class="filter-row"><button class="filter-chip active" type="button" data-filter="all">全部</button>${chips}</div><div class="filter-feedback"><p class="filter-status" role="status" data-filter-status></p><button class="button ghost" type="button" data-clear-filter hidden>查看全部</button></div><div class="blog-grid">${cards}</div></section>
      <section class="section-frame" id="archive"><div class="section-heading"><p class="eyebrow">${escapeHtml(archiveEyebrow)}</p><h2>全部归档</h2><p>按发布时间倒序排列，共 ${posts.length} 篇。</p></div><div class="archive-list">${archive}</div></section>
      <section class="section-frame" id="projects"><div class="section-heading"><p class="eyebrow">${site.projects.length} tools</p><h2>精选项目</h2></div><div class="project-list">${projects}</div></section>`;
  };

  const renderPost = (data) => {
    const main = document.querySelector("[data-post-root]");
    if (!main) return;
    const slug = new URLSearchParams(window.location.search).get("slug");
    const post = data.posts.find((item) => item.slug === slug) || data.posts[0];
    if (!post) {
      main.innerHTML = '<section class="article-shell"><h1>没有可显示的文章</h1><p>归档里还没有可以打开的文章。</p><a class="button primary" href="index.html">返回首页</a></section>';
      return;
    }
    document.title = `${post.title} | OwO Blog`;
    const description = document.querySelector('meta[name="description"]');
    if (description) description.setAttribute("content", post.description || post.excerpt || "");
    const tags = (post.categories || []).map((cat) => `<span>${escapeHtml(cat.name)}</span>`).join("");
    main.innerHTML = `<article class="article-shell">
        <a class="breadcrumb" href="index.html#archive">← 返回文章归档</a>
        <header class="article-header">
          <p class="eyebrow">${escapeHtml(post.date || "Markdown")}</p>
          <h1>${escapeHtml(post.title)}</h1>
          <div class="article-tags">${tags}</div>
        </header>
        <div class="article-content markdown-content">${markdownToHtml(post.body)}</div>
      </article>`;
    if (window.Prism) window.Prism.highlightAllUnder(main);
  };

  const renderAbout = (data) => {
    const main = document.querySelector("[data-about-root]");
    if (!main) return;
    const about = data.site.about;
    main.innerHTML = `<article class="article-shell"><a class="breadcrumb" href="index.html">← 返回首页</a><header class="article-header"><p class="eyebrow">${escapeHtml(about.eyebrow)}</p><h1>${escapeHtml(about.title)}</h1></header><div class="article-content">${about.body.map((item) => `<p>${escapeHtml(item)}</p>`).join("")}</div></article>`;
  };

  const redirectLegacyPost = () => {
    const match = window.location.pathname.match(/\/posts\/([^/]+)\.html$/);
    if (!match) return false;
    const target = window.location.pathname.replace(/\/posts\/[^/]+\.html$/, `/post.html?slug=${encodeURIComponent(match[1])}`);
    window.location.replace(target);
    return true;
  };

  const syncThemeButtons = () => {
    const isDark = root.dataset.theme === "dark";
    document.querySelectorAll(".theme-toggle").forEach((button) => {
      button.textContent = isDark ? "Light" : "Dark";
    });
    syncThemeColor();
  };

  const applyFilter = (filter) => {
    const name = filter || "all";
    document.querySelectorAll(".filter-chip").forEach((chip) => {
      chip.classList.toggle("active", chip.dataset.filter === name);
    });
    let visible = 0;
    let visibleCards = 0;
    document.querySelectorAll(".archive-item").forEach((card) => {
      const tags = card.dataset.tags || "";
      const hide = name !== "all" && !tags.split(/\s+/).includes(name);
      card.classList.toggle("is-hidden", hide);
      if (!hide) visible += 1;
    });
    document.querySelectorAll(".post-card").forEach((card) => {
      const tags = card.dataset.tags || "";
      const hide = name !== "all" && !tags.split(/\s+/).includes(name);
      card.classList.toggle("is-hidden", hide);
      if (!hide) visibleCards += 1;
    });
    const status = document.querySelector("[data-filter-status]");
    const clear = document.querySelector("[data-clear-filter]");
    if (!status) return;
    if (visible === 0) status.textContent = "这个分类还没有文章。";
    else if (visibleCards === 0) status.textContent = `显示 ${visible} 篇。文章在下方归档。`;
    else status.textContent = `显示 ${visible} 篇。`;
    status.classList.toggle("sr-only", name === "all");
    if (clear) clear.hidden = visible !== 0;
  };

  const bindFilters = () => {
    document.querySelectorAll(".filter-chip").forEach((button) => {
      if (button.dataset.bound === "true") return;
      button.dataset.bound = "true";
      button.addEventListener("click", () => applyFilter(button.dataset.filter));
    });
    const clear = document.querySelector("[data-clear-filter]");
    if (clear && clear.dataset.bound !== "true") {
      clear.dataset.bound = "true";
      clear.addEventListener("click", () => applyFilter("all"));
    }
  };

  const loadingMessage = () => {
    const page = document.body.dataset.page;
    if (page === "post") return "正在加载文章...";
    if (page === "about") return "正在加载关于页面...";
    return "正在加载博客数据...";
  };

  let shellReady = false;
  let updateReadingProgress = () => {};

  const initInteractions = () => {
    bindFilters();
    updateReadingProgress();
    if (shellReady) return;
    shellReady = true;

    document.querySelectorAll(".theme-toggle").forEach((button) => {
      button.addEventListener("click", () => {
        const nextTheme = root.dataset.theme === "dark" ? "light" : "dark";
        root.dataset.theme = nextTheme;
        localStorage.setItem("owo-theme", nextTheme);
        syncThemeButtons();
      });
    });
    syncThemeButtons();

    const navToggle = document.querySelector(".nav-toggle");
    const siteMenu = document.querySelector("#site-menu");
    if (navToggle && siteMenu) {
      navToggle.addEventListener("click", () => {
        const isOpen = siteMenu.classList.toggle("open");
        navToggle.setAttribute("aria-expanded", String(isOpen));
      });
    }

    const backToTop = document.querySelector(".back-to-top");
    if (backToTop) {
      window.addEventListener("scroll", () => backToTop.classList.toggle("visible", window.scrollY > 560), { passive: true });
      backToTop.addEventListener("click", () => {
        const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        window.scrollTo({ top: 0, behavior: reduce ? "auto" : "smooth" });
      });
    }

    const bar = document.querySelector("[data-reading-progress]");
    if (bar && document.body.dataset.page === "post") {
      const span = bar.querySelector("span");
      updateReadingProgress = () => {
        const article = document.querySelector(".article-content");
        if (!article || !span) {
          bar.hidden = true;
          return;
        }
        bar.hidden = false;
        const start = article.offsetTop - 96;
        const distance = Math.max(article.offsetHeight - window.innerHeight * 0.45, 1);
        const progress = Math.min(1, Math.max(0, (window.scrollY - start) / distance));
        span.style.transform = `scaleX(${progress})`;
      };
      window.addEventListener("scroll", updateReadingProgress, { passive: true });
      window.addEventListener("resize", updateReadingProgress);
      updateReadingProgress();
    }
  };

  let booting = false;

  const boot = async () => {
    if (booting) return;
    if (document.body.dataset.page === "not-found" && redirectLegacyPost()) return;
    booting = true;
    try {
      const data = await loadSiteData();
      if (document.body.dataset.page === "home") renderHome(data);
      if (document.body.dataset.page === "post") renderPost(data);
      if (document.body.dataset.page === "about") renderAbout(data);
      initInteractions();
    } catch (error) {
      const target = document.querySelector("main");
      if (document.body.dataset.page === "not-found") {
        initInteractions();
      } else if (target) {
        target.innerHTML = `<div class="load-failure"><p class="markdown-status" role="alert">站点数据加载失败：${escapeHtml(error.message)}</p><button class="button primary" type="button" data-retry>重试</button></div>`;
        target.querySelector("[data-retry]")?.addEventListener("click", () => {
          target.innerHTML = `<p class="markdown-status" role="status">${loadingMessage()}</p>`;
          boot();
        });
        initInteractions();
      }
    } finally {
      booting = false;
    }
  };

  boot();
})();
