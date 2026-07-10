(function () {
  const root = document.documentElement;
  const savedTheme = localStorage.getItem("owo-theme");
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;

  if (savedTheme) root.dataset.theme = savedTheme;
  else if (prefersDark) root.dataset.theme = "dark";

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
    return `<table><thead><tr>${header.map((cell) => `<th>${renderInlineMarkdown(cell)}</th>`).join("")}</tr></thead><tbody>${body
      .map((row) => `<tr>${row.map((cell) => `<td>${renderInlineMarkdown(cell)}</td>`).join("")}</tr>`)
      .join("")}</tbody></table>`;
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
          const lang = normalizeLanguage(code.lang);
          out.push(`<pre class="language-${lang}"><code class="language-${lang}">${escapeHtml(code.lines.join("\n"))}</code></pre>`);
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

    if (code) {
      const lang = normalizeLanguage(code.lang);
      out.push(`<pre class="language-${lang}"><code class="language-${lang}">${escapeHtml(code.lines.join("\n"))}</code></pre>`);
    }
    closeParagraph();
    closeList();
    closeTable();
    return out.join("\n");
  };

  const loadSiteData = async () => {
    const response = await fetch("/data/site.json", { cache: "no-cache" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  };

  const postUrl = (post) => `post.html?slug=${encodeURIComponent(post.slug)}`;

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
        (post) => `<article class="post-card reveal" data-tags="${(post.tags || []).map(escapeHtml).join(" ")}"><a href="${postUrl(post)}"><time class="post-date" datetime="${escapeHtml(post.date)}">${escapeHtml(post.date)}</time><div class="post-summary"><h3>${escapeHtml(post.title)}</h3><p>${escapeHtml(post.excerpt || "暂无摘要")}</p></div><span class="post-link">阅读全文 →</span></a></article>`
      )
      .join("");
    const archive = posts
      .map(
        (post) => `<a class="archive-item reveal" href="${postUrl(post)}" data-tags="${(post.tags || []).map(escapeHtml).join(" ")}"><time datetime="${escapeHtml(post.date)}">${escapeHtml(post.date)}</time><span>${escapeHtml(post.title)}</span><small>${escapeHtml((post.categories || []).map((cat) => cat.name).join(" / ") || "未分类")}</small></a>`
      )
      .join("");
    const projects = site.projects
      .map(
        (project) => `<a class="project-card reveal" href="${escapeHtml(project.url)}"><span>${escapeHtml(project.id)}</span><div><h3>${escapeHtml(project.title)}</h3><p>${escapeHtml(project.description)}</p></div></a>`
      )
      .join("");

    main.innerHTML = `
      <section class="hero section-frame" id="top">
        <div class="hero-copy reveal">
          <p class="eyebrow">${escapeHtml(site.hero.eyebrow)}</p>
          <h1>${escapeHtml(site.hero.title)}</h1>
          <p class="hero-lead">${escapeHtml(site.hero.lead)}</p>
          <div class="hero-actions"><a class="button primary" href="#blog">阅读文章</a><a class="button ghost" href="https://github.com/Tommy131" rel="me">GitHub</a></div>
        </div>
        <aside class="hero-card reveal"><div class="orbital-card"><span class="status-dot"></span><p>${escapeHtml(site.owner)}</p><strong>China ↔ Germany</strong><small>UTC+02:00 · building useful things</small></div><div class="metric-grid"><div><strong>${posts.length}</strong><span>历史文章</span></div><div><strong>${categories.length}</strong><span>分类</span></div><div><strong>∞</strong><span>Ideas in progress</span></div></div></aside>
      </section>
      <section class="section-frame" id="blog"><div class="section-heading reveal"><p class="eyebrow">Notebook</p><h2>最新文章</h2><p>这里会持续整理项目复盘、工程踩坑、工具设计和系统实践。</p></div><div class="filter-row reveal"><button class="filter-chip active" type="button" data-filter="all">全部</button>${chips}</div><div class="blog-grid">${cards}</div></section>
      <section class="section-frame" id="archive"><div class="section-heading reveal"><p class="eyebrow">Archive</p><h2>全部归档</h2><p>按发布时间倒序排列，共 ${posts.length} 篇。</p></div><div class="archive-list">${archive}</div></section>
      <section class="section-frame" id="projects"><div class="section-heading reveal"><p class="eyebrow">Forge</p><h2>精选项目</h2></div><div class="project-list">${projects}</div></section>`;
  };

  const renderPost = (data) => {
    const main = document.querySelector("[data-post-root]");
    if (!main) return;
    const slug = new URLSearchParams(window.location.search).get("slug");
    const post = data.posts.find((item) => item.slug === slug) || data.posts[0];
    if (!post) {
      main.innerHTML = '<section class="article-shell reveal in-view"><h1>没有可显示的文章</h1></section>';
      return;
    }
    document.title = `${post.title} | OwO Blog`;
    const description = document.querySelector('meta[name="description"]');
    if (description) description.setAttribute("content", post.description || post.excerpt || "");
    const tags = (post.categories || []).map((cat) => `<span>${escapeHtml(cat.name)}</span>`).join("");
    main.innerHTML = `<article class="article-shell reveal">
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
    main.innerHTML = `<article class="article-shell reveal"><a class="breadcrumb" href="index.html">← 返回首页</a><header class="article-header"><p class="eyebrow">${escapeHtml(about.eyebrow)}</p><h1>${escapeHtml(about.title)}</h1></header><div class="article-content">${about.body.map((item) => `<p>${escapeHtml(item)}</p>`).join("")}</div></article>`;
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
  };

  const initInteractions = () => {
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

    document.querySelectorAll(".filter-chip").forEach((button) => {
      button.addEventListener("click", () => {
        const filter = button.dataset.filter;
        document.querySelectorAll(".filter-chip").forEach((chip) => chip.classList.remove("active"));
        button.classList.add("active");
        document.querySelectorAll(".post-card, .archive-item").forEach((card) => {
          const tags = card.dataset.tags || "";
          card.classList.toggle("is-hidden", filter !== "all" && !tags.split(/\s+/).includes(filter));
        });
      });
    });

    const backToTop = document.querySelector(".back-to-top");
    if (backToTop) {
      window.addEventListener("scroll", () => backToTop.classList.toggle("visible", window.scrollY > 560));
      backToTop.addEventListener("click", () => window.scrollTo({ top: 0, behavior: "smooth" }));
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("in-view");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.14 }
    );
    document.querySelectorAll(".reveal").forEach((element, index) => {
      element.style.transitionDelay = `${Math.min(index * 45, 240)}ms`;
      observer.observe(element);
    });
  };

  const boot = async () => {
    if (document.body.dataset.page === "not-found" && redirectLegacyPost()) return;
    try {
      const data = await loadSiteData();
      if (document.body.dataset.page === "home") renderHome(data);
      if (document.body.dataset.page === "post") renderPost(data);
      if (document.body.dataset.page === "about") renderAbout(data);
      initInteractions();
    } catch (error) {
      const target = document.querySelector("main");
      if (target) target.innerHTML = `<p class="markdown-status">站点数据加载失败：${escapeHtml(error.message)}</p>`;
      initInteractions();
    }
  };

  boot();
})();
