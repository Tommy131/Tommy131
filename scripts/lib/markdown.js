const HEADING_WITHOUT_SPACE = /^(#{1,6})([^#\s].*)$/;
const FRONT_MATTER_BOUNDARY = /^---\s*$/;

const LANGUAGE_ALIASES = {
  bat: "batch",
  cmd: "batch",
  dockerfile: "docker",
  js: "javascript",
  mjs: "javascript",
  cjs: "javascript",
  jsx: "jsx",
  ts: "typescript",
  tsx: "tsx",
  py: "python",
  rb: "ruby",
  rs: "rust",
  sh: "bash",
  shell: "bash",
  zsh: "bash",
  ps1: "powershell",
  pwsh: "powershell",
  yml: "yaml",
  conf: "ini",
  cfg: "ini",
  cnf: "ini",
  ini: "ini",
  env: "properties",
  props: "properties",
  nginxconf: "nginx",
  html: "markup",
  xml: "markup",
  svg: "markup",
};

function decodeEntities(value = "") {
  return String(value)
    .replace(/&quot;/g, '"')
    .replace(/&#34;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function escapeHtml(value = "") {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function normalizeLanguage(language = "") {
  const key = String(language).trim().toLowerCase();
  return LANGUAGE_ALIASES[key] || key || "text";
}

function parseFrontMatter(source = "") {
  const normalized = String(source).replace(/\r\n/g, "\n");
  const lines = normalized.split("\n");
  if (!FRONT_MATTER_BOUNDARY.test(lines[0] || "")) {
    return { meta: {}, body: normalized };
  }

  const end = lines.findIndex((line, index) => index > 0 && FRONT_MATTER_BOUNDARY.test(line));
  if (end < 0) return { meta: {}, body: normalized };

  const meta = {};
  for (const line of lines.slice(1, end)) {
    const match = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (!match) continue;
    meta[match[1]] = match[2].trim().replace(/^["']|["']$/g, "");
  }

  return { meta, body: lines.slice(end + 1).join("\n").replace(/^\n/, "") };
}

function stripText(value = "") {
  return decodeEntities(value)
    .replace(/^---[\s\S]*?---\s*/, "")
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/!\[[^\]]*]\([^)]*\)/g, " ")
    .replace(/\[([^\]]+)]\([^)]*\)/g, "$1")
    .replace(/[#>*_`~\-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function excerpt(value, size = 200) {
  const text = stripText(value);
  return text.length > size ? `${text.slice(0, size)}...` : text;
}

function detectCodeLanguage(line = "") {
  const trimmed = line.trim();
  if (!trimmed) return "";
  if (/^(@echo|chcp\b|title\b|set\b|cd\b|if\b|move\b|pause\b|exit\b|rd\/s\/q\b|cscript\b)/i.test(trimmed)) return "batch";
  if (/^(find\b|grep\b|xargs\b|sudo\b|curl\b|wget\b|npm\b|node\b|git\b|cd\s|\.\/)/i.test(trimmed)) return "bash";
  if (/^[A-Za-z]:\\.*>/.test(trimmed)) return "batch";
  if (/^(<\?php|\?>|\$[A-Za-z_]|var_dump\b|echo\b)/.test(trimmed)) return "php";
  if (/^(async\s+function|function\b|const\b|let\b|var\b|return\b|console\.|[A-Za-z_$][\w$]*\(.*\)|\/\*|\*\/|\/\/)/.test(trimmed)) return "javascript";
  if (/^(server\s*\{|location\b|listen\b|root\b|index\b|try_files\b|error_page\b)/.test(trimmed)) return "nginx";
  if (/^(HKEY_|Windows Registry Editor|reg\b)/i.test(trimmed)) return "reg";
  if (/^\/[a-z][\w-]*(?::|\s|\t)/i.test(trimmed)) return "text";
  return "";
}

function splitMixedCodeAndProse(line) {
  if (!detectCodeLanguage(line)) return [line];
  const match = line.match(/^(.+?[;}\)]|.+?\})(\s+)([\u3400-\u9fff].*)$/u);
  if (!match) return [line];
  return [match[1], match[3]];
}

function inferFenceLanguage(codeLines) {
  for (const line of codeLines) {
    const language = detectCodeLanguage(line);
    if (language) return language;
  }
  return "text";
}

function normalizeMarkdownBody(body = "") {
  const normalized = String(body).replace(/\r\n/g, "\n");
  const lines = normalized.split("\n");
  const out = [];
  let fence = null;

  const openFence = (language, line) => {
    out.push("", `\`\`\`${language}`, line, "\`\`\`", "");
  };

  for (let index = 0; index < lines.length; index += 1) {
    const raw = lines[index];
    const trimmed = raw.trim();

    if (fence) {
      if (/^```/.test(trimmed)) {
        if (fence.lines.some((line) => line.trim())) {
          const language = normalizeLanguage(fence.language || inferFenceLanguage(fence.lines));
          out.push(`\`\`\`${language}`, ...fence.lines, "\`\`\`");
        }
        fence = null;
      } else {
        fence.lines.push(raw.replace(/\s+$/g, ""));
      }
      continue;
    }

    const fenceMatch = trimmed.match(/^```\s*([\w#+.-]*)\s*$/);
    if (fenceMatch) {
      fence = { language: fenceMatch[1], lines: [] };
      continue;
    }

    if (HEADING_WITHOUT_SPACE.test(raw)) {
      out.push(raw.replace(HEADING_WITHOUT_SPACE, "$1 $2"));
      continue;
    }

    if (/^-{4,}\s*$/.test(trimmed)) {
      out.push("---");
      continue;
    }

    const parts = splitMixedCodeAndProse(raw);
    if (parts.length > 1) {
      openFence(detectCodeLanguage(parts[0]) || "text", parts[0].trim());
      out.push(parts[1]);
      continue;
    }

    const language = detectCodeLanguage(raw);
    const previous = lines[index - 1]?.trim() || "";
    const next = lines[index + 1]?.trim() || "";
    const isStandaloneCode = language && (!previous || detectCodeLanguage(previous) || !/[。！？.!?]$/.test(previous)) && trimmed.length < 220;
    if (isStandaloneCode && !/^[-*+]\s+/.test(trimmed) && !/^\d+[.)]\s+/.test(trimmed)) {
      openFence(language, trimmed);
      if (!next) index += 0;
      continue;
    }

    out.push(raw.replace(/\s+$/g, ""));
  }

  if (fence) {
    if (fence.lines.some((line) => line.trim())) {
      const language = normalizeLanguage(fence.language || inferFenceLanguage(fence.lines));
      out.push(`\`\`\`${language}`, ...fence.lines, "\`\`\`");
    }
  }

  return out.join("\n").replace(/\n{3,}/g, "\n\n").trim() + "\n";
}

function normalizeMarkdownDocument(source = "") {
  const { meta, body } = parseFrontMatter(source);
  const normalizedBody = normalizeMarkdownBody(body);
  if (!Object.keys(meta).length) return normalizedBody;

  const frontMatter = Object.entries(meta).map(([key, value]) => `${key}: ${value}`).join("\n");
  return `---\n${frontMatter}\n---\n\n${normalizedBody}`;
}

module.exports = {
  decodeEntities,
  escapeHtml,
  excerpt,
  normalizeLanguage,
  normalizeMarkdownBody,
  normalizeMarkdownDocument,
  parseFrontMatter,
  stripText,
};
