# Changelog

## Unreleased

### 新增

- 本地管理面板与文章发布面板拆分为 `local-admin/manage` 和 `local-admin/publish`。
- 新增 `scripts/build-site.js`，集中生成首页、文章 wrapper 和站点地图。
- 新增 Markdown 文章源结构 `data/content/posts/*.md`。
- 新增 `public/data/site.json` 作为 GitHub Pages 公开站点的唯一内容数据源。

### 调整

- 公开静态资源移动到 `public/assets/css`、`public/assets/js`、`public/assets/img`。
- 历史文章改为 Markdown 源 + HTML wrapper 渲染，修复标题、列表和代码块显示问题。
- 公开静态资源移动到 `public/assets`，文章展示改为 `post.html?slug=...` 动态读取 JSON 渲染。
- 移除 `posts/*.html` 与 `archives/` 这类批量 HTML 产物，减少 GitHub Pages 发布文件数量。
- 本地 Markdown 写作源从 `content/posts/*.md` 移动到 `data/content/posts/*.md`。
- 公开 HTML 入口、`sitemap.xml`、`robots.txt`、`CNAME` 和 `.nojekyll` 改为输出到 `public/`，GitHub Pages 直接发布该目录。
