const state = { posts: [], categories: [], selectedSlug: null };
const $ = (id) => document.getElementById(id);

function toast(message) {
  const node = $("toast");
  node.textContent = message;
  node.hidden = false;
  setTimeout(() => {
    node.hidden = true;
  }, 2400);
}

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function slugify(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9\u4e00-\u9fa5_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}

async function loadState() {
  const data = await api("/api/state");
  state.posts = data.posts || [];
  state.categories = data.categories || [];
  renderCategoryChecks([]);
}

function renderCategoryChecks(selected = []) {
  const box = $("postCategories");
  box.innerHTML = "";
  state.categories.forEach((category) => {
    const label = document.createElement("label");
    label.innerHTML = `<input type="checkbox" value="${category.slug}"> ${category.name}`;
    label.querySelector("input").checked = selected.includes(category.slug);
    box.appendChild(label);
  });
}

function selectedCategorySlugs() {
  return Array.from($("postCategories").querySelectorAll("input:checked")).map((input) => input.value);
}

async function selectPost(slug) {
  const data = await api(`/api/post?slug=${encodeURIComponent(slug)}`);
  const { post, body } = data;
  state.selectedSlug = slug;
  $("editorMode").textContent = "Edit Markdown";
  $("editorTitle").textContent = post.title;
  $("postTitle").value = post.title || "";
  $("postSlug").value = post.slug || "";
  $("postDate").value = post.date || new Date().toISOString().slice(0, 10);
  $("postDescription").value = post.description || post.excerpt || "";
  $("postBody").value = body || "";
  $("previewLink").href = `/site/${post.url}`;
  $("deletePostBtn").hidden = false;
  renderCategoryChecks((post.categories || []).map((category) => category.slug));
}

function newPost() {
  state.selectedSlug = null;
  $("editorMode").textContent = "New Markdown";
  $("editorTitle").textContent = "文章发布面板";
  $("postTitle").value = "";
  $("postSlug").value = "";
  $("postDate").value = new Date().toISOString().slice(0, 10);
  $("postDescription").value = "";
  $("postBody").value = "# 新文章\n\n从这里开始写 Markdown。";
  $("previewLink").href = "/site/index.html";
  $("deletePostBtn").hidden = true;
  renderCategoryChecks([]);
}

async function savePost() {
  try {
    const title = $("postTitle").value.trim();
    if (!title) return toast("标题不能为空");
    const payload = {
      originalSlug: state.selectedSlug,
      title,
      slug: $("postSlug").value.trim() || slugify(title),
      date: $("postDate").value,
      description: $("postDescription").value.trim(),
      categorySlugs: selectedCategorySlugs(),
      body: $("postBody").value,
    };
    const result = await api("/api/post", { method: "POST", body: JSON.stringify(payload) });
    await loadState();
    await selectPost(result.post.slug);
    toast("文章已保存，站点数据已同步");
  } catch (error) {
    toast(`保存失败：${error.message}`);
    throw error;
  }
}

async function deletePost() {
  if (!state.selectedSlug) return toast("当前是新文章，尚未保存");
  if (!confirm("确定删除这篇文章及其 Markdown 源文件吗？")) return;
  await api(`/api/post?slug=${encodeURIComponent(state.selectedSlug)}`, { method: "DELETE" });
  toast("文章已删除");
  window.location.href = "/manage/";
}

$("savePostBtn").addEventListener("click", savePost);
$("deletePostBtn").addEventListener("click", deletePost);
$("postTitle").addEventListener("input", () => {
  if (!state.selectedSlug) $("postSlug").value = slugify($("postTitle").value);
});

loadState()
  .then(() => {
    const slug = new URLSearchParams(window.location.search).get("slug");
    if (slug) return selectPost(slug);
    newPost();
  })
  .catch((error) => toast(error.message));
