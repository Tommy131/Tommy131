const state = { posts: [], categories: [], editingCategory: null };
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
  renderPosts();
  renderCategories();
}

function renderPosts() {
  const keyword = $("postSearch").value.trim().toLowerCase();
  const list = $("postList");
  list.innerHTML = "";
  state.posts
    .filter((post) => !keyword || `${post.title} ${post.slug}`.toLowerCase().includes(keyword))
    .forEach((post) => {
      const row = document.createElement("div");
      row.className = "post-item";
      row.innerHTML = `<strong>${post.title}</strong><small>${post.date || ""} · ${post.slug}</small><div class="header-actions"><a class="small-button" href="/publish/?slug=${encodeURIComponent(post.slug)}">编辑</a><a class="small-button" href="/site/${post.url}" target="_blank">预览</a><button class="small-button" data-delete="${post.slug}" type="button">删除</button></div>`;
      row.querySelector("[data-delete]").addEventListener("click", () => deletePost(post.slug));
      list.appendChild(row);
    });
}

function renderCategories() {
  const list = $("categoryList");
  list.innerHTML = "";
  state.categories.forEach((category) => {
    const row = document.createElement("div");
    row.className = "category-item";
    row.innerHTML = `<strong>${category.name}</strong><small>${category.slug} · ${category.count || 0} 篇</small><div class="header-actions"><button class="small-button" data-edit="${category.slug}" type="button">编辑</button><button class="small-button" data-delete="${category.slug}" type="button">删除</button></div>`;
    row.querySelector("[data-edit]").addEventListener("click", () => openCategoryDialog(category));
    row.querySelector("[data-delete]").addEventListener("click", () => deleteCategory(category.slug));
    list.appendChild(row);
  });
}

async function deletePost(slug) {
  if (!confirm("确定删除这篇文章及其 Markdown 源文件吗？")) return;
  await api(`/api/post?slug=${encodeURIComponent(slug)}`, { method: "DELETE" });
  await loadState();
  toast("文章已删除");
}

function openCategoryDialog(category = null) {
  state.editingCategory = category?.slug || null;
  $("categoryDialogTitle").textContent = category ? "编辑分类标签" : "新增分类标签";
  $("categoryName").value = category?.name || "";
  $("categorySlug").value = category?.slug || "";
  $("categoryDescription").value = category?.description || "";
  $("categoryDialog").showModal();
}

async function saveCategory(event) {
  event.preventDefault();
  const payload = {
    originalSlug: state.editingCategory,
    name: $("categoryName").value.trim(),
    slug: $("categorySlug").value.trim() || slugify($("categoryName").value),
    description: $("categoryDescription").value.trim(),
  };
  if (!payload.name) return toast("分类名称不能为空");
  await api("/api/category", { method: "POST", body: JSON.stringify(payload) });
  $("categoryDialog").close();
  await loadState();
  toast("分类标签已保存");
}

async function deleteCategory(slug) {
  if (!confirm("确定删除这个分类标签？文章不会被删除，但会移除关联。")) return;
  await api(`/api/category?slug=${encodeURIComponent(slug)}`, { method: "DELETE" });
  await loadState();
  toast("分类标签已删除");
}

$("refreshBtn").addEventListener("click", loadState);
$("newCategoryBtn").addEventListener("click", () => openCategoryDialog());
$("saveCategoryBtn").addEventListener("click", saveCategory);
$("postSearch").addEventListener("input", renderPosts);

loadState().catch((error) => toast(error.message));
