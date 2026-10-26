# OwO! Recorder 文章路线

这份文件记录 OwO! Recorder 相关博客文章的写作顺序和素材来源。文章按准备情况不定期发布：先完成内容和本地预览，再单独提交、推送和部署。没有固定发布日期，也不会自动发布未完成的草稿。

## 已发布

### 01. 从一个课堂翻译想法到 OwO! Recorder

- 文件：`data/content/posts/owo-recorder-from-idea-to-product.md`
- 主题：项目动机、最初设想、从小工具到学习资料系统的演进。
- 作用：系列总览，引导读者理解项目为什么存在。
- 状态：已发布。

### 02. OwO! Recorder 的本地优先架构

- 文件：`data/content/posts/owo-recorder-local-first-architecture.md`
- 主题：浏览器、BFF、Recorder API、SQLite、本地模型和私有计算节点的职责划分。
- 作用：架构总览，为后续实现文章建立共同背景。
- 状态：已发布。

## 后续写作顺序

### 03. 实时课堂链路：从浏览器音频到字幕事件

- 主题：麦克风和系统声音授权、AudioWorklet、PCM16 分片、WebSocket、服务端缓冲、ASR 窗口、翻译和字幕展示。
- 核心问题：一段音频如何从浏览器进入系统，又如何变成用户看到的一句字幕。
- 素材：`docs/API_REFERENCE.md`、`frontend/src/modules/recorder/`、后端实时会话和 WebSocket 实现。
- 文章类型：技术实现。
- 前置文章：02。
- 文件：`data/content/posts/owo-recorder-live-audio-to-captions.md`
- 状态：已完成本地初稿，待独立发布。

### 04. 实时转录为什么会丢词：一次完整的故障排查

- 主题：窗口提前提交、失败音频没有放回、翻译阻塞下一窗、去重误删和背压暂停。
- 核心问题：为什么“语速太快”不是唯一原因，以及如何从数据链路定位真正的丢失点。
- 素材：`docs/reports/2026-10-22-live-transcription-loss.md`、相关修复提交和实时转录测试。
- 文章类型：Bug 分析与修复。
- 前置文章：03。
- 状态：待写。

### 05. 长课堂分析：如何处理输入长度和中途恢复

- 主题：音频分段、分析叶节点、检查点、分层归并、进度计算、暂停、停止和恢复。
- 核心问题：一节超过模型上下文限制的课堂，如何生成完整且可恢复的学习资料。
- 素材：`docs/superpowers/specs/2026-08-11-output-budget-aware-binary-reduction-design.md`、`docs/superpowers/plans/`、最终分析服务和测试。
- 文章类型：技术实现与难点。
- 前置文章：02。
- 状态：待写。

### 06. 本地模型运行：ASR、翻译和分析如何分配硬件

- 主题：模型适配器、CUDA、CPU、MPS、显存预算、模型并发和显式设备选择。
- 核心问题：为什么系统不应该在 CUDA 失败时静默切换到 CPU，以及不同任务为什么需要不同的资源策略。
- 素材：`docs/reports/2026-10-07-node-gpu-compatibility.md`、配置文件、模型服务和设备探测测试。
- 文章类型：模型运行与工程取舍。
- 前置文章：02、05。
- 状态：待写。

### 07. 私有计算节点：从单机推理到多设备任务调度

- 主题：节点配对、设备身份、心跳、断线重连、任务队列、结果确认、客户端更新和回滚。
- 核心问题：如何让另一台属于用户自己的电脑运行课堂模型，同时保持数据所有权清晰。
- 素材：`docs/PRIVATE_CLUSTER.md`、`owo-recorder-compute-node/README.md`、`docs/adr/0008-private-compute-cluster.md`、`docs/adr/0021-server-nodes-schedule-only-gateway.md`。
- 文章类型：架构演进与分布式任务。
- 前置文章：02、06。
- 状态：待写。

### 08. 测试体系：如何验证一个实时音频系统没有悄悄丢数据

- 主题：领域测试、模型假适配器、WebSocket 生命周期、任务恢复、前端交互测试、契约检查和质量门禁。
- 核心问题：哪些行为必须自动化验证，哪些问题只能通过真实硬件和人工课堂验收发现。
- 素材：`backend/tests/`、`frontend/tests/`、`docs/QUALITY_GATES.md`、`docs/ACCEPTANCE.md`。
- 文章类型：测试与质量工程。
- 前置文章：03、04、05。
- 状态：待写。

### 09. 本地优先不只是口号：认证、所有权和隐私边界

- 主题：BFF、OIDC、会话 Cookie、资源所有权、分享链接、日志脱敏、删除语义和存储边界。
- 核心问题：当本地课堂工具需要远程访问时，如何避免把无认证内部 API 直接暴露出去。
- 素材：`docs/PRIVACY.md`、`docs/API_REFERENCE.md`、`docs/security/`、`docs/adr/0002-sso-bff-authentication.md`、`docs/adr/0018-owner-scoped-recordings.md`。
- 文章类型：安全与隐私设计。
- 前置文章：02、07。
- 状态：待写。

### 10. 从本机工具到可部署产品：启动器、发布和运维

- 主题：Windows/Linux 启动流程、依赖和模型初始化、生产前后端分离、反向代理、健康检查、备份和回滚。
- 核心问题：一个依赖本地模型和 GPU 的项目，如何让用户可靠地安装、更新和排障。
- 素材：`README.md`、`bootstrap/`、`scripts/`、`docs/deploy/README.md`、`docs/ACCEPTANCE_CLOSEOUT.md`。
- 文章类型：部署和运维。
- 前置文章：06、07、09。
- 状态：待写。

## 发布规则

1. 每次只推进一篇文章，先在 `data/content/posts/` 完成 Markdown 源稿。
2. 文章必须经过本地管理后台或站点预览，检查标题层级、代码块、长段落和移动端阅读。
3. 运行 `npm run build`，确认 `public/data/site.json`、sitemap 和文章链接正常。
4. 检查 `git diff`，只提交文章、必要的构建产物和相关文档。
5. 使用能说明文章内容的 Conventional Commit 提交，再根据需要推送到 `main`。
6. 发布后把本文状态从“待写”改为“已发布”，记录对应文件和提交。

## 选题调整

这份路线允许根据项目开发进展调整。新的重大故障、架构决策或用户实际反馈，可以插入到当前顺序之前；如果一篇文章需要依赖尚未稳定的实现，则保留在“待写”，不为了凑更新频率提前发布。
