# 踩雷知识库（Lessons Learned）

> **用途**：记录项目开发中遇到的真实错误，防止同类问题重复发生。
> **维护规则**（CLAUDE.md 规则 6）：每次 Bug 修复后、Reviewer 标记 Needs Revision 后、用户第二次提醒同一问题后，必须新增记录。
> **加载时机**：每次对话初始化时自动加载（规则 1）。

---

## 记录格式

```markdown
## LL-{序号} [{YYYY-MM-DD}] {问题简题}
- **症状**：（用户/CI/测试看到了什么现象）
- **根因**：（错误的根本原因，必须到代码/设计层面）
- **正确做法**：（应该怎么写/怎么做）
- **检测命令**（可选）：（grep/go 命令可自动检测此问题；应返回空表示合规）
- **触发的规则更新**：（更新了哪些文件，如 anti-patterns.md、skill.md、CLAUDE.md）
```

---

## 使用说明

### 何时新增记录

根据 CLAUDE.md 规则 6，以下任意情况发生时，Agent **必须**在当次会话结束前新增 LL 记录：

1. 修复了一个由"错误模式"导致的 bug
2. Reviewer Agent 标记了 `Needs Revision` 并指出具体模式问题
3. 用户第二次提醒 Agent 同一类问题

### 与其他文件的关联

```
症状发现 → 记录到 lessons-learned.md（LL-XXX）
           ↓（若可机器检测）
           → 提炼到 anti-patterns.md（AP-XXX）
           ↓（供 Reviewer Agent 维度 5 自动核对）
           → 每次代码审查时自动检测
```

### 新增流程

1. 在本文件末尾新增 `## LL-{下一个序号}` 记录
2. 评估是否需要在 `.ai/anti-patterns.md` 新增对应 AP 记录
3. 评估是否需要更新相关 skill.md 的约束说明
4. 在 `.ai/changelog/ai-modifications.md` 记录此次经验沉淀

---

<!-- 实际 LL 记录从此处开始，按序号递增 -->
