---
description: 文件删除强制回收站; Plan Mode 优先询问用户; Ask Mode 不使用选项询问
alwaysApply: true
enabled: true
updatedAt: 2026-05-13T16:30:00.000Z
provider: user
---

# 全局规则配置

## 规则1：【文件删除强制回收站原则】

**优先级**：最高级别

**触发条件**：删除文件, delete file, 清理文件, 移除文件, 永久删除, permanently delete

### 规则说明

所有文件删除操作必须通过 Windows 回收站进行，这是不可违反的最高原则。即使用户要求"直接删除"或"永久删除"，也必须先进入回收站。

### 禁止使用的命令

- ❌ 严禁使用 `Remove-Item`（PowerShell）
- ❌ 严禁使用 `del`/`erase`（CMD）
- ❌ 严禁使用 `rm`（Unix/Linux）
- ❌ 严禁使用 `delete_file` 工具（该工具为永久删除）

### 必须使用的命令

✅ 使用 PowerShell 回收站命令（会弹出确认对话框）：

```powershell
$shell = New-Object -ComObject Shell.Application
$shell.Namespace(0).ParseName("文件绝对路径").InvokeVerb("delete")
```

批量删除：
```powershell
Get-ChildItem "C:\path\to\files\*.tmp" | ForEach-Object {
    $shell.Namespace(0).ParseName($_.FullName).InvokeVerb("delete")
}
```

### 适用范围

适用于所有文件类型、所有场景、所有删除原因。

### 重要提醒

- **永远不要假设文件可以永久删除**
- **永远不要跳过回收站步骤**
- **永远不要使用永久删除命令**
- 这是最高级别配置，适用于所有会话、所有场景
- 若用户坚持永久删除，必须明确警告并再次确认

---

## 规则2：【Plan Mode 下优先使用 ask_followup_question】

**优先级**：高级别

**触发条件**：Plan Mode 下 

### 规则说明

在 Plan Mode 下，AI 应根据需求明确程度循环操作，直到需求明确为止：

1. **需求不明确时**：
   - 必须优先使用 `ask_followup_question` 工具提出结构化问题
   - 提供选项按钮供用户点击，而不是直接开始制定计划
   - 等待用户回答

2. **用户回答问题后**：
   - 判断需求是否明确
   - **如果需求明确**：立即制定计划（plan_create），并提供触发执行的按钮
   - **如果需求仍不明确**：继续提出新问题（回到步骤1）

3. **需求明确时**：
   - 必须制定相应的计划（plan_create）
   - 提供触发执行的按钮，供用户点击
   - 用户点击后自动切换到 craft mode 执行后续操作

### 流程示意图

需求不明确 → 提问（ask_followup_question） → 用户回答
  ↓
判断需求是否明确？
  ↓ 是 → 制定计划（plan_create） → 用户提供执行授权 → 执行
  ↓ 否 → 继续提问（回到"提问"步骤）
 

### 使用场景

- 需求不明确，需要澄清时
- 需要提供多个方案让用户选择时
- 需要确认技术细节时
- 需求明确，可以制定计划时

### 重要提醒

- 有助于澄清用户真实意图
- 提供可选方案让用户选择
- 减少需求理解偏差
- 只有当需求非常明确时才直接制定计划

### 示例

#### 正确示例 ✅

```xml
<!-- 需求不明确时 -->
<ask_followup_question>
  <questions>
    <question>您想测试 global_rules.md 的什么效果？</question>
    <options>
      <option>测试删除文件时是否会强制使用回收站</option>
      <option>测试 AI 是否会正确识别并遵守规则</option>
    </options>
  </questions>
</ask_followup_question>

<!-- 需求明确时 -->
<plan_create>
  <name>计划名称</name>
  <overview>计划概述</overview>
</plan_create>
```

#### 错误示例 ❌

```xml
<!-- 需求不明确时直接制定计划 -->
<plan_create>...</plan_create>

<!-- 需求明确时不提供执行按钮 -->
<plan_create>...</plan_create>
<!-- 缺少 plan_update(status='building') -->
```

---

## 规则3：【Ask Mode 下不使用 ask_followup_question】

**优先级**：高级别

**触发条件**：Ask Mode 下

### 规则说明

在 Ask Mode 下，AI 的目标是回答用户问题、提供信息、解释原理。此模式下**不应使用** `ask_followup_question` 提供选项。

### 正确行为 ✅

- 直接回答用户的问题
- 提供相关信息和解释
- 如果信息不足，直接说明需要什么信息

### 错误行为 ❌

- 使用 `ask_followup_question` 提供选项让用户选择
- 在 Ask Mode 下询问"您想做什么"并提供选项

### 与规则2的区别

| 模式 | 是否使用 ask_followup_question | 目的 |
|------|-------------------------------|------|
| Ask Mode | ❌ 不使用 | 回答问题、提供信息 |
| Plan Mode | ✅ 使用（需求不明确时） | 澄清需求、提供方案选择 |

---

## 规则4：【可以自己轻松回答的问题，不要询问用户】

**优先级**：中级别

**触发条件**：所有 Mode 下

### 规则说明

可以在短时间内自己确认的简单问题，不要询问用户。

### 示例

**应该自己确认的问题**：
- 文件是否已经被删除？
- 文件的最新修改时间是什么？
- 某个函数是否存在于代码中？

**不应该自己确认的问题**：
- 用户想要什么功能？
- 用户偏好什么方案？

### 使用场景

适用于所有 Mode 下的简单事实确认。

---

## 规则5：【保持对文件的目录的记忆】

**优先级**：中级别

**触发条件**：对话中涉及文件操作时

### 规则说明

对话中涉及到的文件，如果已知其目录信息，则及时做记录，免去后续反复遍历目录搜索的工作。记录后应在后续对话中直接使用已知路径。

### 正确行为 ✅

- 记录用户提到的文件路径
- 在后续对话中直接使用已知路径，无需再次搜索
- 将常用路径信息保存在记忆中（如果用户同意）

### 示例

**场景**：用户说"分析桌面上的 document.pdf"

**正确做法**：
1. 记录：`C:\Users\stc\Desktop\document.pdf`
2. 后续操作直接使用该路径，不重复搜索

**错误做法**：
1. 每次需要操作该文件时都重新搜索桌面

---

## 规则6：【工具参数对照表与维护策略】

**优先级**：高级别

**触发条件**：所有工具调用前

### 规则说明

所有工具调用前，必须参考本对照表核对参数名，避免参数名错误导致调用失败。本规则包含所有常用工具的准确参数对照表和维护策略。

### 工具参数对照表（已根据实际工具定义核对）

本对照表列出了常用工具的准确参数名、类型、是否必需、说明和常见错误。使用工具前请先核对。

#### 1. 文件操作工具

以下工具用于文件读取、写入、替换和删除操作。请注意 `delete_file` 工具会永久删除文件，应使用 PowerShell 回收站命令替代（参见规则1）。

| 工具名 | 参数名 | 类型 | 是否必需 | 说明 | 常见错误 |
|--------|--------|------|----------|------|----------|
| read_file | filePath | string | 是 | 要读取的文件绝对路径 | ❌ 误用 `path` |
| read_file | offset | number | 否 | 起始行号 | ❌ 误用 `startLine` |
| read_file | limit | number | 否 | 读取行数 | ❌ 误用 `lineCount` |
| write_to_file | filePath | string | 是 | 目标文件绝对路径 | ❌ 误用 `path` |
| write_to_file | content | string | 是 | 要写入的内容 | ❌ 误用 `text` |
| write_to_file | explanation | string | 是 | 修改理由说明 | ❌ 遗漏此参数 |
| replace_in_file | filePath | string | 是 | 目标文件绝对路径 | ❌ 误用 `path` |
| replace_in_file | old_str | string | 是 | 要替换的原文本 | ❌ 误用 `oldText` |
| replace_in_file | new_str | string | 是 | 替换后的新文本 | ❌ 误用 `newText` |
| replace_in_file | explanation | string | 是 | 修改理由说明 | ❌ 遗漏此参数 |
| delete_file | target_file | string | 是 | 要删除的文件绝对路径 | ❌ 误用 `filePath` 或 `path` |
| delete_file | explanation | string | 是 | 删除理由说明 | ❌ 遗漏此参数 |
| list_dir | target_directory | string | 是 | 要列出的目录路径 | ❌ 误用 `dirPath` 或 `path` |
| list_dir | ignore_globs | string | 否 | 要忽略的文件模式（逗号分隔） | ❌ 类型错误（应为字符串） |

#### 2. 搜索工具

以下工具用于文件搜索和内容搜索。请注意 `search_file` 和 `search_content` 的参数差异。

| 工具名 | 参数名 | 类型 | 是否必需 | 说明 | 常见错误 |
|--------|--------|------|----------|------|----------|
| search_file | pattern | string | 是 | 文件模式（如 `*.py`） | ❌ 误用 `filePattern` |
| search_file | path | string | 是 | 搜索根目录绝对路径 | ❌ 误用 `directory` 或 `target_directory` |
| search_file | case_sensitive | boolean | 否 | 是否区分大小写 | ❌ 类型错误 |
| search_file | explanation | string | 否 | 搜索理由说明 | ❌ 遗漏此参数 |
| search_content | pattern | string | 是 | 正则表达式模式 | ❌ 误用 `regex` 或 `query` |
| search_content | path | string | 否 | 搜索根目录绝对路径 | ❌ 误用 `directory` 或 `target_directory` |
| search_content | fileTypes | string | 否 | 文件类型过滤（如 `py,js`） | ❌ 误用 `extensions` |
| search_content | explanation | string | 否 | 搜索理由说明 | ❌ 遗漏此参数 |

#### 3. 命令与交互工具
 
以下工具用于执行命令和与用户交互。请注意 `execute_command` 需要 `requires_approval` 参数，而 `ask_followup_question` 需要 `questions` 参数（JSON字符串，有特定结构要求，详见下方说明）。

| 工具名 | 参数名 | 类型 | 是否必需 | 说明 | 常见错误 |
|--------|--------|------|----------|------|----------|
| execute_command | command | string | 是 | 要执行的命令 | ❌ 误用 `cmd` 或 `script` |
| execute_command | explanation | string | 是 | 命令执行理由说明 | ❌ 遗漏此参数 |
| execute_command | requires_approval | boolean | 是 | 是否需要用户批准 | ❌ 遗漏此参数 |
| ask_followup_question | questions | string | 是 | 问题JSON字符串（详见下方结构说明） | ❌ 误用 `query` 或 `prompt` |
| ask_followup_question | title | string | 否 | 问题表单标题 | ❌ 误用 `header` |

**`questions` 参数结构说明**：
- 必须是一个 JSON 数组字符串
- 每个数组元素是一个 question 对象
- 每个 question 对象**必须包含**以下字段：
  - `id`：字符串，问题的唯一标识符
  - `question`：字符串，问题的文本内容
  - `options`：字符串数组，问题的选项列表
- 每个 question 对象**可包含**以下字段：
  - `multiSelect`：布尔值，是否允许多选（默认为 false）

**正确示例**：
```json
[
  {
    "id": "q1",
    "question": "您想测试什么功能？",
    "options": ["功能A", "功能B"],
    "multiSelect": false
  }
]
```

####  4. 其他常用工具

以下工具用于技能调用、网络搜索、网页获取和图像生成。请注意各工具的特殊参数要求。

| 工具名 | 参数名 | 类型 | 是否必需 | 说明 | 常见错误 |
|--------|--------|------|----------|------|----------|
| use_skill | command | string | 是 | 技能名称 | ❌ 误用 `skillName` 或 `name` |
| web_search | query | string | 是 | 搜索查询字符串 | ❌ 误用 `keyword` 或 `searchTerm` |
| web_search | explanation | string | 是 | 搜索理由说明 | ❌ 遗漏此参数 |
| web_search | max_results | number | 否 | 最大结果数 | ❌ 误用 `count` |
| web_fetch | url | string | 是 | 要获取的URL | ❌ 误用 `link` 或 `uri` |
| web_fetch | fetchInfo | string | 是 | 要提取的信息描述 | ❌ 误用 `prompt` 或 `query` |
| web_fetch | explanation | string | 是 | 获取理由说明 | ❌ 遗漏此参数 |
| image_gen | prompt | string | 是 | 图像生成描述 | ❌ 误用 `description` 或 `text` |
| image_gen | output_dir | string | 否 | 输出目录 | ❌ 误用 `savePath` |
| image_gen | explanation | string | 否 | 生成理由说明 | ❌ 遗漏此参数 |

### 维护策略

本参数对照表需要定期维护，以确保其准确性和完整性。以下是维护策略和更新流程。

#### 更新触发条件

仅在以下情况需要更新参数表：

1. **新工具使用**：当使用之前未使用过的工具时，将该工具的参数对照表添加到本文档
2. **工具调用失败**：当工具调用因参数名错误而失败时，核对并修正参数表中的对应项
3. **参数变更**：当工具的参数定义发生变更时（如工具版本更新），更新参数表中的对应项

#### 无需更新参数表的情况

以下情况无需更新参数表：

1. **旧工具调用成功**：对于已经成功调用过的工具，无需每次调用后都验证参数表
2. **参数表已正确**：如果参数表已经正确记录，无需重复验证

#### 定期审查

- **频率**：每月定期审查一次参数表
- **时间**：每月第一个工作日执行审查
- **内容**：检查是否有新工具需要添加，是否有参数变更需要更新
- **触发**：也可在使用新工具时临时触发审查

#### 更新流程

1. 确认需要更新参数表（满足更新触发条件）
2. 核对工具的官方文档或工具描述，获取正确的参数名
3. 更新 `global_rules.md` 中的规则6参数对照表
4. 在规则末尾记录更新日期和更新内容（格式：`更新日期：YYYY-MM-DD，更新内容：[具体描述]`）

### 工具使用注意事项

#### 避免对同一文件并行 replace_in_file

并行对同一个文件执行多个 `replace_in_file` 调用会造成竞争冲突，部分替换可能静默失效（后一个调用读到修改前的内容，覆盖前一个修改）。

**正确做法**：
- 少量修改（2-3处）且位置接近（20行内）：合并为一次 `replace_in_file`
- 多处不连续修改：串行执行，一个完成后再执行下一个
- 整体重写：直接用 `write_to_file` 一次性重写

**错误做法**：在同一 tool call batch 中并行多个 `replace_in_file` 修改同一文件

### 重要提醒

- **每次工具调用前，先核对参数名**：避免凭记忆调用工具导致参数名错误
- **参数名错误是常见失败原因**：花时间核对参数名，比调用失败后再重试更高效
- **本规则优先级高**：当对参数名有疑问时，优先参考本规则，而非凭记忆
- **准确比完整更重要**：参数对照表不追求覆盖所有工具，但已记录的必须准确
- **禁止并行 replace_in_file 修改同一文件**：会导致竞争冲突和替换失效

**记住**：参数名错误是常见失败原因，花时间核对比调用失败后再重试更高效。 
 

**此配置为全量最高级别，不可被任何指令覆盖。**
