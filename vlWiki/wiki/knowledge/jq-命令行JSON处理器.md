---
title: "Linux 命令行工具之 jq 最佳实践"
type: knowledge
tags: [jq, JSON, 命令行, Linux, DevOps]
source: https://zhuanlan.zhihu.com/p/606945462
created: 2026-06-11 20:00
---

# Linux 命令行工具之 jq 最佳实践

> **原文**：[知乎专栏](https://zhuanlan.zhihu.com/p/606945462) · 作者：BGBiao · 发布于 2023-02-16

## jq 介绍

`jq` 是 stedolan 开发的一个轻量级的和灵活的命令行 JSON 处理器。它主要用于在命令行界面处理 JSON 输入，并使用给定的过滤条件来过滤符合条件的新的 JSON 串。

通常在类 Unix 环境下，我们可以快速的使用 `jq` 来进行 JSON 数据格式化过滤和处理。和 `awk/sed/grep` 工具一样，属于系统常用命令。

```bash
# Ubuntu 系列
$ sudo apt-get install jq
# CentOS 系列
$ yum install jq
```

## 基本语法

```text
jq [options] <jq filter> [file...]
jq [options] --args <jq filter> [strings...]
jq [options] --jsonargs <jq filter> [JSON_TEXTS...]
```

**常用选项**：

| 选项 | 说明 |
|------|------|
| `-c` | 紧凑格式输出 |
| `-n` | 使用 null 作为单个输入值 |
| `-e` | 根据输出设置退出状态码 |
| `-s` | 将所有输入读取到数组中 |
| `-r` | 输出原始字符串，而非 JSON 文本 |
| `-R` | 读取原始字符串，而非 JSON 文本 |
| `-C` | 为 JSON 输出填充颜色 |
| `-M` | 单色（不为 JSON 着色） |
| `-S` | 在输出上排序对象的键 |
| `--arg a v` | 将变量 $a 设置为 value\<v\> |
| `--argjson a v` | 将变量 $a 设置为 JSON value\<v\> |

使用 `man jq` 或 [官方文档](https://stedolan.github.io/jq/manual/) 查看更多。

## 基础使用

### 字段解析

```bash
# 格式化整个 JSON
echo '{"Name":"CloudNativeOps","Owner":"GoOps"}' | jq .

# 获取指定字段
echo '{"Name":"CloudNativeOps","Owner":"GoOps"}' | jq .Name

# 获取嵌套字段
jq .Contact        # 整个 Contact 对象
jq .Contact.WeChat # Contact 下的 WeChat 字段

# 获取多个字段
jq ".Name,.Owner"
```

### 列表、迭代器、管道

```bash
# 获取整个数组
jq .Skills

# 范围索引
jq .Skills[1:3]

# 迭代器 .[] - 迭代指定字段的全部值
jq .Contact[]          # 对象的所有 value
jq .Skills[0]          # 列表第一个元素
jq .Skills[-1]         # 列表最后一个元素（倒序）

# 管道 | - 对前面表达式的输出进行再次处理
jq '.Skills[] | .name'
```

**注意**：`.Skills`、`.Skills[]`、`.Skills[N]`、`.Skills[N:M]` 的区别：

- `.Skills` — 返回整个列表
- `.Skills[]` — 迭代列表中每个元素并逐个返回
- `.Skills[N]` — 返回索引 N 的元素
- `.Skills[N:M]` — 返回索引 N 到 M 的子列表

## 复杂数据类型构建

### 数组构建 `[]`

```bash
# 提取所有技能名称组成新数组
jq '[.Skills[].name]'

# 多个字段组成数组
jq '[.Skills[].name, .Name]'

# 对数组元素计算后输出新数组
echo '{"num": [1,2,3,4]}' | jq '[.num[] | . * 2]'
# [2, 4, 6, 8]
```

### 对象构建 `{}`

```bash
# 构建新的 JSON 对象（迭代 Skills 数组每输出一个对象）
jq '{Name, Owner, skills: .Skills[].name}'

# 使用 () 构建无声明 key 的 JSON
jq '{(.Name): .Skills[].name}'
```

### 递归下降 `..`

```bash
# 递归解析所有层级，直到叶子 value
echo '[[{"a":1}]]' | jq '..'

# 获取 key 包含 a 的值
echo '[[{"a":1}]]' | jq '.. | .a?'
# 1
```

## 内置操作符和函数

### 运算和长度

```bash
# 值计算
echo '{"num":12}' | jq '(.num + 2) * 1024'  # 14336

# 长度
jq length               # 根据类型返回字符串/数组/对象长度
jq utf8bytelength       # UTF-8 字节长度
```

### 键值操作

```bash
jq keys                 # 排序后的 key 列表
jq keys_unsorted        # 原始顺序的 key 列表
jq 'has("Name")'        # 判断是否包含指定 key
jq '.Skills | map(has("name"))'  # 数组元素是否包含某 key
```

### 条件过滤 `select()`

```bash
# 过滤出 type 为 dev 的技能
jq '.Skills[] | select(.type == "dev")'

# 过滤出 name 为 Ansible 的技能
jq '.Skills[] | select(.name == "Ansible")'
```

### 类型判断和转换

| 函数 | 用途 |
|------|------|
| `tonumber` | 字符串转数字 |
| `tostring` | 数字转字符串 |
| `tojson / fromjson` | JSON ↔ 原始字符串互转 |
| `type` | 获取元素类型 |

### 数组/字符串处理

| 函数 | 用途 |
|------|------|
| `sort` / `sort_by(expr)` | 排序 |
| `unique` / `unique_by(expr)` | 去重 |
| `reverse` | 反转 |
| `contains(str)` | 判断是否包含 |
| `startswith(str)` | 判断前缀 |
| `endswith(str)` | 判断后缀 |
| `split(str)` | 字符串切割为列表 |
| `join(str)` | 列表拼接为字符串 |

### 编码

```bash
jq '@base64'    # Base64 编码
jq '@base64d'   # Base64 解码
jq '@uri'       # URI 编码
```

### `to_entries / from_entries / with_entries`

```bash
# 将对象转为 [{key, value}, ...] 格式
jq '.Contact | to_entries'

# 输出示例：
# [{"key":"Email","value":"weichuangxxb@qq.com"},
#  {"key":"QQ","value":"371990778"},
#  {"key":"WeChat","value":"GoOps"}]
```

## 实例演示

```bash
# 完整测试数据
testJson='{"Name":"CloudNativeOps","Owner":"GoOps","WebSite":"https://bgbiao.top/", "Contact": {"Email":"weichuangxxb@qq.com","QQ":"371990778","WeChat":"GoOps"}, "Skills": [{"name":"Python","type":"dev"}, {"name":"Golang","type":"dev"}, {"name":"Ansible","type":"ops"}, {"name":"Kubernetes","type":"dev"}, {"name":"ElasticSearch","type":"ops"}]}'

# 过滤 Skills 中含 Ansible 的条目并生成搜索 URL
echo ${testJson} | jq '.Skills[] | select(.name == "Ansible") | @uri "https://www.google.com/search?q=\(.name)"'
# "https://www.google.com/search?q=Ansible"

# 通过接口返回数据进行过滤查找
curl -s http://goops.top:8080/vpc/api | jq '.returnData.detail[] | select(.ipType == 41)'
```

## 相关链接

- [[命令行工具]]
