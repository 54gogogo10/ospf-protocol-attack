# OSPF 攻击模拟器 GUI 配置面板 — 设计文档

**日期:** 2026-05-12
**状态:** 已实现

## 1. 概述

为 OSPF 协议攻击模拟器增加 Tkinter 桌面 GUI 操作面板，提供独立入口，支持可视化配置参数、启动/停止攻击、实时日志输出和进度监控。

### 目标

- 零额外依赖，仅用 Python 内置 tkinter + threading + queue
- 独立入口（双击 exe 打开 GUI），CLI 保持可用
- 覆盖全部 12 种攻击类型的可视化配置
- 实时日志、进度条、停止控制

---

## 2. 文件结构

```
ospf_attack/gui/
├── __init__.py          # 导出 launch_gui()
├── app.py               # 主窗口 (Tk 根窗口, 左右分栏, 按钮编排)
├── attack_tree.py       # 左侧攻击列表 (Treeview, 4 类 12 攻击)
├── config_form.py       # 动态配置表单 + FIELD_META (41 字段)
│                        #   + RoutesEditor (多路由表格编辑)
│                        #   + PacketPreview (报文预览面板)
│                        #   + build_packet / export_pcap (报文构造/导出)
├── log_panel.py         # 日志输出面板 (ScrolledText + Queue 轮询)
├── pcap_tools.py        # 报文嗅探 / pcap 导入 / PacketBrowser
│                        #   + OSPF 报文解析 (Hello/LSU/DBD/LSR)
├── runner.py            # 攻击执行器 (后台线程, Event 停止)
└── styles.py            # 颜色/字体/间距常量

ospf_attack/
└── __main__.py          # 入口: python -m ospf_attack 启动 GUI
```

---

## 3. 窗口布局

主窗口 1100×720，最小 900×600。

```
┌──────────┬────────────────────────────────┬────────────┐
│ 攻击模块  │  [通用参数]                     │  报文预览    │
│          │  网卡: [____▼] 目标: [224.0.0.5]│  (24 行)    │
│ ▸ 邻接关系│  模式: ◎旁路 ○主动               │  [导出pcap]  │
│   ·Hello │  ───────────────────────────── │  [刷新预览]  │
│     注入  │  [攻击专属参数]                  │            │
│   ·邻接  │  lsa_type: [▼ 5]  age: [0]    │  ┌─IP Hdr─┐ │
│   ·DR/BDR│  metric: [20]                 │  │ Src:... │ │
│ ▸ LSA攻击│  [编辑路由...] 2 条路由           │  ├─OSPF───┤ │
│   ·路由  │  ───────────────────────────── │  │ ...     │ │
│   ·Max-  │  [▶启动] [■停止] [保存] [加载]    │  └────────┘ │
│   ·Max-  │  | [嗅探报文] [导入pcap]         │            │
│     Age  │  ● 状态: 就绪                   │            │
│ ▸ 拒绝服务│  ████████████░░░░               │            │
│ ▸ 协议操控│  [日志面板]                      │            │
├──────────┴────────────────────────────────┴────────────┤
│ 状态栏: Npcap ✓                                         │
└──────────────────────────────────────────────────────────┘
```

### 布局说明

- **左侧树形列表**: 4 个分类节点 × 各 2~4 个子攻击，选中后右侧表单立即切换
- **通用参数区**: 始终可见，所有攻击共享，所有字段都有默认值
- **专属参数区**: 根据选中的攻击类型动态显示，攻击专属默认值（如 max-seq 默认 seq=0x7FFFFFFF）
- **报文预览**: 右侧独立面板，显示构造的 OSPF 报文结构，支持导出 pcap
- **停止按钮**: 仅在攻击运行时可用，通过 threading.Event 通知停止
- **日志区**: 自动滚动，颜色区分 INFO(白)/WARN(黄)/ERROR(红)/SYSTEM(蓝)
- **进度条**: indeterminate 模式

---

## 4. 动态表单映射

| 攻击 | 专属参数字段 |
|------|------------|
| hello-inject / adjacency-break / dr-bdr-hijack | hello_interval, router_dead_interval, router_priority, auth_type(下拉), auth_key, subnet_mask |
| route-inject / max-seq / max-age / fight-back | lsa_type(下拉:1/3/5), link_state_id, advertising_router, sequence, age, metric, network_mask, forwarding_address |
| flood / spf-recalc / db-overflow | duration, thread_count, lsa_change_interval(spf-rec), lsa_count(db-over) |
| mitm | target_a, target_b, action(下拉:drop/modify/forward/inject), modify_rules(表格编辑) |
| replay | capture_file(文件选择), replay_loop(复选框), replay_interval, modify_fields |

### 字段类型映射

- `str` → Entry 输入框
- `int` → Spinbox 数字选择器
- `Enum` → Combobox 下拉
- `bool` → Checkbutton 复选框
- `list/dict` → "编辑"按钮 → 弹出子窗口

---

## 5. 线程模型

```
┌──────────┐    ┌─────────────┐    ┌──────────────┐
│   UI 线程  │───▶│  runner 线程 │───▶│  attack.run() │
│ (tkinter)  │    │ (daemon)    │    │ (setup→launch│
│            │◀───│             │◀───│  →verify)    │
└──────────┘    └─────────────┘    └──────────────┘
     │               │
     │   ┌───────────┴──────────┐
     │   │  queue.Queue()        │  ← 线程安全日志管道
     │   │  (log messages)       │
     │   └───────────┬──────────┘
     │               │
     ▼               ▼
  UI 轮询队列     attack 写入队列
  (after 100ms)  (实时进度/日志)
```

### 关键设计

- **runner 线程**: daemon 线程，执行 attack.run()，通过 threading.Event 控制停止
- **日志队列**: queue.Queue() 线程安全传日志到 UI，UI 用 root.after(100ms) 轮询刷新
- **停止机制**: 点击停止 → 设置 stop_event → runner 检测 → 调用 attack.teardown() 清理
- **结果回调**: 攻击结束后 runner 通过队列发送 _RESULT_ 标记，UI 更新状态栏和进度
- **错误处理**: runner 异常通过队列发送 _ERROR_ 标记，UI 弹窗提示

---

## 6. 模块职责

| 模块 | 职责 | 关键数据 |
|------|------|---------|
| `app.py` | 创建 Tk 根窗口，编排面板布局，处理关闭事件 | `Tk`, `PanedWindow` |
| `attack_tree.py` | 左侧 Treeview，4 类 12 攻击，选中事件回调 | `ttk.Treeview` |
| `config_form.py` | 根据攻击类型动态生成输入控件，收集/验证参数 | 动态 Frame |
| `log_panel.py` | 队列轮询，彩色日志输出，自动滚动 | `ScrolledText` |
| `runner.py` | 后台攻击线程，Event 停止，进度/日志回调 | `threading.Thread` |
| `styles.py` | 颜色/字体/间距常量，ttk 样式配置 | 常量模块 |

---

## 7. 依赖与兼容性

- **仅依赖 Python 标准库**: tkinter, threading, queue, dataclasses, enum
- **Packaging**: PyInstaller 打包时添加 `--hidden-import tkinter --hidden-import tkinter.ttk`
- **平台**: Windows 7+ (32/64 bit), Linux (若安装了 python3-tk)
- **Npcap**: GUI 启动时检测 Npcap，状态栏显示结果，不影响纯发包功能

---

## 8. 与现有代码的关系

- 复用 `ospf_attack.cli.commands._ATTACK_REGISTRY` 获取攻击列表和配置类
- 复用 `ospf_attack.config.types` 中的 dataclass 作为表单元数据
- 复用 `ospf_attack.config.config.build_config` 构造 AttackConfig
- 攻击执行完全走现有 `Attack.run()` 接口，不重复实现

---

## 9. 明确避免的反模式

- 不引入任何第三方 GUI 框架（PyQt/wxPython 等）
- GUI 模块不修改核心攻击逻辑
- runner 线程不直接操作 UI 控件（全部通过 queue 传递）
- 日志不阻塞 UI 线程（轮询间隔保护）
- 停止操作必须在 5 秒内完成清理

---

## 10. 已实现的扩展功能

### 10.1 路由条目表格编辑器

LSA 攻击支持通过表格编辑多条伪造路由：

- 弹出窗口显示路由表格（目标网段 / 掩码 / Metric / E1-E2类型 / 转发地址）
- 支持添加、编辑、删除路由条目
- LSA 类型自动关联（Type-3 Summary / Type-5 External）
- Link State ID 自动计算（Type-1=AdvRouter, Type-3/5=第一条路由网段）

### 10.2 报文预览面板

右侧独立面板实时显示构造的 OSPF 报文结构：

- Hello 攻击 → IP Header + OSPF Header + Hello body
- LSA 攻击 → IP Header + OSPF Header + LSU + LSA Header + Body + 伪造路由详情
- DoS / MITM / Replay → 攻击参数摘要
- 支持导出为 pcap 文件（Scapy wrpcap）

### 10.3 实时嗅探与 pcap 导入

- **嗅探报文**: 在选定网卡捕获 OSPF 报文（可配置时长），弹出 PacketBrowser
- **导入 pcap**: 从 pcap/pcapng 文件解析 OSPF 报文
- **PacketBrowser**: 表格展示所有报文（类型/源IP/目的IP/摘要）
  - 选中报文 → 详情区显示完整字段
  - 「应用到表单」→ 自动填充 GUI 参数
  - 「保存为 pcap」→ 导出选中报文

### 10.4 参数自动填充

从捕获/导入的 OSPF 报文中提取字段自动填充表单：
- Hello 报文 → router_id, area_id, mask, hello_interval, priority, dead_interval
- LSU 报文 → router_id, area_id, lsa_type, link_state_id, advertising_router, sequence, age, metric, network_mask, forwarding_address

### 10.5 攻击专属默认值

不同攻击类型自动设置专属默认值：
- max-seq → sequence_number = 0x7FFFFFFF
- max-age → age = 3600
- 通用 LSA → sequence_number = 0x80000001, age = 0

### 10.6 类型安全转换

`build_config_dict` 支持 `type` 元数据自动转换：
- `"type": int` → `int("0x80000001", 0)` 自动识别 hex/decimal
- combo 字段如 lsa_type ("5") 自动转为 int
