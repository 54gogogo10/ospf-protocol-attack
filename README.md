# OSPF Protocol Attack Simulator

OSPF 协议攻击模拟与测试工具，支持 12 种攻击类型。

## 快速开始
```bash
pip install -e ".[dev]"
ospf-attack --help
ospf-attack hello-inject --iface eth0 --target 192.168.1.0/24
```

## 攻击类型

| 类别 | 命令 | 描述 |
|------|------|------|
| 邻接关系 | hello-inject | 恶意 Hello 注入 |
| 邻接关系 | adjacency-break | 邻接关系破坏 |
| 邻接关系 | dr-bdr-hijack | DR/BDR 选举操纵 |
| LSA | route-inject | 路由注入/毒化 |
| LSA | max-seq | 最大序列号攻击 |
| LSA | max-age | Max-Age 攻击 |
| LSA | fight-back | Fight-back 反击 |
| DoS | flood | Hello/LSA 泛洪 |
| DoS | spf-recalc | SPF 重计算攻击 |
| DoS | db-overflow | 数据库溢出 |
| 协议级 | mitm | 中间人攻击 |
| 协议级 | replay | 重放攻击 |

## 构建 exe
```powershell
.\build.ps1
```
