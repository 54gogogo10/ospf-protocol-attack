import json
from ospf_attack.config.types import AttackResult


def format_table(result: AttackResult) -> str:
    lines = [
        "=" * 50,
        "  攻击结果",
        "=" * 50,
        f"  成功:     {'是' if result.success else '否'}",
        f"  发包数:   {result.packets_sent}",
        f"  目标影响: {'是' if result.target_affected else '否'}",
        f"  详情:     {result.details}",
    ]
    if result.evidence:
        lines.append(f"  证据:     {json.dumps(result.evidence, indent=2, ensure_ascii=False)}")
    lines.append("=" * 50)
    return "\n".join(lines)


def format_json(result: AttackResult) -> str:
    return json.dumps({
        "success": result.success,
        "packets_sent": result.packets_sent,
        "target_affected": result.target_affected,
        "details": result.details,
        "evidence": result.evidence,
    }, indent=2, ensure_ascii=False)
