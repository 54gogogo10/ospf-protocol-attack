import click
from ospf_attack.cli.commands import register_commands


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """OSPF 协议攻击模拟器 -- 支持 12 种 OSPF 攻击类型"""
    pass


register_commands(cli)


if __name__ == "__main__":
    cli()
