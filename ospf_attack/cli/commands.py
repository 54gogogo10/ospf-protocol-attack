import click
from ospf_attack.config.types import (
    AttackConfig,
    HelloInjectionConfig,
    LSAConfig,
    DoSConfig,
    MITMConfig,
    ReplayConfig,
    AttackMode,
    SniffMode,
)
from ospf_attack.config.config import build_config
from ospf_attack.attacks.adjacency.hello_inject import HelloInjectAttack
from ospf_attack.attacks.adjacency.adjacency_break import AdjacencyBreakAttack
from ospf_attack.attacks.adjacency.dr_bdr_hijack import DRBDRHijackAttack
from ospf_attack.attacks.lsa.route_inject import RouteInjectAttack
from ospf_attack.attacks.lsa.max_seq import MaxSeqAttack
from ospf_attack.attacks.lsa.max_age import MaxAgeAttack
from ospf_attack.attacks.lsa.fight_back import FightBackAttack
from ospf_attack.attacks.dos.flood import FloodAttack
from ospf_attack.attacks.dos.spf_recalc import SPFRecalcAttack
from ospf_attack.attacks.dos.db_overflow import DBOverflowAttack
from ospf_attack.attacks.protocol.mitm import MITMAttack
from ospf_attack.attacks.protocol.replay import ReplayAttack
from ospf_attack.cli.formatters import format_table, format_json

ATTACK_REGISTRY = {
    "hello-inject":    (HelloInjectAttack, HelloInjectionConfig),
    "adjacency-break": (AdjacencyBreakAttack, HelloInjectionConfig),
    "dr-bdr-hijack":   (DRBDRHijackAttack, HelloInjectionConfig),
    "route-inject":    (RouteInjectAttack, LSAConfig),
    "max-seq":         (MaxSeqAttack, LSAConfig),
    "max-age":         (MaxAgeAttack, LSAConfig),
    "fight-back":      (FightBackAttack, LSAConfig),
    "flood":           (FloodAttack, DoSConfig),
    "spf-recalc":      (SPFRecalcAttack, DoSConfig),
    "db-overflow":     (DBOverflowAttack, DoSConfig),
    "mitm":            (MITMAttack, MITMConfig),
    "replay":          (ReplayAttack, ReplayConfig),
}


def _common_options(f):
    options = [
        click.option("--iface", required=True, help="网卡接口"),
        click.option("--target", required=True, help="目标 IP 或网段"),
        click.option("--passive/--active", "mode_flag", default=None),
        click.option("--sniff-mode", type=click.Choice(["hub", "arp_spoof"]), default="hub"),
        click.option("--router-id", default="1.1.1.1"),
        click.option("--area-id", default="0.0.0.0"),
        click.option("--sniff-duration", type=int, default=30),
        click.option("--arp-target-a", default=""),
        click.option("--arp-target-b", default=""),
        click.option("--arp-interval", type=int, default=2),
        click.option("--packet-rate", type=int, default=10),
        click.option("--max-packets", type=int, default=0),
        click.option("--verbose/--no-verbose", default=False),
        click.option("--config", "config_file", default=""),
        click.option("--pcap-output", default=""),
        click.option("--output", type=click.Choice(["table", "json"]), default="table"),
    ]
    for opt in reversed(options):
        f = opt(f)
    f = click.command()(f)
    return f


def _run_attack(attack_cls, config_cls, **kwargs):
    output_fmt = kwargs.pop("output", "table")
    config_file = kwargs.pop("config_file", "")

    if kwargs.get("mode_flag") is True:
        kwargs["mode"] = "passive"
    elif kwargs.get("mode_flag") is False:
        kwargs["mode"] = "active"

    config = build_config(attack_cls.name, kwargs, config_file)

    attack = attack_cls(config)
    result = attack.run()

    if output_fmt == "json":
        click.echo(format_json(result))
    else:
        click.echo(format_table(result))

    if not result.success:
        raise SystemExit(1)


def register_commands(cli: click.Group):
    for name, (attack_cls, config_cls) in ATTACK_REGISTRY.items():
        def _make_cmd(a_cls, c_cls):
            @_common_options
            @click.pass_context
            def cmd(ctx, **kwargs):
                filtered = {k: v for k, v in kwargs.items()
                           if k in c_cls.__dataclass_fields__ or k in ("mode_flag", "sniff_mode", "output")}
                _run_attack(a_cls, c_cls, **filtered)
            cmd.name = name
            return cmd

        cmd = _make_cmd(attack_cls, config_cls)
        cli.add_command(cmd)
