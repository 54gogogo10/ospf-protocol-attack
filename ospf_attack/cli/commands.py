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

_ATTACK_REGISTRY = {
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
        click.option("--pcap-output", default=""),
        click.option("--output", type=click.Choice(["table", "json"]), default="table"),
    ]
    for opt in reversed(options):
        f = opt(f)
    f = click.command()(f)
    return f


def _run_attack(attack_cls, config_cls, **kwargs):
    output_fmt = kwargs.pop("output", "table")

    mode = AttackMode.PASSIVE
    if "mode_flag" in kwargs and kwargs["mode_flag"] is not None:
        mode = AttackMode.PASSIVE if kwargs.pop("mode_flag") else AttackMode.ACTIVE

    sniff_mode = SniffMode(kwargs.pop("sniff_mode", "hub"))

    config = config_cls(
        iface=kwargs.pop("iface"),
        target=kwargs.pop("target"),
        mode=mode,
        sniff_mode=sniff_mode,
        router_id=kwargs.pop("router_id", "1.1.1.1"),
        area_id=kwargs.pop("area_id", "0.0.0.0"),
        sniff_duration=kwargs.pop("sniff_duration", 30),
        arp_target_a=kwargs.pop("arp_target_a", ""),
        arp_target_b=kwargs.pop("arp_target_b", ""),
        arp_interval=kwargs.pop("arp_interval", 2),
        packet_rate=kwargs.pop("packet_rate", 10),
        max_packets=kwargs.pop("max_packets", 0),
        verbose=kwargs.pop("verbose", False),
        pcap_output=kwargs.pop("pcap_output", ""),
        **kwargs,
    )

    attack = attack_cls(config)
    result = attack.run()

    if output_fmt == "json":
        click.echo(format_json(result))
    else:
        click.echo(format_table(result))

    if not result.success:
        raise SystemExit(1)


def register_commands(cli: click.Group):
    for name, (attack_cls, config_cls) in _ATTACK_REGISTRY.items():
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
