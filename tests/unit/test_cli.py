from click.testing import CliRunner
from ospf_attack.cli.main import cli


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "hello-inject" in result.output


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0


def test_attack_list_all():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    expected = [
        "hello-inject", "adjacency-break", "dr-bdr-hijack",
        "route-inject", "max-seq", "max-age", "fight-back",
        "flood", "spf-recalc", "db-overflow",
        "mitm", "replay",
    ]
    for name in expected:
        assert name in result.output
