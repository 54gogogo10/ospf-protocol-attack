import pytest
import subprocess
import time
import os
import json
import re

COMPOSE_FILE = "docker/topo1-single-area/docker-compose.yml"
R1 = "ospf_r1"
R2 = "ospf_r2"
ATTACKER = "ospf_attacker"

# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def docker_exec(container: str, cmd: list[str], timeout: int = 15) -> str:
    """Run a command inside a Docker container, return stdout."""
    result = subprocess.run(
        ["docker", "exec", container] + cmd,
        capture_output=True, text=True, timeout=timeout,
    )
    return result.stdout


def frr_vtysh(container: str, command: str, timeout: int = 15) -> str:
    """Run a vtysh command inside an FRR container."""
    return docker_exec(container, ["vtysh", "-c", command], timeout)


# ---------------------------------------------------------------------------
# OSPF state parsers
# ---------------------------------------------------------------------------

def get_ospf_neighbors(container: str) -> list[dict]:
    """Parse 'show ip ospf neighbor' into a list of neighbor dicts."""
    out = frr_vtysh(container, "show ip ospf neighbor json")
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    neighbors = []
    nbrs = data.get("neighbors", {})
    for nid, entries in nbrs.items():
        if isinstance(entries, list):
            for entry in entries:
                entry["neighborId"] = nid
                neighbors.append(entry)
        elif isinstance(entries, dict):
            entries["neighborId"] = nid
            neighbors.append(entries)
    return neighbors


def get_ospf_database(container: str) -> dict:
    """Parse 'show ip ospf database' json output."""
    out = frr_vtysh(container, "show ip ospf database json")
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {}


def get_ip_routes(container: str) -> dict:
    """Parse 'show ip route' json output."""
    out = frr_vtysh(container, "show ip route json")
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {}


def get_ospf_interface(container: str, iface: str = "eth0") -> dict:
    """Parse 'show ip ospf interface' json for a specific interface."""
    out = frr_vtysh(container, "show ip ospf interface {} text".format(iface))
    return {"raw": out}


# ---------------------------------------------------------------------------
# Convergence / wait helpers
# ---------------------------------------------------------------------------

def wait_for_convergence(container: str, expected_neighbors: int = 1,
                         timeout: int = 30) -> bool:
    """Wait until the container has the expected number of FULL neighbors."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        nbrs = get_ospf_neighbors(container)
        full_count = sum(
            1 for n in nbrs
            if n.get("state", "").startswith("Full")
        )
        if full_count >= expected_neighbors:
            return True
        time.sleep(2)
    return False


def check_neighbor_state(container: str, neighbor_id: str) -> str:
    """Return the state string for a specific neighbor ID, or 'NotFound'."""
    nbrs = get_ospf_neighbors(container)
    for n in nbrs:
        rid = n.get("neighborId", "")
        if rid == neighbor_id or rid.startswith(neighbor_id):
            return n.get("state", "Unknown")
    return "NotFound"


def get_spf_count(container: str) -> int:
    """Get the SPF execution count from 'show ip ospf'."""
    out = frr_vtysh(container, "show ip ospf json")
    try:
        data = json.loads(out)
        return data.get("spfCount", 0) or data.get("spfScheduleCount", 0)
    except json.JSONDecodeError:
        return -1


def count_external_lsas(container: str) -> int:
    """Count Type-5 external LSAs in the LSDB."""
    db = get_ospf_database(container)
    externals = db.get("externalAreas", {})
    total = 0
    for area, lsas in externals.items():
        for lsa_list in lsas.values() if isinstance(lsas, dict) else []:
            if isinstance(lsa_list, list):
                total += len(lsa_list)
    # Alternative format: direct "external" key
    for key in db:
        if "external" in key.lower():
            entries = db[key]
            if isinstance(entries, dict):
                total += sum(
                    len(v) if isinstance(v, list) else 1
                    for v in entries.values()
                )
    return total


# ---------------------------------------------------------------------------
# Topology fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def docker_network():
    """Start the OSPF test topology, wait for convergence, tear down after."""
    project_dir = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    compose_path = os.path.join(project_dir, COMPOSE_FILE)

    subprocess.run(
        ["docker", "compose", "-f", compose_path, "up", "-d"],
        check=True, cwd=project_dir,
    )
    time.sleep(15)

    # Wait for OSPF convergence between r1 and r2
    for container in [R1, R2]:
        if not wait_for_convergence(container, expected_neighbors=1, timeout=45):
            pytest.fail(f"OSPF did not converge on {container}")

    yield {
        "r1": R1,
        "r2": R2,
        "attacker": ATTACKER,
    }

    subprocess.run(
        ["docker", "compose", "-f", compose_path, "down", "-v"],
        check=True, cwd=project_dir,
    )


# ---------------------------------------------------------------------------
# Per-test fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def attacker(docker_network):
    """Return the attacker container and ensure ospf_attack is importable."""
    # Verify Python and ospf_attack are available
    result = docker_exec(ATTACKER, ["python", "-c", "import ospf_attack; print('OK')"])
    assert "OK" in result
    return ATTACKER


def run_script_in_container(script: str, timeout: int = 30) -> str:
    """Write a Python script, docker-cp it, run it, return stdout.

    Use this for inline Python that contains null bytes or special
    characters that can't survive the subprocess → docker exec pipeline.
    """
    import os
    import tempfile

    fd, host_path = tempfile.mkstemp(suffix=".py", prefix="ospf_test_")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(script)

    container_path = "/tmp/ospf_test_script.py"
    subprocess.run(
        ["docker", "cp", host_path, f"{ATTACKER}:{container_path}"],
        check=True, capture_output=True,
    )

    result = subprocess.run(
        ["docker", "exec", ATTACKER, "python", container_path],
        capture_output=True, timeout=timeout,
    )
    os.unlink(host_path)
    out = (result.stdout or b"") + (result.stderr or b"")
    return out.decode("utf-8", errors="replace")


def run_attack_in_container(container: str, attack_cmd: list[str],
                            timeout: int = 60) -> str:
    """Run an ospf-attack command inside the attacker container."""
    cmd = ["python", "-m", "ospf_attack.cli.main"] + attack_cmd
    result = subprocess.run(
        ["docker", "exec", container] + cmd,
        capture_output=True, timeout=timeout,
    )
    out = (result.stdout or b"") + (result.stderr or b"")
    return out.decode("utf-8", errors="replace")


def run_attack_with_config(attack_cmd: list[str], yaml_overrides: dict,
                           timeout: int = 60) -> str:
    """Run attack with a temp YAML config file for attack-specific params.

    Writes a YAML file inside the attacker container, then invokes the
    attack with --config pointing to it.  Cleans up the temp file.
    """
    import yaml
    import tempfile

    base = {"iface": "eth0", "target": "224.0.0.5", "sniff_duration": 5}
    base.update(yaml_overrides)

    fd, host_path = tempfile.mkstemp(suffix=".yaml", prefix="ospf_itest_")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        yaml.dump(base, f)

    container_path = "/tmp/ospf_itest_config.yaml"
    subprocess.run(
        ["docker", "cp", host_path, f"{ATTACKER}:{container_path}"],
        check=True, capture_output=True,
    )

    full_cmd = attack_cmd + ["--config", container_path]
    result = run_attack_in_container(ATTACKER, full_cmd, timeout=timeout)

    os.unlink(host_path)
    return result
