"""对 pipeline/stage2_masscan.py 的提取逻辑做 monkeypatch + 场景化实测。

重点验证 PR#1 修复的 "masscan JSON 被预写污染导致命中被静默丢" 的真实场景。
通过 monkeypatch 文件系统（把真实 masscan 输出写到临时目录）来模拟外部行为，
不依赖真正的 masscan 二进制。

运行: pytest tests/test_stage2_masscan.py -v
"""
import json
import os
import sys
import tempfile

import pytest

# 让 import pipeline 可用（仓库根在 sys.path）
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from pipeline import stage2_masscan as s2  # noqa: E402


def _write(path: str, content: str):
    with open(path, "w") as f:
        f.write(content)


def test_normal_array_extracts_all(tmp_path):
    """正常合法 masscan JSON：提取全部 ip:port。"""
    data = [
        {"ip": "1.2.3.4", "ports": [{"port": 443}, {"port": 8443}]},
        {"ip": "5.6.7.8", "ports": [{"port": 2053}]},
    ]
    jf = tmp_path / "block_001.json"
    _write(str(jf), json.dumps(data))
    tf = tmp_path / "targets.txt"
    s2._extract_targets_from_masscan(str(jf), str(tf))
    got = tf.read_text().splitlines()
    assert got == ["1.2.3.4:443", "1.2.3.4:8443", "5.6.7.8:2053"], got


def test_polluted_prefix_with_real_hits(tmp_path):
    """PR#1 核心回归：文件开头被预写了 `[]\n`（老 bug 的污染），后面是真实命中。

    这是记忆里 'masscan 有命中但 verify 报无开放端口' 的真实成因。
    正确行为：仍应提取出全部真实命中，而不是被开头的 `[]` 截断。
    """
    real = [
        {"ip": "9.9.9.9", "ports": [{"port": 443}]},
        {"ip": "10.1.1.1", "ports": [{"port": 2083}, {"port": 2087}]},
    ]
    polluted = "[]\n" + json.dumps(real)
    jf = tmp_path / "block_002.json"
    _write(str(jf), polluted)
    tf = tmp_path / "targets.txt"
    s2._extract_targets_from_masscan(str(jf), str(tf))
    got = tf.read_text().splitlines()
    assert got == ["9.9.9.9:443", "10.1.1.1:2083", "10.1.1.1:2087"], got


def test_truncated_array_fallback(tmp_path):
    """截断/损坏的 JSON（缺结尾 ]）：兜底解析不崩，尽量取最外层 []。"""
    broken = '[{"ip":"1.1.1.1","ports":[{"port":443}]'
    jf = tmp_path / "block_003.json"
    _write(str(jf), broken)
    tf = tmp_path / "targets.txt"
    # 不应抛异常
    s2._extract_targets_from_masscan(str(jf), str(tf))
    got = tf.read_text().splitlines()
    assert got == ["1.1.1.1:443"], got


def test_empty_result_is_empty(tmp_path):
    """masscan 无命中，输出 `[]`：返回空 targets。"""
    jf = tmp_path / "block_004.json"
    _write(str(jf), "[]")
    tf = tmp_path / "targets.txt"
    s2._extract_targets_from_masscan(str(jf), str(tf))
    assert tf.read_text() == "", "空结果应写出空文件"


def test_missing_file_is_empty(tmp_path):
    """masscan JSON 文件本身不存在：不崩，targets 为空。"""
    jf = tmp_path / "block_005.json"
    tf = tmp_path / "targets.txt"
    s2._extract_targets_from_masscan(str(jf), str(tf))
    assert tf.read_text() == ""


def test_nested_ports_parsing(tmp_path):
    """嵌套 ports 数组：必须按最外层解析，不能误用 rfind('[') 命中内层 ports。"""
    data = [
        {"ip": "2.2.2.2", "ports": [{"port": 443}, {"port": 8443}]},
        {"ip": "3.3.3.3", "ports": [{"port": 443}]},
    ]
    jf = tmp_path / "block_006.json"
    _write(str(jf), json.dumps(data))
    tf = tmp_path / "targets.txt"
    s2._extract_targets_from_masscan(str(jf), str(tf))
    got = tf.read_text().splitlines()
    assert got == ["2.2.2.2:443", "2.2.2.2:8443", "3.3.3.3:443"], got


def test_generate_plan_block_partition():
    """generate_plan：纯输入驱动，block 划分正确。"""
    prefixes = [f"10.0.{i}.0/24" for i in range(120)]
    plan = s2.generate_plan(13335, prefixes, block_size=50)
    blocks = plan["resume_identity"]["blocks"]
    assert len(blocks) == 3, len(blocks)
    assert blocks[0]["index"] == 1
    assert blocks[-1]["cidr_range"]["end_idx"] == 120


def test_make_ports_hash_order_independent():
    """make_ports_hash：逗号顺序不同但集合相同 → hash 相同。"""
    a = s2.make_ports_hash("443,8443,2053")
    b = s2.make_ports_hash("2053,443,8443")
    assert a == b, (a, b)
    assert len(a) == 16
