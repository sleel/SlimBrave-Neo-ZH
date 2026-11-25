"""SlimBrave Neo 汉化构建与边界条件全量验证套件。"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import platform
import subprocess
import sys
import tempfile
import types
import unittest

from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
LOCALE_PATH = ROOT / "locales" / "zh-CN.json"
sys.path.insert(0, str(ROOT))
import build_zh  # noqa: E402


def _has_cjk(text: str) -> bool:
    return any("\u4e00" <= ch <= "\u9fff" for ch in (text or ""))


class _MockStdscr:
    """Minimal curses stdscr stub that validates every draw stays inside (max_y, max_x - 1)."""

    def __init__(self, h: int, w: int, keys: list | None = None, wcswidth_fn=None):
        self.h, self.w = h, w
        self._keys = list(keys or [])
        self._wcswidth = wcswidth_fn or len
        self.writes: list[tuple[int, int, str]] = []

    def getmaxyx(self):
        return self.h, self.w

    def erase(self):
        self.writes.clear()

    def refresh(self):
        pass

    def addstr(self, y, x, text, attr=0):
        assert 0 <= y < self.h, f"y={y} out of bounds (h={self.h})"
        assert 0 <= x < self.w - 1, f"x={x} out of bounds (usable_w={self.w - 1})"
        tw = self._wcswidth(text)
        assert x + tw <= self.w - 1, f"Overflow at y={y}, x={x}: width={tw} > usable_w={self.w - 1} ({text!r})"
        self.writes.append((y, x, text))

    def get_wch(self):
        return self._keys.pop(0)


def _load_py_module(path: pathlib.Path, mod_name: str):
    injected = False
    if "curses" not in sys.modules:
        try:
            import curses  # noqa: F401
        except ImportError:
            stub = types.ModuleType("curses")
            stub.error = Exception
            stub.A_BOLD = 1
            stub.A_DIM = 2
            stub.KEY_RESIZE = 410
            stub.KEY_ENTER = 343
            stub.KEY_BACKSPACE = 263
            stub.KEY_DC = 330
            stub.KEY_LEFT = 260
            stub.KEY_RIGHT = 261
            stub.KEY_HOME = 262
            stub.KEY_END = 360
            stub.color_pair = lambda n: n
            stub.update_lines_cols = lambda: None
            sys.modules["curses"] = stub
            injected = True
    try:
        spec = importlib.util.spec_from_file_location(mod_name, str(path))
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        if injected:
            sys.modules.pop("curses", None)


class TestLocalizationArtifacts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.locale = build_zh.load_locale(LOCALE_PATH)

    def test_dist_files_license_and_utf8_bom(self):
        self.assertTrue((ROOT / "LICENSE").is_file(), "缺少 GPL-3.0 LICENSE 文件")
        for name in ("SlimBrave-zh.ps1", "slimbrave-linux-zh.py", "slimbrave-mac-zh.py"):
            self.assertTrue((DIST / name).is_file(), f"缺少产物 dist/{name}")
        self.assertTrue(
            (DIST / "SlimBrave-zh.ps1").read_bytes().startswith(b"\xef\xbb\xbf"),
            "SlimBrave-zh.ps1 必须使用 UTF-8 with BOM",
        )

    def test_double_injection_guard(self):
        with self.assertRaises(ValueError):
            build_zh.build_ps1_zh((DIST / "SlimBrave-zh.ps1").read_text(encoding="utf-8-sig"), self.locale)
        with self.assertRaises(ValueError):
            build_zh.build_py_zh((DIST / "slimbrave-linux-zh.py").read_text(encoding="utf-8"), self.locale, "linux")

    def test_python_tui_cjk_width_help_overlay_and_unicode_input(self):
        policies_dict = self.locale["policies"]
        for fname in ("slimbrave-linux-zh.py", "slimbrave-mac-zh.py"):
            with self.subTest(script=fname):
                mod = _load_py_module(DIST / fname, f"t_{fname.replace('-', '_').replace('.', '_')}")
                self.assertGreaterEqual(len(mod.CATEGORIES), 1)
                total = 0
                for cat in mod.CATEGORIES:
                    if cat.get("en_name") in self.locale["categories"]:
                        self.assertTrue(_has_cjk(cat["name"]), f"已收录分类未汉化: {cat['en_name']}")
                    for feat in cat["features"]:
                        total += 1
                        self.assertTrue(feat.get("en_name"))
                        if build_zh.lookup_policy_translation(policies_dict, feat["key"], feat.get("value", "")):
                            self.assertTrue(_has_cjk(feat["name"]), f"已收录策略未汉化: {feat['key']}")
                            self.assertTrue(_has_cjk(feat["desc"]), f"已收录说明未汉化: {feat['key']}")
                        else:
                            # 上游新增未翻译策略必须优雅回退保留英文原文，不阻塞 CI 同步
                            self.assertTrue(bool(feat["name"]))
                        for lbl, _ in feat.get("choices", []):
                            self.assertTrue(_has_cjk(lbl))
                self.assertGreaterEqual(total, 50)
                self.assertEqual(mod.BUTTONS, ["Import", "Export", "Apply", "Reset", "Quit"])
                self.assertEqual(mod.DNS_MODES, ["unmanaged", "automatic", "off", "secure", "custom"])

                # CJK 换行边界（极窄 20 列 + 常规 76 列）
                sample = "阻止 Brave 向 Google 发送数据，参考 https://dns.example/dns-query 与 brave://policy。"
                for w in (20, 40, 76):
                    lines = mod.wrap_description(sample, width=w, max_lines=4)
                    self.assertTrue(1 <= len(lines) <= 4)
                    for ln in lines:
                        self.assertLessEqual(mod._zh_wcswidth(ln), w)

                # 双语 `/` 筛选
                rows = mod.build_rows([])
                p3a = next(r for r in rows if r.get("key") == "BraveP3AEnabled")
                self.assertTrue(mod.row_matches_filter(p3a, "分析"))
                self.assertTrue(mod.row_matches_filter(p3a, "p3a"))
                self.assertTrue(mod.row_matches_filter(p3a, "bravep3aenabled"))

                # 模拟 curses 终端渲染：80x24 与窄屏 56x16 下 draw / draw_help / overlay 均零越界
                # 在 Linux/macOS 无 TTY 环境下需 mock color_pair / update_lines_cols，避免真实 curses 报错 initscr()
                with mock.patch.object(mod.curses, "color_pair", side_effect=lambda n: n), \
                     mock.patch.object(mod.curses, "update_lines_cols", side_effect=lambda: None):
                    for h, w in ((24, 80), (16, 56), (8, 50)):
                        scr = _MockStdscr(h, w, wcswidth_fn=mod._zh_wcswidth)
                        mod.draw(scr, rows, 1, 0, mod.FOCUS_LIST, 0, "已应用 12 条策略，请重启 Brave。", True, show_desc=True)
                        mod.draw_help(scr)
                        if hasattr(mod, "_draw_prompt_overlay"):
                            mod._draw_prompt_overlay(
                                scr,
                                f"  Persist across reboots: < on >    ↳ {mod.PERSIST_DESCRIPTIONS['on']}",
                                "  ←/→ select   Y/N quick-pick   Enter=confirm   Esc=cancel",
                            )

                    # 模拟中文输入法通过 get_wch() 键入「隐私」+ 退格 +「藏」+ 回车
                    scr_in = _MockStdscr(24, 80, keys=["隐", "私", "\x7f", "藏", "\n"], wcswidth_fn=mod._zh_wcswidth)
                    ok, text = mod.prompt_text_input(scr_in, rows, 1, 0, 0, "", "Filter (Esc=clear)")
                    self.assertTrue(ok)
                    self.assertEqual(text, "隐藏")

    @unittest.skipUnless(platform.system() == "Windows", "PowerShell AST/Runtime test runs on Windows")
    def test_powershell_ast_runtime_and_search_edge_cases(self):
        ps1_path = DIST / "SlimBrave-zh.ps1"
        ps_check = rf"""
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile('{str(ps1_path)}', [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {{ $errors | ForEach-Object {{ Write-Error $_.Message }}; exit 1 }}

$src = [System.IO.File]::ReadAllText('{str(ps1_path)}')
$adapterBlock = $src.Substring($src.IndexOf('$telemetryFeatures = @('),
                               $src.IndexOf('$script:dnsState = @{{ Mode = 0; Tmpl = "" }}') - $src.IndexOf('$telemetryFeatures = @('))
$searchBlock  = $src.Substring($src.IndexOf('function Get-SearchStem([string]$w){{'),
                               $src.IndexOf('function Show-SearchResults([string]$query){{') - $src.IndexOf('function Get-SearchStem([string]$w){{'))
Invoke-Expression $adapterBlock
Invoke-Expression $searchBlock

$totalRows = 0; $zhRows = 0
foreach ($c in $script:cats) {{
    if ($null -ne (Get-ZhProp $script:zhData.categories $c.enName) -and $c.name -notmatch '[\u4e00-\u9fff]') {{ throw "Uncovered category: $($c.enName)" }}
    foreach ($r in $c.rows) {{
        $totalRows++
        $tr = Get-ZhProp $script:zhData.policies "$($r.key):$(Get-ZhNormVal $r.value)"
        if ($null -eq $tr) {{ $tr = Get-ZhProp $script:zhData.policies $r.key }}
        if ($null -ne $tr) {{
            if ($r.name -match '[\u4e00-\u9fff]' -and $r.full -match '[\u4e00-\u9fff]') {{ $zhRows++ }}
            else {{ throw "Uncovered mapped row: $($r.key)" }}
        }}
    }}
}}
$zhPresets = @($script:presets | Where-Object {{ $_.name -match '[\u4e00-\u9fff]' -and $_.blurb -match '[\u4e00-\u9fff]' }}).Count
$shortTest = Split-ZhShort "第一句说明。第二句补充。"

[pscustomobject]@{{
    totalRows = $totalRows
    zhRows    = $zhRows
    presets   = $zhPresets
    shortTest = $shortTest
    hitZh     = @(Get-SearchMatches '钱包').Count
    hitEn     = @(Get-SearchMatches 'webrtc').Count
    hitKey    = @(Get-SearchMatches 'DynamicCodeSettings').Count
    hitMix    = @(Get-SearchMatches '遥测 ping').Count
    hitSym    = @(Get-SearchMatches '---').Count
    hitBlank  = @(Get-SearchMatches '   ').Count
}} | ConvertTo-Json -Compress
"""
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_check],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"PS1 测试失败:\n{proc.stdout}\n{proc.stderr}")
        res = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertGreaterEqual(res["totalRows"], 50)
        self.assertGreaterEqual(res["zhRows"], 50)
        self.assertGreaterEqual(res["presets"], 1)
        self.assertEqual(res["shortTest"], "第一句说明")
        self.assertGreaterEqual(res["hitZh"], 1)
        self.assertGreaterEqual(res["hitEn"], 1)
        self.assertGreaterEqual(res["hitKey"], 1)
        self.assertGreaterEqual(res["hitMix"], 1)
        self.assertEqual(res["hitSym"], 0, "纯符号搜索不应匹配任何条目")
        self.assertEqual(res["hitBlank"], 0, "空白搜索不应匹配任何条目")

    def test_resilience_to_simulated_upstream_update(self):
        upstream_dir = ROOT.parent / "SlimBrave-Neo"
        if not upstream_dir.is_dir():
            self.skipTest("本地未找到上游对比目录")
        ps1_orig = (upstream_dir / "SlimBrave.ps1").read_text(encoding="utf-8-sig")
        lin_orig = (upstream_dir / "slimbrave-linux.py").read_text(encoding="utf-8-sig")

        ps1_mod = ("# shift\n" * 20) + ps1_orig.replace(
            '$telemetryFeatures = @(\n',
            '$telemetryFeatures = @(\n    @{ Name = "Disable Future Telemetry"; Key = "FutureBraveTelemetryEnabled"; Value = 0; Type = "DWord"\n       Tip = "Blocks future telemetry." },\n',
            1,
        )
        lin_mod = ("# shift\n" * 20) + lin_orig.replace(
            '"features": [\n',
            '"features": [\n            {"name": "Disable Future Telemetry", "key": "FutureBraveTelemetryEnabled", "value": False, "desc": "Blocks future telemetry."},\n',
            1,
        )

        audit = build_zh.audit_coverage({"SlimBrave.ps1": ps1_mod, "slimbrave-linux.py": lin_mod}, self.locale)
        self.assertEqual((audit["translated"], audit["total"]), (90, 91))
        self.assertIn("FutureBraveTelemetryEnabled", audit["missing"])

        lin_zh, _ = build_zh.build_py_zh(lin_mod, self.locale, "linux")
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "sim_zh.py"
            p.write_text(lin_zh, encoding="utf-8")
            mod = _load_py_module(p, "sim_zh_mod")
            feats = [f for c in mod.CATEGORIES for f in c["features"]]
            self.assertEqual(len(feats), 90)
            self.assertEqual(next(f for f in feats if f["key"] == "FutureBraveTelemetryEnabled")["name"], "Disable Future Telemetry")
            self.assertTrue(_has_cjk(next(f for f in feats if f["key"] == "BraveP3AEnabled")["name"]))


if __name__ == "__main__":
    unittest.main()
