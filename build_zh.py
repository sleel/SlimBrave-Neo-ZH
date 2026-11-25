#!/usr/bin/env python3
"""SlimBrave Neo 抗上游更新汉化构建器 (Update-Resilient Localization Builder).

零第三方依赖（仅需 Python 3.9+ 标准库）：
- 单一词库 locales/zh-CN.json 按稳定的策略 Key / Key:NormalizedValue 索引
- 运行时注入（Post-Adapter Hook），不依赖行号 diff，上游更新后重跑即可生效
- 未翻译的上游新增策略优雅回退显示英文原文，并输出覆盖率与待翻译模板

用法：
  python build_zh.py --fetch                      # 拉取最新上游 main 并构建 dist/
  python build_zh.py --fetch --ref v2.2.0         # 拉取指定 Tag 构建
  python build_zh.py --upstream-dir ../SlimBrave-Neo --check --emit-missing missing.json
"""

from __future__ import annotations

import argparse
import ast
import base64
import io
import json
import pathlib
import re
import urllib.request
import zipfile
from typing import Any

UPSTREAM_REPO = "ChaoticSi1ence/SlimBrave-Neo"
MAX_ARCHIVE_BYTES = 20 * 1024 * 1024  # 20 MiB 防护上限
INJECTED_MARKER = "SLIMBRAVE-NEO-ZH"
ROOT_DIR = pathlib.Path(__file__).resolve().parent
DEFAULT_LOCALE_PATH = ROOT_DIR / "locales" / "zh-CN.json"
DEFAULT_DIST_DIR = ROOT_DIR / "dist"
REQUIRED_LOCALE_SECTIONS = ("categories", "choices", "dns_modes", "presets", "policies", "ps1_ui", "py_ui")


def normalize_policy_value(val: Any) -> str:
    """Normalize policy value across Python (True/False/list) and PowerShell (1/0/$true/$false/@(...))."""
    if isinstance(val, bool):
        return "1" if val else "0"
    if isinstance(val, (int, float)):
        return str(int(val)) if float(val).is_integer() else str(val)
    if isinstance(val, (list, tuple)):
        return json.dumps([str(x) for x in val], separators=(",", ":"))
    s = str(val).strip()
    if s.startswith("@(") and s.endswith(")"):
        items = re.findall(r'"([^"]*)"|\'([^\']*)\'', s[2:-1])
        return json.dumps([a or b for a, b in items], separators=(",", ":"))
    low = s.lower()
    if low in ("true", "$true"):
        return "1"
    if low in ("false", "$false"):
        return "0"
    return s


def lookup_policy_translation(policies_dict: dict[str, Any], key: str, value: Any) -> dict[str, str] | None:
    """Look up translation by Key:NormalizedValue first, then by Key."""
    composite = f"{key}:{normalize_policy_value(value)}"
    return policies_dict.get(composite) or policies_dict.get(key)


def load_locale(path: pathlib.Path) -> dict[str, Any]:
    """Load and validate locale JSON schema."""
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    missing = [k for k in REQUIRED_LOCALE_SECTIONS if k not in data]
    if missing:
        raise ValueError(f"词库文件 {path} 缺少必需字段: {missing}")
    return data


def _download_zip(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "SlimBrave-Neo-ZH-Builder/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read(MAX_ARCHIVE_BYTES + 1)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise RuntimeError(f"上游归档超过 {MAX_ARCHIVE_BYTES // (1024 * 1024)} MiB 上限，已中止。")
    return data


def fetch_upstream_sources(ref: str = "main") -> dict[str, str]:
    """Download upstream scripts directly from github.com zip archive (no git or API token needed)."""
    try:
        raw = _download_zip(f"https://github.com/{UPSTREAM_REPO}/archive/refs/heads/{ref}.zip")
    except Exception:
        raw = _download_zip(f"https://github.com/{UPSTREAM_REPO}/archive/refs/tags/{ref}.zip")

    wanted = {"SlimBrave.ps1", "slimbrave-linux.py", "slimbrave-mac.py"}
    files: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for name in zf.namelist():
            base = pathlib.PurePosixPath(name).name
            if base in wanted and name.count("/") == 1:
                files[base] = zf.read(name).decode("utf-8-sig")
    missing = wanted - set(files)
    if missing:
        raise RuntimeError(f"上游归档缺少预期文件: {sorted(missing)}")
    return files


def load_local_upstream_sources(upstream_dir: pathlib.Path) -> dict[str, str]:
    """Load upstream scripts from a local directory (rejects already-patched files)."""
    files: dict[str, str] = {}
    for fname in ("SlimBrave.ps1", "slimbrave-linux.py", "slimbrave-mac.py"):
        p = upstream_dir / fname
        if p.is_file():
            text = p.read_text(encoding="utf-8-sig")
            if INJECTED_MARKER in text:
                raise ValueError(f"{p} 已经是汉化产物，请指定原始上游目录，避免重复注入。")
            files[fname] = text
    if not files:
        raise FileNotFoundError(f"目录 {upstream_dir} 中未找到 SlimBrave.ps1 或 slimbrave-*.py")
    return files


def extract_ps1_policies(ps1_src: str) -> list[dict[str, Any]]:
    """Extract policy rows from SlimBrave.ps1 for coverage auditing."""
    rows: list[dict[str, Any]] = []
    block_re = re.compile(r"@\{(?P<body>[^{}]*?Key\s*=\s*\"[^\"]+\"[^{}]*?)\}", re.S)
    for m in block_re.finditer(ps1_src):
        body = m.group("body")
        km = re.search(r'Key\s*=\s*"([^"]+)"', body)
        nm = re.search(r'Name\s*=\s*"([^"]+)"', body)
        tm = re.search(r'Tip\s*=\s*"([^"]+)"', body)
        vm = re.search(r'Value\s*=\s*(@\([^\)]*\)|"[^"]*"|\$[A-Za-z]+|-?\d+)', body)
        if km and nm:
            rows.append({
                "key": km.group(1),
                "value": vm.group(1).strip('"') if vm else "",
                "name": nm.group(1),
                "desc": tm.group(1) if tm else "",
            })
    return rows


def extract_py_policies(py_src: str) -> list[dict[str, Any]]:
    """Extract policy rows from slimbrave-linux.py or slimbrave-mac.py via Python AST."""
    tree = ast.parse(py_src)
    ns: dict[str, Any] = {}
    cats_node = None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    if t.id.startswith("CHOICES_"):
                        ns[t.id] = ast.literal_eval(node.value)
                    elif t.id == "CATEGORIES":
                        cats_node = node.value
    if cats_node is None:
        return []
    cats = eval(compile(ast.Expression(cats_node), "<upstream>", "eval"), ns)
    return [
        {
            "category": c["name"],
            "key": f["key"],
            "value": f.get("value", ""),
            "name": f["name"],
            "desc": f.get("desc", ""),
        }
        for c in cats
        for f in c.get("features", [])
    ]


def audit_coverage(sources: dict[str, str], locale: dict[str, Any]) -> dict[str, Any]:
    """Compare upstream policies against locale JSON and report translated/missing items."""
    policies_dict = locale["policies"]
    key_counts: dict[str, int] = {}
    all_rows: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str]] = set()
    for fname, extractor in (
        ("SlimBrave.ps1", extract_ps1_policies),
        ("slimbrave-linux.py", extract_py_policies),
        ("slimbrave-mac.py", extract_py_policies),
    ):
        if fname not in sources:
            continue
        for r in extractor(sources[fname]):
            pair = (r["key"], normalize_policy_value(r["value"]))
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                all_rows.append(r)
                key_counts[r["key"]] = key_counts.get(r["key"], 0) + 1

    translated = 0
    missing: dict[str, dict[str, str]] = {}
    for r in all_rows:
        if lookup_policy_translation(policies_dict, r["key"], r["value"]):
            translated += 1
        else:
            pid = f"{r['key']}:{normalize_policy_value(r['value'])}" if key_counts[r["key"]] > 1 else r["key"]
            missing[pid] = {"name": r["name"], "desc": r["desc"]}
    return {"total": len(all_rows), "translated": translated, "missing": missing}


def _safe_replace(src: str, old: str, new: str, warnings: list[str], label: str, count: int = 1) -> str:
    if old in src:
        return src.replace(old, new, count) if count > 0 else src.replace(old, new)
    warnings.append(f"[补丁跳过] 未找到锚点 '{label}'（将优雅保留上游原文）")
    return src


def _ps_escape(s: str) -> str:
    """Escape string for Windows PowerShell 5.1 double-quoted literal (including Unicode curly quotes!)."""
    return (
        s.replace("`", "``")
        .replace("$", "`$")
        .replace('"', '`"')
        .replace("\u201c", "`\u201c")
        .replace("\u201d", "`\u201d")
        .replace("\u201e", "`\u201e")
    )


def build_ps1_zh(ps1_src: str, locale: dict[str, Any]) -> tuple[str, list[str]]:
    """Transform upstream SlimBrave.ps1 into a self-contained UTF-8-BOM Chinese script."""
    if INJECTED_MARKER in ps1_src:
        raise ValueError("输入 SlimBrave.ps1 已经包含汉化运行时，拒绝重复注入。")
    warnings: list[str] = []
    ui = locale["ps1_ui"]
    b64_payload = base64.b64encode(
        json.dumps(
            {k: locale[k] for k in ("categories", "choices", "dns_modes", "presets", "policies")} | {"ui": ui},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).decode("ascii")

    ps1_runtime = f"""
# ===========================================================================
# {INJECTED_MARKER} LOCALIZATION RUNTIME (Auto-generated by build_zh.py)
# ===========================================================================
$script:zhData = [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String('{b64_payload}')
) | ConvertFrom-Json

function Get-ZhProp($obj, [string]$key) {{
    if ($null -eq $obj -or [string]::IsNullOrEmpty($key)) {{ return $null }}
    $p = $obj.PSObject.Properties[$key]
    if ($null -ne $p) {{ return $p.Value }}
    return $null
}}
function Get-ZhNormVal($v) {{
    if ($v -is [bool]) {{ if ($v) {{ return "1" }} else {{ return "0" }} }}
    return [string]$v
}}
function Get-ZhButton([string]$id) {{
    $v = Get-ZhProp $script:zhData.ui.buttons $id
    if ($null -ne $v) {{ return [string]$v }}
    return $id
}}
function Get-ZhDnsMode([string]$mode) {{
    $v = Get-ZhProp $script:zhData.dns_modes $mode
    if ($null -ne $v) {{ return [string]$v }}
    return $mode
}}
function Split-ZhShort([string]$tip) {{
    if ([string]::IsNullOrEmpty($tip)) {{ return "" }}
    $iZh = $tip.IndexOf([char]0x3002); $iEn = $tip.IndexOf(". ")
    $cut = -1
    if ($iZh -gt 0 -and $iEn -gt 0) {{ $cut = [Math]::Min($iZh, $iEn) }}
    elseif ($iZh -gt 0) {{ $cut = $iZh }}
    elseif ($iEn -gt 0) {{ $cut = $iEn }}
    if ($cut -gt 0) {{ return $tip.Substring(0, $cut) }}
    return $tip
}}

foreach ($cat in $script:cats) {{
    $cat | Add-Member -NotePropertyName 'enName' -NotePropertyValue $cat.name -Force
    $zhCat = Get-ZhProp $script:zhData.categories $cat.name
    if ($zhCat) {{ $cat.name = [string]$zhCat }}
    foreach ($row in $cat.rows) {{
        $row | Add-Member -NotePropertyName 'enName' -NotePropertyValue $row.name -Force
        $row | Add-Member -NotePropertyName 'enFull' -NotePropertyValue $row.full -Force
        $tr = Get-ZhProp $script:zhData.policies "$($row.key):$(Get-ZhNormVal $row.value)"
        if ($null -eq $tr) {{ $tr = Get-ZhProp $script:zhData.policies $row.key }}
        if ($null -ne $tr) {{
            if ($tr.name) {{ $row.name = [string]$tr.name }}
            if ($tr.desc) {{ $row.full = [string]$tr.desc; $row.short = Split-ZhShort $row.full }}
        }}
        if ($null -ne $row.PSObject.Properties['choices'] -and $null -ne $row.choices) {{
            for ($ci2 = 0; $ci2 -lt $row.choices.Count; $ci2++) {{
                $zhCh = Get-ZhProp $script:zhData.choices ([string]$row.choices[$ci2][0])
                if ($zhCh) {{ $row.choices[$ci2][0] = [string]$zhCh }}
            }}
        }}
    }}
}}
foreach ($pr in $script:presets) {{
    $trPr = Get-ZhProp $script:zhData.presets "$($pr.name) Preset"
    if ($null -eq $trPr) {{ $trPr = Get-ZhProp $script:zhData.presets $pr.name }}
    if ($null -ne $trPr) {{
        if ($trPr.name)  {{ $pr.name  = [string]$trPr.name }}
        if ($trPr.blurb) {{ $pr.blurb = [string]$trPr.blurb }}
    }}
}}
# ===========================================================================
"""

    anchor_adapter = '$script:dnsState = @{ Mode = 0; Tmpl = "" }'
    out = _safe_replace(ps1_src, anchor_adapter, ps1_runtime + "\n" + anchor_adapter, warnings, "post-adapter hook")

    # Native CJK font with graceful fallback
    out = _safe_replace(
        out,
        """function New-UiFont($family,[double]$pt){
    return New-Object System.Drawing.Font($family,[float]($pt*96.0/72.0*$script:DPI),
        [System.Drawing.FontStyle]::Regular,[System.Drawing.GraphicsUnit]::Pixel)
}""",
        """$script:zhUiFontFamily = $null
try {
    $fams = (New-Object System.Drawing.Text.InstalledFontCollection).Families | ForEach-Object { $_.Name }
    if ($fams -contains "Microsoft YaHei UI") { $script:zhUiFontFamily = "Microsoft YaHei UI" }
    elseif ($fams -contains "Microsoft YaHei") { $script:zhUiFontFamily = "Microsoft YaHei" }
} catch {}
function New-UiFont($family,[double]$pt){
    $fam = $family; $style = [System.Drawing.FontStyle]::Regular
    if ($script:zhUiFontFamily -and ($family -eq "Segoe UI" -or $family -eq "Segoe UI Semibold")) {
        $fam = $script:zhUiFontFamily
        if ($family -eq "Segoe UI Semibold") { $style = [System.Drawing.FontStyle]::Bold }
    }
    return New-Object System.Drawing.Font($fam,[float]($pt*96.0/72.0*$script:DPI),
        $style,[System.Drawing.GraphicsUnit]::Pixel)
}""",
        warnings,
        "New-UiFont",
    )

    # CJK-aware status tooltip wrapping (handles spaceless Chinese strings)
    out = _safe_replace(
        out,
        """        $ln=@(); $cur=""
        foreach($w in ($script:statusText -split '\\s+')){
            if($cur.Length -eq 0){ $cur=$w }
            elseif(($cur.Length+1+$w.Length) -le 90){ $cur="$cur $w" }
            else { $ln+=$cur; $cur=$w }
        }
        if($cur){ $ln+=$cur }""",
        """        $ln=@(); $cur=""; $curW=0
        foreach($ch in $script:statusText.ToCharArray()){
            $cw=$(if([int]$ch -ge 0x2E80){2}else{1})
            if($curW + $cw -gt 84 -and $cur.Length -gt 0){ $ln+=$cur; $cur=""; $curW=0 }
            $cur+=$ch; $curW+=$cw
        }
        if($cur){ $ln+=$cur }""",
        warnings,
        "Status tooltip CJK wrap",
    )

    # Decouple action bar button display label from internal switch ID
    out = _safe_replace(
        out,
        """function New-BarButton([string]$label,[bool]$accent){
    $b=New-Object System.Windows.Forms.Panel
    $w=[int]([System.Windows.Forms.TextRenderer]::MeasureText($label,$script:btnFont).Width+(S 34))
    $b.Location=New-Object System.Drawing.Point 0,(S 18)   # x is placed by the caller once the width is known
    $b.Size=New-Object System.Drawing.Size $w,(S 32)
    $b.BackColor=$F.Bar; $b.Tag=@{L=$label;A=$accent;Hot=$false}""",
        """function New-BarButton([string]$label,[bool]$accent){
    $disp = Get-ZhButton $label
    $b=New-Object System.Windows.Forms.Panel
    $w=[int]([System.Windows.Forms.TextRenderer]::MeasureText($disp,$script:btnFont).Width+(S 34))
    $b.Location=New-Object System.Drawing.Point 0,(S 18)   # x is placed by the caller once the width is known
    $b.Size=New-Object System.Drawing.Size $w,(S 32)
    $b.BackColor=$F.Bar; $b.Tag=@{Id=$label;L=$disp;A=$accent;Hot=$false}""",
        warnings,
        "New-BarButton",
    )
    out = _safe_replace(out, "switch($this.Tag.L){", "switch($this.Tag.Id){", warnings, "New-BarButton switch")
    out = _safe_replace(
        out,
        '$b.AccessibleName=$label; $b.AccessibleRole=[System.Windows.Forms.AccessibleRole]::PushButton',
        '$b.AccessibleName=$disp; $b.AccessibleRole=[System.Windows.Forms.AccessibleRole]::PushButton',
        warnings,
        "New-BarButton AccessibleName",
    )

    # CJK + English + Policy Key search (with symbol-only query guard)
    search_pat = re.compile(r"function Get-SearchMatches\(\[string\]\$query\)\{.*?\n\}\n\nfunction Show-SearchResults", re.S)
    new_search = r"""function Test-HasCjk([string]$s){
    return ($s -match '[\u3400-\u9FFF\uF900-\uFAFF]')
}
function Get-SearchMatches([string]$query){
    $rawTokens=@($query.Trim().ToLower() -split '[\s,;:，；：/\\|]+' | Where-Object { $_ })
    $effTokens=@()
    foreach($t in $rawTokens){
        if(Test-HasCjk $t){ $effTokens += @{ IsCjk=$true; Val=$t } }
        else {
            $c = ($t -replace '[^a-z0-9]+', '')
            if($c){ $effTokens += @{ IsCjk=$false; Val=$c } }
        }
    }
    if($effTokens.Count -eq 0){ return @() }
    $hits=@()
    for($ci=0;$ci -lt $script:cats.Count;$ci++){
        $cat=$script:cats[$ci]
        $catEn=$(if($null -ne $cat.PSObject.Properties['enName']){ [string]$cat.enName } else { "" })
        foreach($row in $cat.rows){
            $name=[string]$row.name; $desc=[string]$row.full; $key=[string]$row.key
            $enName=$(if($null -ne $row.PSObject.Properties['enName']){ [string]$row.enName } else { "" })
            $enFull=$(if($null -ne $row.PSObject.Properties['enFull']){ [string]$row.enFull } else { "" })
            $titleHay="$name $enName $key".ToLower()
            $fullHay="$name $enName $key $desc $enFull $($cat.name) $catEn".ToLower()
            $hayWords=Get-SearchWords "$enName $key $enFull $catEn"
            $titleWords=Get-SearchWords "$enName $key"
            $all=$true; $score=0
            foreach($tk in $effTokens){
                $v=$tk.Val
                if($tk.IsCjk){
                    if($titleHay.Contains($v)){ $score+=10 }
                    elseif($fullHay.Contains($v)){ $score+=3 }
                    else { $all=$false; break }
                } else {
                    $stem=Get-SearchStem $v
                    if((Test-SearchHit $hayWords $v $stem) -or $fullHay.Contains($v)){
                        if((Test-SearchHit $titleWords $v $stem) -or $titleHay.Contains($v)){ $score+=10 }
                        else { $score+=3 }
                    } else { $all=$false; break }
                }
            }
            if($all){ $hits+=@{Row=$row;Cat=$cat.name;Score=$score} }
        }
    }
    return ($hits | Sort-Object -Property @{Expression={$_.Score};Descending=$true},@{Expression={$_.Row.name}})
}

function Show-SearchResults"""
    if search_pat.search(out):
        out = search_pat.sub(lambda _m: new_search, out, count=1)
    else:
        warnings.append("[补丁跳过] 未找到 Get-SearchMatches 函数块")

    # DNS dropdown display labels (underlying $script:dnsModes stay English)
    out = _safe_replace(
        out,
        '$g.DrawString($script:dnsModes[$script:dnsState.Mode],$script:rowFont,$vb,($dr.X+(S 12)),($dr.Y+(S 6)),$script:SF); $vb.Dispose()',
        '$g.DrawString((Get-ZhDnsMode $script:dnsModes[$script:dnsState.Mode]),$script:rowFont,$vb,($dr.X+(S 12)),($dr.Y+(S 6)),$script:SF); $vb.Dispose()',
        warnings,
        "DNS dropdown text",
    )
    out = _safe_replace(
        out,
        'foreach($m in $script:dnsModes){\n            $mi=$menu.Items.Add($m)',
        'foreach($m in $script:dnsModes){\n            $mi=$menu.Items.Add((Get-ZhDnsMode $m))',
        warnings,
        "DNS dropdown menu",
    )

    # Semantic UI chrome, status & dialog replacements
    q = _ps_escape
    pairs = [
        ("window title", '$form.Text = "SlimBrave Neo"', f'$form.Text = "{q(ui["window_title"])}"', 1),
        ("rail subtitle", '$g.DrawString("Policy manager",$script:railSubFont,$sb,(S 60),(S 31),$script:SF)', f'$g.DrawString("{q(ui["rail_subtitle"])}",$script:railSubFont,$sb,(S 60),(S 31),$script:SF)', 1),
        ("nav pages", '$script:pages=@("Quick Presets","All Options")', f'$script:pages=@("{q(ui["nav_presets"])}","{q(ui["nav_all"])}")', 1),
        ("nav dns", '$script:pages+="DNS Over HTTPS"', f'$script:pages+="{q(ui["nav_dns"])}"', 1),
        ("search placeholder", '$g.DrawString("Search policies and descriptions",$script:capFont,$pb,(S 34),(S 9),$script:SF)', f'$g.DrawString("{q(ui["search_placeholder"])}",$script:capFont,$pb,(S 34),(S 9),$script:SF)', 1),
        ("search accessible", '$script:searchBox.AccessibleName="Search policies and descriptions"', f'$script:searchBox.AccessibleName="{q(ui["search_placeholder"])}"', 1),
        ("status ready", '$script:statusText="Ready"', f'$script:statusText="{q(ui["status_ready"])}"', 1),
        ("toggle on/off", '$word="Off"; if($script:state[$st.Row.Id].On){$word="On"}', f'$word="{q(ui["toggle_off"])}"; if($script:state[$st.Row.Id].On){{$word="{q(ui["toggle_on"])}"}}', 1),
        ("preset count", '$g.DrawString("$($st.P.count) policies",$script:capFont,$cb,(S 18),(S 56),$script:SF)', f'$g.DrawString("$($st.P.count) {q(ui["preset_policies_suffix"])}",$script:capFont,$cb,(S 18),(S 56),$script:SF)', 1),
        ("preset Load measure", '$sz=$g.MeasureString("Load",$script:btnFont,1000,$script:SF)', f'$sz=$g.MeasureString("{q(ui["preset_load_btn"])}",$script:btnFont,1000,$script:SF)', 1),
        ("preset Load draw", '$g.DrawString("Load",$script:btnFont,$lb,($br.X+($bw-$sz.Width)/2),($br.Y+(S 7)),$script:SF)', f'$g.DrawString("{q(ui["preset_load_btn"])}",$script:btnFont,$lb,($br.X+($bw-$sz.Width)/2),($br.Y+(S 7)),$script:SF)', 1),
        ("preset loaded", 'Set-Status "$($s.Tag.P.name) loaded - $($s.Tag.P.count) policies staged. Nothing is written until Apply."', 'Set-Status ([string]::Format($script:zhData.ui.preset_loaded_status, $s.Tag.P.name, $s.Tag.P.count))', 1),
        ("DNS mode title", '$g.DrawString("DNS over HTTPS mode",$script:rowFont,$tb,(S 18),(S 18),$script:SF)', f'$g.DrawString("{q(ui["dns"]["mode_title"])}",$script:rowFont,$tb,(S 18),(S 18),$script:SF)', 1),
        ("DNS tmpl title", '$g.DrawString("Custom template URL",$script:rowFont,$tb,(S 18),(S 92),$script:SF)', f'$g.DrawString("{q(ui["dns"]["tmpl_title"])}",$script:rowFont,$tb,(S 18),(S 92),$script:SF)', 1),
        ("DNS mode desc", '$g.DrawString("unmanaged writes no DNS policy, leaving Brave\'s own setting alone",$script:capFont,$cb,(S 18),(S 40),$script:SF)', f'$g.DrawString("{q(ui["dns"]["mode_desc"])}",$script:capFont,$cb,(S 18),(S 40),$script:SF)', 1),
        ("DNS note opt", '$note="Only used by the custom and secure modes"', f'$note="{q(ui["dns"]["tmpl_note_optional"])}"', 1),
        ("DNS note req", 'if($needs){ $note="Required - secure DNS with no template resolves nothing" }', f'if($needs){{ $note="{q(ui["dns"]["tmpl_note_required"])}" }}', 1),
        ("DNS status", 'Set-Status "DNS mode: $m"', 'Set-Status ([string]::Format($script:zhData.ui.dns.status_mode, (Get-ZhDnsMode $m)))', 1),
        ("DoH tmpl err", 'Set-Status "DoH template: $($chk.Reason)"', 'Set-Status ([string]::Format($script:zhData.ui.dns.status_tmpl_err, $chk.Reason))', 1),
        ("Search title", '$pageTitle.Text="Search"', f'$pageTitle.Text="{q(ui["search_title"])}"', 1),
        ("Search crumb", '$crumb.Text="SlimBrave Neo  >  Search  -  $n $word for `"$query`""', '$crumb.Text=[string]::Format($script:zhData.ui.search_crumb, $n, $query)', 1),
        ("Search empty", '$empty.Text="Nothing matches `"$query`"."', '$empty.Text=[string]::Format($script:zhData.ui.search_empty, $query)', 1),
        ("All title", '$pageTitle.Text="All Options"', f'$pageTitle.Text="{q(ui["nav_all"])}"', 1),
        ("All crumb", '$crumb.Text="SlimBrave Neo  >  All Options  -  $total policies in one list"', '$crumb.Text=[string]::Format($script:zhData.ui.all_crumb, $total)', 1),
        ("No policy", 'Set-Status "No Brave policy set on this machine"', f'Set-Status "{q(ui["status_no_policy"])}"', 1),
        ("Synced", 'Set-Status "Policy read from registry - $($live.Count) values found"', 'Set-Status ([string]::Format($script:zhData.ui.status.synced_fmt, $live.Count))', 1),
        ("Exported", 'Set-Status "Exported $($feat.Count) policies"', 'Set-Status ([string]::Format($script:zhData.ui.status.exported_fmt, $feat.Count))', 1),
        ("Export fail", 'Set-Status "Export failed - $err"', 'Set-Status ([string]::Format($script:zhData.ui.status.export_failed_fmt, $err))', 1),
        ("Import fail", 'Set-Status "Import failed - $why"', 'Set-Status ([string]::Format($script:zhData.ui.status.import_failed_fmt, $why))', 1),
        ("Import lead", '$lead="Imported from "+(Format-ImportFileName ([System.IO.Path]::GetFileName($dlg.FileName)))', '$lead=[string]::Format($script:zhData.ui.status.imported_from_fmt, (Format-ImportFileName ([System.IO.Path]::GetFileName($dlg.FileName))))', 1),
        ("Applied", '$lead = "Applied $written policies. Restart Brave, then check brave://policy."', '$lead = [string]::Format($script:zhData.ui.status.applied_fmt, $written)', 1),
        ("Apply fail", 'Set-Status (Join-Status ("Failed to write: " + (($failed | Sort-Object) -join ", ") + ". Applied $written policies.") $repair)', 'Set-Status (Join-Status ([string]::Format($script:zhData.ui.status.apply_failed_fmt, (($failed | Sort-Object) -join ", "), $written)) $repair)', 1),
        ("Reset done", '$note = "Reset. Only keys SlimBrave Neo manages were removed."', f'$note = "{q(ui["status"]["reset_done"])}"', 1),
        ("Repair skip", 'return " Close Brave fully and run this again to clear leaked profile prefs - Brave is running, and it would overwrite the fix on its next save."', f'return " {q(ui["status"]["repair_skipped"])}"', 1),
        ("Reset body", '"Remove every policy SlimBrave Neo manages? Policies set by group policy or another tool are left alone."', f'"{q(ui["dialogs"]["confirm_reset_body"])}"', 1),
        ("Reset title", '"Confirm reset"', f'"{q(ui["dialogs"]["confirm_reset_title"])}"', 1),
        ("Unsaved", '"Staged changes have not been applied. Close and discard them?"', f'"{q(ui["dialogs"]["unsaved_body"])}"', 1),
        ("Apply admin", '"Writing machine policy needs Administrator. Relaunch elevated to apply."', f'"{q(ui["dialogs"]["not_elevated_apply"])}"', 1),
        ("Reset admin", '"Removing machine policy needs Administrator. Relaunch elevated to reset."', f'"{q(ui["dialogs"]["not_elevated_reset"])}"', 1),
        ("Relaunch loop", "'SlimBrave relaunched itself to get Administrator rights, but the new window is still not elevated, so it stopped instead of relaunching again. Run it from an administrator account.'", f'"{q(ui["dialogs"]["relaunch_loop_body"])}"', 1),
        ("No path body", '"Run this from a saved .ps1 file so it can relaunch itself as Administrator."', f'"{q(ui["dialogs"]["no_path_body"])}"', 1),
        ("No path title", '"Cannot determine script path"', f'"{q(ui["dialogs"]["no_path_title"])}"', 1),
        ("DoH title", '"Check the DoH template"', f'"{q(ui["dialogs"]["doh_check_title"])}"', 1),
        ("JSON filter", '$dlg.Filter="JSON files (*.json)|*.json"', f'$dlg.Filter="{q(ui["dialogs"]["json_filter"])}"', 0),
    ]
    for label, old, new, cnt in pairs:
        out = _safe_replace(out, old, new, warnings, label, count=cnt)

    return out, warnings


def build_py_zh(py_src: str, locale: dict[str, Any], variant: str) -> tuple[str, list[str]]:
    """Transform upstream slimbrave-linux.py or slimbrave-mac.py into a standalone Chinese TUI/CLI."""
    if INJECTED_MARKER in py_src:
        raise ValueError(f"输入 {variant} 脚本已经包含汉化运行时，拒绝重复注入。")
    warnings: list[str] = []
    b64_payload = base64.b64encode(
        json.dumps(
            {
                "categories": locale["categories"],
                "choices": locale["choices"],
                "dns_modes": locale["dns_modes"],
                "policies": locale["policies"],
                "py_ui": locale["py_ui"],
                "variant": variant,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).decode("ascii")

    runtime_code = f'''
# ===========================================================================
# {INJECTED_MARKER} LOCALIZATION & CJK CURSES RUNTIME (zero external deps)
# ===========================================================================
def _sb_zh_install():
    import base64 as _b64
    import json as _json
    import unicodedata as _ud

    _ZH = _json.loads(_b64.b64decode("{b64_payload}").decode("utf-8"))
    _UI = _ZH["py_ui"]
    _CAT_MAP, _CHOICE_MAP = _ZH["categories"], _ZH["choices"]
    _DNS_MAP, _POL_MAP = _ZH["dns_modes"], _ZH["policies"]
    _BTN_LABELS = _UI["buttons"]
    _IS_MAC_VARIANT = (_ZH.get("variant") == "mac")
    g = globals()

    def _norm_val(v):
        if isinstance(v, bool):
            return "1" if v else "0"
        if isinstance(v, (int, float)):
            return str(int(v)) if float(v).is_integer() else str(v)
        return str(v)

    def _ch_w(ch):
        if not ch or ord(ch) < 32 or _ud.category(ch) in ("Mn", "Me", "Cf"):
            return 0
        return 2 if _ud.east_asian_width(ch) in ("W", "F") else 1

    def _wcswidth(text):
        return sum(_ch_w(c) for c in (text or ""))

    def _slice_w(text, max_w):
        if max_w <= 0:
            return ""
        out, w = [], 0
        for ch in (text or ""):
            cw = _ch_w(ch)
            if w + cw > max_w:
                break
            out.append(ch)
            w += cw
        return "".join(out)

    def _truncate_w(text, max_w, ellipsis="..."):
        if max_w <= 0:
            return ""
        if _wcswidth(text) <= max_w:
            return text
        ew = _wcswidth(ellipsis)
        if max_w <= ew:
            return _slice_w(ellipsis, max_w)
        return _slice_w(text, max_w - ew).rstrip() + ellipsis

    def _ljust_w(text, width):
        s = _slice_w(text, width)
        return s + (" " * max(0, width - _wcswidth(s)))

    def _center_w(text, width):
        s = _slice_w(text, width)
        rem = max(0, width - _wcswidth(s))
        return (" " * (rem // 2)) + s + (" " * (rem - rem // 2))

    def _wrap_w(text, width, max_lines, ellipsis="..."):
        if width < 1 or max_lines < 1:
            return []
        text = " ".join((text or "").split())
        if not text:
            return []
        tokens, buf = [], []
        for ch in text:
            if ch == " " or _ch_w(ch) == 2:
                if buf:
                    tokens.append("".join(buf))
                    buf = []
                tokens.append(ch)
            else:
                buf.append(ch)
        if buf:
            tokens.append("".join(buf))

        lines, cur, cur_w = [], "", 0
        for tok in tokens:
            if tok == " ":
                if cur and cur_w + 1 <= width:
                    cur += " "
                    cur_w += 1
                elif cur:
                    lines.append(cur.rstrip())
                    cur, cur_w = "", 0
                continue
            tw = _wcswidth(tok)
            if cur and cur_w + tw > width:
                lines.append(cur.rstrip())
                cur, cur_w = "", 0
            if tw > width:
                part = tok
                while part:
                    chunk = _slice_w(part, width)
                    if not chunk:
                        break
                    lines.append(chunk)
                    part = part[len(chunk):]
                cur, cur_w = "", 0
            else:
                cur += tok
                cur_w += tw
        if cur.strip():
            lines.append(cur.rstrip())
        if len(lines) <= max_lines:
            return lines
        kept = lines[:max_lines]
        kept[-1] = _truncate_w(kept[-1], width, ellipsis)
        return kept

    # 1. Translate CATEGORIES in-place (preserving en_name / key for bilingual search)
    for cat in g.get("CATEGORIES", []):
        cat["en_name"] = cat.get("name", "")
        cat["name"] = _CAT_MAP.get(cat["en_name"], cat["en_name"])
        for feat in cat.get("features", []):
            feat["en_name"] = feat.get("name", "")
            feat["en_desc"] = feat.get("desc", "")
            key, val = feat.get("key", ""), feat.get("value", "")
            tr = _POL_MAP.get(f"{{key}}:{{_norm_val(val)}}") or _POL_MAP.get(key)
            if tr:
                feat["name"] = tr.get("name") or feat["name"]
                feat["desc"] = tr.get("desc") or feat["desc"]
            if "choices" in feat:
                feat["choices"] = [(_CHOICE_MAP.get(lbl, lbl), cval) for lbl, cval in feat["choices"]]

    for cname in ("CHOICES_ALLOW_ASK_BLOCK", "CHOICES_ALLOW_BLOCK", "CHOICES_ASK_BLOCK"):
        if cname in g:
            g[cname] = [(_CHOICE_MAP.get(lbl, lbl), cval) for lbl, cval in g[cname]]

    # 2. Translate module-level constants
    for k_mod, k_ui in (
        ("INERT_SUFFIX", "inert_suffix"),
        ("ORIGIN_NOTE_ONLY", "origin_note_only"),
        ("ORIGIN_NOTE_BESIDE", "origin_note_beside"),
        ("PROFILE_STILL_INSTALLED", "profile_still_installed"),
        ("PROFILE_STILL_APPLIES", "profile_still_applies"),
    ):
        if k_mod in g:
            g[k_mod] = _UI[k_ui]
    if "BUTTON_DESC" in g:
        g["BUTTON_DESC"].update(_UI["button_desc_mac"] if _IS_MAC_VARIANT else _UI["button_desc_linux"])
    if "DNS_DESC" in g:
        g["DNS_DESC"].update(_UI["dns_desc"])
    if "PERSIST_DESCRIPTIONS" in g:
        g["PERSIST_DESCRIPTIONS"].update(_UI["persist_desc"])
    if "HELP_LINES" in g:
        g["HELP_LINES"] = list(_UI["help_lines"])

    # 3. Preserve en_name onto rows built by build_rows() & enable bilingual `/` filter
    _orig_build_rows = g["build_rows"]
    def _zh_build_rows(*args, **kwargs):
        rows = _orig_build_rows(*args, **kwargs)
        fmap = {{}}
        for cat in g.get("CATEGORIES", []):
            for feat in cat.get("features", []):
                fmap[(feat.get("key"), _norm_val(feat.get("value")))] = feat
                fmap[(feat.get("key"), None)] = feat
        for row in rows:
            if row.get("type") in (g["ROW_FEATURE"], g["ROW_CHOICE"]):
                f = fmap.get((row.get("key"), _norm_val(row.get("value")))) or fmap.get((row.get("key"), None))
                if f:
                    row["en_text"] = f.get("en_name", "")
        return rows
    g["build_rows"] = _zh_build_rows

    def _zh_row_matches_filter(row, needle):
        if row["type"] not in (g["ROW_FEATURE"], g["ROW_CHOICE"]):
            return False
        hay = f"{{row.get('text', '')}} {{row.get('en_text', '')}} {{row.get('key', '')}}".lower()
        return needle in hay
    g["row_matches_filter"] = _zh_row_matches_filter

    # 4. CJK-aware wrapping & description pane
    g["wrap_description"] = _wrap_w
    g["_desc_pane_lines"].clear()
    def _zh_desc_pane_lines(max_x):
        cache = g["_desc_pane_lines"]
        if max_x not in cache:
            width = max(1, (max_x - 1) - 4)
            texts = [f.get("desc", "") for cat in g["CATEGORIES"] for f in cat["features"]]
            texts += list(g["DNS_DESC"].values()) + list(g["BUTTON_DESC"].values())
            need = max((len(_wrap_w(t, width, g["DESC_PANE_MAX_LINES"] + 2)) for t in texts), default=1)
            cache[max_x] = max(1, min(g["DESC_PANE_MAX_LINES"], need))
        return cache[max_x]
    g["desc_pane_lines"] = _zh_desc_pane_lines

    def _zh_describe_row(rows, cursor_idx, focus, btn_idx):
        if focus == g["FOCUS_BUTTONS"]:
            return g["BUTTON_DESC"].get(g["BUTTONS"][btn_idx], "")
        if not (0 <= cursor_idx < len(rows)):
            return ""
        row = rows[cursor_idx]
        kind = row["type"]
        if kind == g["ROW_HEADER"]:
            on, total = g["header_counts"](rows, cursor_idx)
            inert = g["header_inert_count"](rows, cursor_idx)
            if total or inert:
                built_in = _UI["header_desc_origin_part"].format(inert) if inert else ""
                return _UI["header_desc_tpl"].format(row["text"], total, on, built_in)
            return _UI["header_desc_dns"].format(row["text"])
        if kind == g["ROW_DNS"]:
            return g["DNS_DESC"]["mode"]
        if kind == g["ROW_DNS_TEMPLATE"]:
            return g["DNS_DESC"]["template"]
        if row.get("inert"):
            return _UI["inert_desc_prefix"] + " " + row.get("desc", "")
        return row.get("desc", "")
    g["describe_row"] = _zh_describe_row

    _STATUS_EXACT = {{
        "Apply cancelled.": _UI["prompts"]["apply_cancelled"],
        "Reset cancelled.": _UI["prompts"]["reset_cancelled"],
        "Import cancelled.": _UI["prompts"]["import_cancelled"],
        "Export cancelled.": _UI["prompts"]["export_cancelled"],
        "Secure/custom DNS requires a DoH template URL.": _UI["prompts"]["doh_required"],
        "Terminal too short for the description pane.": _UI["prompts"]["term_too_short"],
        "Reset all settings? Press Enter to confirm, any key to cancel.": _UI["prompts"]["reset_confirm"],
    }}
    _PROMPT_EXACT = {{
        "Filter (Esc=clear)": _UI["prompts"]["filter"],
        "Import path (Esc=cancel)": _UI["prompts"]["import_path"],
        "Export path (Esc=cancel)": _UI["prompts"]["export_path"],
    }}

    def _safe_put(stdscr, y, x, text, max_cols, attr, max_y, usable_w):
        curses = g["curses"]
        if max_cols <= 0 or y < 0 or y >= max_y or x < 0 or x >= usable_w:
            return
        clipped = _slice_w(text, min(max_cols, usable_w - x))
        if not clipped:
            return
        try:
            stdscr.addstr(y, x, clipped, attr)
        except (curses.error, ValueError):
            pass

    # 5. CJK-safe draw(), draw_help(), _draw_prompt_overlay(), and Unicode prompt_text_input()
    def _zh_draw(stdscr, rows, cursor_idx, scroll_offset, focus, btn_idx,
                 status_msg, status_ok, install_method="",
                 prompt_label="", prompt_buf="", prompt_cur=0, filter_text="",
                 show_desc=False, describe_focus=None):
        curses = g["curses"]
        stdscr.erase()
        max_y, max_x = stdscr.getmaxyx()
        usable_w = max_x - 1
        hz, vt, tl, tr, bl, br, ellipsis = g["box_glyphs"]()
        status_msg = _STATUS_EXACT.get(status_msg, status_msg)
        prompt_label = _PROMPT_EXACT.get(prompt_label, prompt_label)
        status = g["status_lines"](status_msg, max_x) if focus != g["FOCUS_PROMPT"] else []
        lay = g["layout"](max_y, max_x, show_desc, len(status))
        if len(status) > lay["status_lines"]:
            status = g["status_lines"](status_msg, max_x, lay["status_lines"])
        framed = lay["framed"]
        inner_x = 2 if framed else 0
        inner_w = max(1, usable_w - 4) if framed else usable_w
        edge_attr = curses.color_pair(g["CP_NORMAL"]) | curses.A_DIM

        def put(y, x, text, max_cols, attr):
            _safe_put(stdscr, y, x, text, max_cols, attr, max_y, usable_w)

        def frame(top, bottom, label=""):
            ew = max(0, usable_w - 2)
            lw = _wcswidth(label)
            head = (hz + label + (hz * (ew - lw - 1))) if (label and lw + 2 < ew) else (hz * ew)
            put(top, 0, tl + head + tr, usable_w, edge_attr)
            for yy in range(top + 1, bottom):
                put(yy, 0, vt, 1, edge_attr)
                put(yy, usable_w - 1, vt, 1, edge_attr)
            put(bottom, 0, bl + (hz * ew) + br, usable_w, edge_attr)

        title = _UI["title_with_method"].format(install_method) if install_method else _UI["title"]
        put(0, 0, _center_w(title, usable_w), usable_w, curses.color_pair(g["CP_TITLE"]) | curses.A_BOLD)

        vis = g["visible_indices"](rows, filter_text)
        needle = filter_text.strip()
        if needle:
            matches = sum(1 for i in vis if rows[i]["type"] != g["ROW_HEADER"])
            hint = _UI["hint_filter"].format(needle, matches)
        else:
            hint = _UI["hint_default"] if _wcswidth(_UI["hint_default"]) <= usable_w else _UI["hint_short"]
        put(1, 0, _center_w(hint, usable_w), usable_w, curses.color_pair(g["CP_NORMAL"]) | curses.A_DIM)

        list_start_y, visible_count = lay["list_top"], lay["list_rows"]
        if framed:
            frame(list_start_y - 1, lay["list_bottom"], _UI["frame_settings"])

        current_dns_mode = g["get_dns_mode"](rows)
        for vi in range(visible_count):
            vpos = vi + scroll_offset
            if vpos >= len(vis):
                break
            ri = vis[vpos]
            row = rows[ri]
            y = list_start_y + vi
            is_cursor = (focus == g["FOCUS_LIST"] and ri == cursor_idx)
            line, attr = "", curses.color_pair(g["CP_NORMAL"])

            if row["type"] == g["ROW_HEADER"]:
                attr = curses.color_pair(g["CP_HEADER"]) | curses.A_BOLD
                open_g, shut_g = g["disclosure_glyphs"]()
                marker = shut_g if (row.get("collapsed", False) and not needle) else open_g
                left_t = f"{{marker}} {{row['text']}}"
                on_c, tot = g["header_counts"](rows, ri)
                inert = g["header_inert_count"](rows, ri)
                counter = _UI["header_counter"].format(on_c, tot) if tot else (_UI["header_origin_only"].format(inert) if inert else "")
                if counter:
                    gap = max(2, inner_w - _wcswidth(counter) - _wcswidth(left_t) - 1)
                    line = left_t + (" " * gap) + counter
                else:
                    line = left_t
            elif row["type"] == g["ROW_FEATURE"]:
                if row.get("inert"):
                    suf = g["INERT_SUFFIX"]
                    room = max(0, inner_w - _wcswidth(suf) - _wcswidth("    [-]  "))
                    line = f"    [-] {{_truncate_w(row['text'], room, ellipsis)}} {{suf}}"
                    attr = curses.color_pair(g["CP_DIM"]) | curses.A_DIM
                else:
                    mark = "x" if row["checked"] else " "
                    line = f"    [{{mark}}] {{row['text']}}"
                    attr = curses.color_pair(g["CP_CHECKED"] if row["checked"] else g["CP_NORMAL"])
            elif row["type"] == g["ROW_CHOICE"]:
                line = f"    {{row['text']}}: < {{row['choices'][row['selected']][0]}} >"
                attr = curses.color_pair(g["CP_CHECKED"] if row["selected"] > 0 else g["CP_NORMAL"])
            elif row["type"] == g["ROW_DNS"]:
                cur_opt = row["options"][row["selected"]]
                line = f"    < {{_DNS_MAP.get(cur_opt, cur_opt)}} >"
            elif row["type"] == g["ROW_DNS_TEMPLATE"]:
                val = row["value"] or ""
                if current_dns_mode in ("custom", "secure"):
                    field_w = g["template_field_width"](max_x)
                    scroll = max(0, min(row.get("scroll", 0), len(val)))
                    cur_pos = row.get("cursor", 0)
                    if cur_pos - scroll >= field_w:
                        scroll = cur_pos - field_w + 1
                    elif cur_pos < scroll:
                        scroll = cur_pos
                    row["scroll"] = scroll
                    line = f"    Template: [{{g['_field_text'](val[scroll:scroll + field_w]).ljust(field_w)}}]"
                else:
                    line = _UI["dns_template_inactive"]
                    attr = curses.color_pair(g["CP_DIM"]) | curses.A_DIM

            if is_cursor:
                attr = curses.color_pair(g["CP_CURSOR"]) | curses.A_BOLD
            put(y, inner_x, _ljust_w(line, inner_w), inner_w, attr)

            if is_cursor and row["type"] == g["ROW_DNS_TEMPLATE"] and current_dns_mode in ("custom", "secure"):
                tmpl_val, field_start = row["value"], inner_x + 15
                field_w = g["template_field_width"](max_x)
                cur_pos = row.get("cursor", 0)
                cx = field_start + cur_pos - row.get("scroll", 0)
                if field_start <= cx < min(inner_x + inner_w, field_start + field_w):
                    ch = g["_field_text"](tmpl_val[cur_pos]) if cur_pos < len(tmpl_val) else " "
                    put(y, cx, ch, 1, curses.color_pair(g["CP_BUTTON_ACTIVE"]))

        mark_x = usable_w - 7 if framed else usable_w - 5
        if scroll_offset > 0:
            put(list_start_y - 1, mark_x, " ^^^ ", 5, edge_attr)
        if scroll_offset + visible_count < len(vis):
            put(lay["list_bottom"], mark_x, " vvv ", 5, edge_attr)

        if lay["pane_lines"]:
            top = lay["pane_top"]
            frame(top, top + lay["pane_lines"] + 1, _UI["frame_desc"])
            what = describe_focus if describe_focus is not None else focus
            parts = g["wrap_description"](g["describe_row"](rows, cursor_idx, what, btn_idx), inner_w, lay["pane_lines"], ellipsis)
            for i, part in enumerate(parts):
                put(top + 1 + i, inner_x, part, inner_w, curses.color_pair(g["CP_NORMAL"]))

        if framed:
            frame(lay["btn_top"], lay["btn_top"] + 2)
        btn_y, btn_x = lay["btn_y"], inner_x
        for i, label in enumerate(g["BUTTONS"]):
            disp = f" {{_BTN_LABELS.get(label, label)}} "
            attr = (curses.color_pair(g["CP_BUTTON_ACTIVE"]) | curses.A_BOLD) if (focus == g["FOCUS_BUTTONS"] and i == btn_idx) else curses.color_pair(g["CP_BUTTON"])
            put(btn_y, btn_x, disp, max(0, inner_x + inner_w - btn_x), attr)
            btn_x += _wcswidth(disp) + 3

        status_y = lay["status_y"]
        if focus == g["FOCUS_PROMPT"]:
            prefix = f" {{prompt_label}}: "
            pw = _wcswidth(prefix)
            avail = max(1, usable_w - pw - 1)
            # Horizontal scroll so long CJK/path inputs stay visible around the cursor
            vis_buf = prompt_buf
            vis_cur = prompt_cur
            while vis_cur > 0 and _wcswidth(vis_buf[:vis_cur]) >= avail:
                vis_buf = vis_buf[1:]
                vis_cur -= 1
            put(status_y, 0, _ljust_w(prefix + vis_buf, usable_w), usable_w, curses.color_pair(g["CP_TITLE"]))
            cur_x = pw + _wcswidth(vis_buf[:vis_cur])
            if cur_x < usable_w:
                ch = vis_buf[vis_cur] if vis_cur < len(vis_buf) else " "
                put(status_y, cur_x, ch, max(1, _ch_w(ch)), curses.color_pair(g["CP_BUTTON_ACTIVE"]))
        elif status_msg:
            cp = g["CP_STATUS_OK"] if status_ok else g["CP_STATUS_ERR"]
            for i, sline in enumerate(status):
                put(status_y + i, 2, sline, usable_w - 3, curses.color_pair(cp))
        stdscr.refresh()

    def _zh_draw_help(stdscr):
        curses = g["curses"]
        stdscr.erase()
        max_y, max_x = stdscr.getmaxyx()
        usable_w = max_x - 1
        for i, text in enumerate(g["HELP_LINES"]):
            if i >= max_y:
                break
            attr = (curses.color_pair(g["CP_TITLE"]) | curses.A_BOLD) if i == 0 else curses.color_pair(g["CP_NORMAL"])
            _safe_put(stdscr, i, 0, _ljust_w(text, usable_w), usable_w, attr, max_y, usable_w)
        stdscr.refresh()

    def _zh_draw_prompt_overlay(stdscr, desc_line, keys_line):
        curses = g["curses"]
        max_y, max_x = stdscr.getmaxyx()
        usable_w = max_x - 1
        lay = g["layout"](max_y, max_x, False)
        x, w = (2, max(1, usable_w - 4)) if lay["framed"] else (0, usable_w)
        desc_line = (desc_line
                     .replace("Apply to which Brave channels?", "应用到哪些 Brave 渠道？")
                     .replace("Persist across reboots:", "重启后保持持久化："))
        keys_line = (keys_line
                     .replace("move", "移动").replace("select", "选择")
                     .replace("quick-pick", "快捷切换").replace("toggle", "切换")
                     .replace("Enter=confirm", "Enter=确认").replace("Esc=cancel", "Esc=取消"))
        _safe_put(stdscr, lay["btn_y"], x, _ljust_w(desc_line, w), w,
                  curses.color_pair(g["CP_TITLE"]) | curses.A_BOLD, max_y, usable_w)
        _safe_put(stdscr, lay["status_y"], 0, _ljust_w(keys_line, usable_w), usable_w,
                  curses.color_pair(g["CP_STATUS_OK"]), max_y, usable_w)
        stdscr.refresh()

    def _zh_prompt_text_input(stdscr, rows, cursor_idx, scroll_offset, btn_idx,
                              install_method, label, default="", on_change=None, show_desc=False):
        """Unicode/CJK IME-aware status-line input using curses get_wch()."""
        curses = g["curses"]
        buf, cur, shown = list(default), len(default), None
        while True:
            text = "".join(buf)
            if on_change is not None and text != shown:
                cursor_idx, scroll_offset = on_change(text)
                shown = text
            g["draw"](stdscr, rows, cursor_idx, scroll_offset,
                      g["FOCUS_PROMPT"], btn_idx, "", True, install_method,
                      prompt_label=label, prompt_buf=text, prompt_cur=cur,
                      filter_text="" if on_change is None else text,
                      show_desc=show_desc,
                      describe_focus=None if on_change is not None else g["FOCUS_BUTTONS"])
            try:
                key = stdscr.get_wch() if hasattr(stdscr, "get_wch") else stdscr.getch()
            except curses.error:
                continue
            if key == curses.KEY_RESIZE:
                curses.update_lines_cols()
                continue
            if key in (27, "\\x1b"):
                return False, ""
            if key in (curses.KEY_ENTER, 10, 13, "\\n", "\\r"):
                return True, "".join(buf).strip()
            if key in (curses.KEY_BACKSPACE, 127, 8, "\\x7f", "\\x08"):
                if cur > 0:
                    buf.pop(cur - 1)
                    cur -= 1
            elif key == curses.KEY_DC:
                if cur < len(buf):
                    buf.pop(cur)
            elif key == curses.KEY_LEFT:
                if cur > 0:
                    cur -= 1
            elif key == curses.KEY_RIGHT:
                if cur < len(buf):
                    cur += 1
            elif key == curses.KEY_HOME:
                cur = 0
            elif key == curses.KEY_END:
                cur = len(buf)
            elif isinstance(key, str) and key.isprintable():
                buf.insert(cur, key)
                cur += 1
            elif isinstance(key, int) and 32 <= key <= 126:
                buf.insert(cur, chr(key))
                cur += 1

    g["draw"] = _zh_draw
    g["draw_help"] = _zh_draw_help
    g["prompt_text_input"] = _zh_prompt_text_input
    if "_draw_prompt_overlay" in g:
        g["_draw_prompt_overlay"] = _zh_draw_prompt_overlay
    g["_zh_wcswidth"] = _wcswidth

_sb_zh_install()
'''

    anchor = 'if __name__ == "__main__":'
    if anchor in py_src:
        out = py_src.replace(anchor, runtime_code + "\n\n" + anchor, 1)
    else:
        warnings.append(f"[{variant}] 未找到 main 入口锚点，已追加到文件末尾")
        out = py_src + "\n" + runtime_code
    return out, warnings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="构建 SlimBrave Neo 汉化版（抗上游更新架构）")
    src_group = parser.add_mutually_exclusive_group(required=True)
    src_group.add_argument("--upstream-dir", type=pathlib.Path, help="本地上游 SlimBrave-Neo 目录")
    src_group.add_argument("--fetch", action="store_true", help="直接从 GitHub 拉取上游源码（无需 git / Token）")
    parser.add_argument("--ref", default="main", help="搭配 --fetch 的分支或 Tag（默认 main）")
    parser.add_argument("--locale", type=pathlib.Path, default=DEFAULT_LOCALE_PATH, help="中文词库路径")
    parser.add_argument("--out-dir", type=pathlib.Path, default=DEFAULT_DIST_DIR, help="产物输出目录")
    parser.add_argument("--check", action="store_true", help="严格审计：若有未翻译的上游新增策略返回退出码 2")
    parser.add_argument("--emit-missing", type=pathlib.Path, help="导出未翻译策略的 JSON 模板路径")
    args = parser.parse_args(argv)

    locale = load_locale(args.locale)
    if args.fetch:
        print(f"[1/3] 拉取上游源码: {UPSTREAM_REPO}@{args.ref}")
        sources = fetch_upstream_sources(ref=args.ref)
    else:
        print(f"[1/3] 读取本地上游: {args.upstream_dir}")
        sources = load_local_upstream_sources(args.upstream_dir)

    report = audit_coverage(sources, locale)
    total, translated, missing = report["total"], report["translated"], report["missing"]
    pct = (100.0 * translated / total) if total else 100.0
    print(f"[2/3] 策略翻译覆盖率: {translated}/{total} ({pct:.1f}%)")
    if missing:
        print(f"      发现 {len(missing)} 条上游新增未翻译策略（运行时将自动回退显示英文）:")
        for k, v in missing.items():
            print(f"        - {k}: {v['name']}")
        if args.emit_missing:
            args.emit_missing.parent.mkdir(parents=True, exist_ok=True)
            args.emit_missing.write_text(json.dumps(missing, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"      已导出待翻译模板: {args.emit_missing}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    all_warnings: list[str] = []
    print(f"[3/3] 生成单文件零依赖产物 -> {args.out_dir}")

    if "SlimBrave.ps1" in sources:
        ps1_zh, w = build_ps1_zh(sources["SlimBrave.ps1"], locale)
        all_warnings.extend(w)
        out_ps1 = args.out_dir / "SlimBrave-zh.ps1"
        out_ps1.write_text(ps1_zh, encoding="utf-8-sig", newline="\r\n")  # UTF-8 BOM for WinPS 5.1
        print(f"      {out_ps1.name} ({out_ps1.stat().st_size:,} bytes, UTF-8-BOM)")

    for src_name, out_name, variant in (
        ("slimbrave-linux.py", "slimbrave-linux-zh.py", "linux"),
        ("slimbrave-mac.py", "slimbrave-mac-zh.py", "mac"),
    ):
        if src_name in sources:
            py_zh, w = build_py_zh(sources[src_name], locale, variant)
            all_warnings.extend(w)
            out_py = args.out_dir / out_name
            out_py.write_text(py_zh, encoding="utf-8", newline="\n")
            print(f"      {out_py.name} ({out_py.stat().st_size:,} bytes, UTF-8)")

    if all_warnings:
        print("\n[警告] 上游结构变动导致以下非致命锚点跳过:")
        for w in all_warnings:
            print("  " + w)

    return 2 if (args.check and missing) else 0


if __name__ == "__main__":
    raise SystemExit(main())
