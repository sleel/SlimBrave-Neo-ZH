
# Forwarded by the elevation relaunch below, never passed by hand. After
# elevation $env:LOCALAPPDATA and HKCU belong to whichever account approved
# UAC, which under over-the-shoulder UAC is the admin and not the user whose
# Brave profile holds the leaked prefs. These carry the invoking user's path
# and SID across. $OriginalSid is read further down; dropping it from this
# block does not fail loudly, it silently scrubs the wrong hive.
# Must stay the literal first statement of the file.
param (
    [string] $OriginalLocalAppData,
    [string] $OriginalSid
)

# SlimBrave Neo - debloat and harden Brave Browser on Windows.
# https://github.com/ChaoticSi1ence/SlimBrave-Neo
#
# One self-contained script. Writes Chromium enterprise managed policy to
# HKLM\SOFTWARE\Policies\BraveSoftware\Brave; Brave reads it at startup.
#
# Relaunches itself elevated so Apply and
# Reset can write machine policy. Capture the path BEFORE anything else: under
# `iex (irm ...)` or an unsaved buffer $MyInvocation.MyCommand.Path is empty,
# and -File "" dies instantly with no diagnostic.
$script:selfPath = $MyInvocation.MyCommand.Path
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$isAdmin = (New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    # $OriginalSid is set only by the relaunch below. Seeing it here means
    # the relaunched copy is still not elevated (UAC off and a standard
    # account, for one), and relaunching again would loop without end.
    if (-not [string]::IsNullOrWhiteSpace($OriginalSid)) {
        [void][System.Windows.Forms.MessageBox]::Show(
            "SlimBrave 已尝试提权重启，但新窗口仍未获得管理员权限，为避免死循环已停止。请使用管理员账户运行。",
            'Not elevated',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error)
        exit 1
    }
    if ([string]::IsNullOrWhiteSpace($script:selfPath)) {
        [void][System.Windows.Forms.MessageBox]::Show(
            "请将脚本保存为本地 .ps1 文件后再运行，以便自动提权为管理员。",
            "无法确定脚本路径",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error)
        exit 1
    }
    try {
        # ONE quoted string, not an array: Start-Process joins an array with
        # spaces and quotes nothing, so any path containing a space (OneDrive,
        # "John Smith") silently launches the wrong thing. -NoProfile keeps the
        # elevating admin's PowerShell profile out of this process.
        $currentSid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        $relaunchArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$($script:selfPath)`"" +
            " -OriginalLocalAppData `"$env:LOCALAPPDATA`" -OriginalSid `"$currentSid`""
        Start-Process -FilePath "powershell.exe" -Verb RunAs -ErrorAction Stop `
            -ArgumentList $relaunchArgs
    } catch {
        # A declined UAC prompt is non-terminating without -ErrorAction Stop,
        # so without this the original would exit silently and look broken.
        # Report the actual error: a blocked or missing powershell.exe is not
        # the user clicking No, and a wrapper needs a non-zero exit either way.
        [void][System.Windows.Forms.MessageBox]::Show(
            "Could not relaunch as Administrator: $($_.Exception.Message)`n`nApply and Reset need elevation to write machine policy.",
            "Not elevated",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning)
        exit 1
    }
    exit
}
# ---------------------------------------------------------------------------
# High DPI & Visual Styles Support
# Fixes blurry window / text rendering on displays with >100% DPI scaling
# ---------------------------------------------------------------------------

try {
    [System.Windows.Forms.Application]::EnableVisualStyles()
} catch {}

try {
    Add-Type -Namespace SlimBrave -Name DpiHelper -MemberDefinition @'
[DllImport("user32.dll")]
public static extern bool SetProcessDpiAwarenessContext(IntPtr dpiContext);

[DllImport("shcore.dll")]
public static extern int SetProcessDpiAwareness(int awareness);

[DllImport("user32.dll")]
public static extern bool SetProcessDPIAware();

public static void EnableDpiAwareness() {
    try {
        // -4 = DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 (Windows 10 1703+)
        if (!SetProcessDpiAwarenessContext((IntPtr)(-4))) {
            // Fallback: 2 = PROCESS_PER_MONITOR_DPI_AWARE (Windows 8.1 / earlier Win10)
            if (SetProcessDpiAwareness(2) != 0) {
                // Fallback: Windows Vista / 7
                SetProcessDPIAware();
            }
        }
    } catch {
        try { SetProcessDPIAware(); } catch {}
    }
}

[DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
'@
    [SlimBrave.DpiHelper]::EnableDpiAwareness()
} catch {}

# Layout scale. The process is per-monitor-DPI-aware (above), so Windows does
# not bitmap-scale the window: every pixel literal in the GUI is laid out as
# written, while the fonts are in points and grow with the display. S() maps
# a 96-DPI design pixel to a device pixel so the grid grows with the glyphs.
# Read once, AFTER the awareness call - before it the screen DC reports a
# virtualised 96 - and kept for the life of the window (see the form below).
# It is the system DPI at startup: nothing here handles WM_DPICHANGED, so a
# scaling change after launch, or a drag to a monitor of a different DPI,
# keeps this factor (relaunch to pick up the new one).
$script:DPI = 1.0
try {
    $g0 = [System.Drawing.Graphics]::FromHwnd([IntPtr]::Zero)
    $script:DPI = [double]$g0.DpiX / 96.0
    $g0.Dispose()
} catch {}
function S([double]$px){
    # AwayFromZero: [math]::Round alone is banker's rounding, 22.5 -> 22.
    return [int][math]::Round($px*$script:DPI,[System.MidpointRounding]::AwayFromZero)
}

$machineRegistryPath = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
# HKCU inside the elevated process is the admin's hive, which is the wrong
# one under over-the-shoulder UAC. The invoking user is interactively logged
# on, so their hive is already mounted under HKEY_USERS - address it by SID
# rather than loading it. Falls back to HKCU when the script was already
# elevated (then we ARE the invoking user).
if ([string]::IsNullOrWhiteSpace($OriginalSid)) {
    $userRegistryPath = "HKCU:\SOFTWARE\Policies\BraveSoftware\Brave"
} else {
    $userRegistryPath = "Registry::HKEY_USERS\$OriginalSid\SOFTWARE\Policies\BraveSoftware\Brave"
}

Clear-Host

# The old three-column engine used to live here. Its functions were defined
# a second time by the interface's engine further down, and PowerShell binds
# the LATER definition - so this block was dead at runtime while still
# matching every grep-based test. Removed; see test_ps1_no_function_is_defined_twice.

function Test-ListPolicyIsExactly {
    param (
        [string]   $RegistryPath,
        [string]   $Name,
        [string[]] $Expected
    )
    # Ownership test: is the list on
    # disk exactly the one SlimBrave writes? An admin's own blocklist is a
    # superset (or a different set entirely) and must not be deleted just
    # because the matching box is unchecked. Absent means nothing to
    # protect, so removal is safe. Chromium reads a list in either form (see
    # List-policy helpers), and every form present must be exactly ours.
    # First the REG_SZ holding a JSON array, the form SlimBrave wrote before
    # 0f14e74; ConvertFrom-Json is assigned, never wrapped in @(), because
    # Windows PowerShell 5.1 emits a JSON array as one object.
    $item = Get-ItemProperty -Path $RegistryPath -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $item) {
        $raw = $item.$Name
        if (-not ($raw -is [string])) { return $false }
        try { $parsed = ConvertFrom-Json -InputObject $raw -ErrorAction Stop } catch { return $false }
        $vals = @()
        foreach ($x in $parsed) { $vals += [string]$x }
        if (-not (($vals.Count -eq $Expected.Count) -and -not (Compare-Object $vals $Expected))) { return $false }
    }
    # Then the numbered values in the subkey.
    $listKey = Join-Path $RegistryPath $Name
    if (-not (Test-Path $listKey)) { return $true }
    $props = Get-ItemProperty -Path $listKey -ErrorAction SilentlyContinue
    if (-not $props) { return $true }
    $actual = @()
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -match '^\d+$') { $actual += [string]$p.Value }
    }
    # An empty subkey holds no third-party list, so let it be cleaned up.
    if ($actual.Count -eq 0) { return $true }
    return (($actual.Count -eq $Expected.Count) -and -not (Compare-Object $actual $Expected))
}

$telemetryFeatures = @(
    @{ Name = "Disable Metrics Reporting"; Key = "MetricsReportingEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from uploading crash reports: locks 'Automatically send diagnostic reports' off, hides the prompt after a crash and blocks Send now on brave://crashes. Beta and Nightly turn it on by default; on Release the welcome page pre-ticks it. P3A and the usage ping have their own rows." },
    @{ Name = "Disable URL Data Collection"; Key = "UrlKeyedAnonymizedDataCollectionEnabled"; Value = 0; Type = "DWord"
       Tip = "Locks 'Make searches and browsing better' (URL-keyed anonymized data collection) off. Brave already ships it off; its only switch, the hidden Privacy Guide at brave://settings/privacy/guide, goes away once any policy is set. This also overrides an opt-in made there earlier." },
    @{ Name = "Disable Google Image Descriptions"; Key = "AccessibilityImageLabelsEnabled"; Value = 0; Type = "DWord"
       Tip = "Brave already keeps Google's image descriptions off and no longer offers the opt-in. A profile that accepted it in an older version still sends unlabeled images to Google whenever a screen reader runs; this turns that off and locks it." },
    @{ Name = "Disable P3A Analytics"; Key = "BraveP3AEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables P3A (Privacy-Preserving Product Analytics), Brave's anonymized product usage telemetry." },
    @{ Name = "Disable Stats Ping"; Key = "BraveStatsPingEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops the daily usage ping that counts this install in Brave's active-user statistics, plus the search-engine usage counts it carries and the referral-code check. P3A Analytics sends its own copy of the search counts until it is disabled too." },
    @{ Name = "Limit Variations to Critical Fixes"; Key = "ChromeVariations"; Value = 1; Type = "DWord"; Group = "variations"
       Tip = "Restricts Brave's remote seed (Griffin) to critical studies, so what Brave enables only that way stays off: WebGL/WebGPU fingerprint masking, image metadata stripping (brave://flags restores both), a Google sign-in fix. Takes effect after a restart. Mutually exclusive with Disable Variations." },
    @{ Name = "Disable Variations / Griffin Experiments"; Key = "ChromeVariations"; Value = 2; Type = "DWord"; Group = "variations"
       Tip = "Refuses every Griffin study, critical ones too, so what Brave enables only through its remote seed stays off: WebGL/WebGPU fingerprint masking, image metadata stripping, a Google sign-in fix. The seed still downloads. Takes effect after a restart. Mutually exclusive with Limit Variations." },
    @{ Name = "Disable Enhanced Spell Check"; Key = "SpellCheckServiceEnabled"; Value = 0; Type = "DWord"; Group = "spellcheck"
       Tip = "Locks off enhanced spell check, which sends what you type in web forms to Google. Brave already ships it off with no setting to turn it on; offline spell checking keeps working. Mutually exclusive with Disable Spellcheck, which turns spell checking off altogether and makes this row do nothing." }
)

$privacyFeatures = @(
    @{ Name = "Disable Safe Browsing (security downgrade)"; Key = "SafeBrowsingProtectionLevel"; Value = 0; Type = "DWord"; Group = "safebrowsing"
       Tip = "Turns Safe Browsing fully off. Brave routes these lookups through its own servers, so Google never learns who made them; turning it off buys almost no privacy and costs you the phishing and malware warning pages. Excluded from every preset. Mutually exclusive with Lock Safe Browsing On." },
    @{ Name = "Disable Autofill (Addresses)"; Key = "AutofillAddressEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from saving and auto-filling addresses and other contact details in web forms. Chromium has deprecated this policy, so brave://policy lists it as Deprecated, but Brave still applies it; its replacement (AutofillSettings) does not work in Brave yet." },
    @{ Name = "Disable Autofill (Credit Cards)"; Key = "AutofillCreditCardEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from saving and auto-filling credit card numbers in web forms. Chromium has deprecated this policy, so brave://policy lists it as Deprecated, but Brave still applies it; its replacement (AutofillSettings) does not work in Brave yet." },
    @{ Name = "Disable Password Manager"; Key = "PasswordManagerEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops the built-in password manager from offering to save or generate passwords. Passwords already saved still autofill. Recommended if you use a dedicated password manager." },
    @{ Name = "Disable Password Leak Detection"; Key = "PasswordLeakDetectionEnabled"; Value = 0; Type = "DWord"
       Tip = "Locks off the online check of your credentials against known breach lists, which runs after you sign in to a site and when you edit a saved login. Brave already ships it off; this keeps it off." },
    @{ Name = "Disable Browser Sign-in"; Key = "BrowserSignin"; Value = 0; Type = "DWord"
       Tip = "Brave has no Google browser sign-in; this locks 'Allow Google login for extensions' (brave://settings/extensions) off, as Brave already ships it. Extensions can still open Google's sign-in popup via chrome.identity. Brave Account is not affected. Takes effect after a restart." },
    @{ Name = "Enable Global Privacy Control"; Key = "BraveGlobalPrivacyControlEnabled"; Value = 1; Type = "DWord"
       Tip = "Brave already sends the Global Privacy Control signal (asking sites not to sell or share your data) on every request and has no setting for it; this keeps it on if Adblock-Only mode (English UI only) is turned on. Works even where Shields are down." },
    @{ Name = "Enable De-AMP"; Key = "BraveDeAmpEnabled"; Value = 1; Type = "DWord"
       Tip = "Keeps De-AMP on: Google AMP pages are skipped for the publisher's original page. Brave already does this by default; this locks the Settings toggle and stops Adblock-Only mode from turning it off." },
    @{ Name = "Enable Debouncing"; Key = "BraveDebouncingEnabled"; Value = 1; Type = "DWord"
       Tip = "Keeps debouncing on: known tracking redirects are skipped and you go straight to the final URL. Brave already does this by default; this locks the Settings toggle and stops Adblock-Only mode from turning it off." },
    @{ Name = "Strip Tracking URL Parameters"; Key = "BraveTrackingQueryParametersFilteringEnabled"; Value = 1; Type = "DWord"
       Tip = "Brave already strips known tracking parameters (fbclid, gclid, mc_eid, ...) from URLs and has no setting for it; this keeps stripping on if Adblock-Only mode (English UI only) is turned on. Needs Shields up." },
    @{ Name = "Reduce Language Fingerprinting"; Key = "BraveReduceLanguageEnabled"; Value = 1; Type = "DWord"
       Tip = "Brave already does this by default; this locks its Settings toggle on. Sites get only your first language in the Accept-Language header and, on Windows, macOS and a few Linux distros, only a standard font list. Needs Shields up and fingerprinting protection on." },
    @{ Name = "Disable WebRTC IP Leak"; Key = "WebRtcIPHandling"; Value = "disable_non_proxied_udp"; Type = "String"
       Tip = "Restricts WebRTC to proxied connections so video/voice calls can't expose your real IP address behind a VPN or proxy." },
    @{ Name = "Disable QUIC Protocol"; Key = "QuicAllowed"; Value = 0; Type = "DWord"
       Tip = "Disables QUIC (HTTP/3) for web requests so they use TCP (HTTP/2 or HTTP/1.1). Useful when a firewall or filter can't inspect QUIC; may slightly slow some Google sites. WebRTC calls and WebTransport still use UDP." },
    @{ Name = "Disable Network Prediction (Prefetch)"; Key = "NetworkPredictionOptions"; Value = 2; Type = "DWord"
       Tip = "Stops Brave from fetching pages ahead of your click when a site's speculation rules or prerender hints ask for it, and from pre-connecting to your search engine. Brave already defaults to this; the policy locks it against Sync and extensions." },
    @{ Name = "Block Third Party Cookies"; Key = "BlockThirdPartyCookies"; Value = 1; Type = "DWord"
       Tip = "Brave already blocks third-party cookies by default; this locks that, so the global 'Allow all cookies' choice in Shields settings, extensions, Sync and Adblock-Only mode can't turn it off. Per-site Shields exceptions still work, e.g. for an embedded login that breaks." },
    @{ Name = "Block Payment Method Probing"; Key = "PaymentMethodQueryEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops sites from learning whether you have payment methods saved: canMakePayment() always answers yes and hasEnrolledInstrument() always answers no, so neither reveals anything." },
    @{ Name = "Block Remote Debugging"; Key = "RemoteDebuggingAllowed"; Value = 0; Type = "DWord"
       Tip = "Blocks the remote debugging port and pipe, the interface automation tools use to drive the browser and read your cookies and logged-in sessions. Disable Developer Tools does not cover this. Breaks Puppeteer, Playwright and the brave://inspect remote-debugging toggle. No restart needed." },
    @{ Name = "Require HTTPS for Basic Auth"; Key = "BasicAuthOverHttpEnabled"; Value = 0; Type = "DWord"
       Tip = "Refuses HTTP Basic authentication over plain HTTP so your username and password are never sent in the clear. Breaks logins on legacy routers, printers and other appliances that only serve HTTP, and plain-HTTP proxies that use Basic authentication." },
    @{ Name = "Block Local Network Access"; Key = "LocalNetworkAccessBlockedForUrls"; Value = @("*"); Type = "List"
       Tip = "Stops public websites from reaching devices on your local network (router, NAS, printers, smart-home hubs) or apps on this computer, with no prompt or per-site exception; Brave otherwise asks. Pages opened from a local address still work. Breaks web apps that pair with local devices or helper apps." },
    @{ Name = "Disable XSLT"; Key = "XSLTEnabled"; Value = 0; Type = "DWord"
       Tip = "Turns off XSLT, the legacy XML transform engine behind XSLTProcessor and xml-stylesheet pages, an attack surface Chromium is removing; this keeps it off, even for sites that opt back in. XML styled with it (some RSS feeds and sitemaps) shows unstyled. Takes full effect after a restart." },
    @{ Name = "Disable JavaScript Optimization (hardening)"; Key = "DefaultJavaScriptOptimizerSetting"; Value = 2; Type = "DWord"
       Tip = "Turns off V8's optimizing compilers (TurboFan, Maglev) on websites; Brave says this makes it more resistant to attacks. Sites keep working, WebAssembly included, but script-heavy pages and web apps run slower, with no per-site exception. Applies to tabs opened after the change." },
    @{ Name = "Remove 'Always Allow' from App-Launch Prompts"; Key = "ExternalProtocolDialogShowAlwaysOpenCheckbox"; Value = 0; Type = "DWord"
       Tip = "Removes the 'Always allow' checkbox from the prompt Brave shows before a site opens an external app, so every launch (mailto:, Zoom, Teams, Steam, ms-* links) needs a click. Apps you already set to always open from a site still open without asking." },
    @{ Name = "Force Site Isolation for Every Site"; Key = "SitePerProcess"; Value = 1; Type = "DWord"
       Tip = "Keeps every site in its own process, as Brave already does on desktop, and stops brave://flags#site-isolation-trial-opt-out or --disable-site-isolation-trials from turning it off. Takes effect after a restart." },
    @{ Name = "Isolate Subdomains in Separate Processes"; Key = "OriginKeyedProcessesEnabled"; Value = 1; Type = "DWord"
       Tip = "Puts each origin (for example mail.example.com and docs.example.com) in its own process rather than one per site, for stronger protection against Spectre-style leaks between subdomains. Uses more processes and memory. Takes effect after a restart. A brave://flags setting overrides it." },
    @{ Name = "Block Dynamic Code in the Browser Process"; Key = "DynamicCodeSettings"; Value = 1; Type = "DWord"
       Tip = "Stops Brave's main process from creating or changing executable memory (Arbitrary Code Guard), which blocks injected shellcode and code-patching hooks there. Some antivirus, printer-driver or input-method software that loads into Brave may fail or crash it; untick this if so." }
)

# Site permissions and access lockdowns: content-setting defaults plus the
# escape hatches (guest, incognito, extensions) that would otherwise bypass
# the rest of the policy set.
#
# The first nine rows are tri-state content settings: a row carrying
# `Choices` is drawn as a dropdown instead of a checkbox, because Chromium
# accepts more than "block or leave alone" for these keys. Choices is an
# ordered list of Label/Value pairs; Value $null means "not managed", i.e.
# write nothing and remove any value we previously wrote. That entry is
# always first and is the default selection, so an untouched row behaves
# exactly like the old unchecked checkbox.
#
# The legal values differ per key and are NOT uniform - Allow (1) is not a
# member of the *GuardSetting / LocalFonts / WindowManagement / Clipboard
# enums, so those rows only offer Ask (3) and Block (2). Do not "tidy" them
# into a shared list. Web Notifications offers no Ask either: a managed Ask
# lets no notification through (AUDIT.md, DefaultNotificationsSetting row).
#
# `Value` stays on a choice row as the value its pre-tri-state checkbox
# wrote (always Block). It is never written directly; it is what a bare key
# in a legacy array-format export means on import.
#
# The last two rows (microphone, camera) carry no Choices and are plain
# checkboxes: AudioCaptureAllowed / VideoCaptureAllowed are booleans whose
# true equals unset, so false is the only managed state.
$sitePermissionFeatures = @(
    @{ Name = "Web Notifications"; Key = "DefaultNotificationsSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Allow"; Value = 1 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Sets the default for desktop notifications. Block stops every site from asking or showing them; Allow lets every site show them. Either overrides your per-site settings. Not managed keeps Brave's normal prompt (a managed Ask would let no notification through)." },
    @{ Name = "Location Access"; Key = "DefaultGeolocationSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Allow"; Value = 1 },
           @{ Label = "Ask";   Value = 3 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Sets the default for reading your physical location. Block removes the prompt entirely, so maps and delivery sites will need the location typed manually; Ask prompts every time a site asks and remembers no answer. Any choice overrides your per-site settings." },
    @{ Name = "Motion Sensors"; Key = "DefaultSensorsSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Allow"; Value = 1 },
           @{ Label = "Ask";   Value = 3 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Motion and orientation sensors are a fingerprinting vector, and Brave already blocks them by default. Block locks that: neither the settings page nor a per-site exception, even one made earlier, can allow them. Ask and Allow loosen Brave's default." },
    @{ Name = "WebUSB Access"; Key = "DefaultWebUsbGuardSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Ask";   Value = 3 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Sets the default for sites talking to USB devices. Block removes the prompt and breaks web-based hardware wallets (Ledger, Trezor) and in-browser firmware flashers; Ask keeps the prompt. Chromium has no Allow state for this key." },
    @{ Name = "Web Serial Access"; Key = "DefaultSerialGuardSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Ask";   Value = 3 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Sets the default for sites opening serial ports. Block removes the prompt and breaks in-browser microcontroller and device programming tools; Ask keeps the prompt. Chromium has no Allow state for this key." },
    @{ Name = "WebHID Access"; Key = "DefaultWebHidGuardSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Ask";   Value = 3 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Sets the default for sites talking to human interface devices. Block removes the prompt, cuts Brave Wallet's own Ledger hardware-wallet connection, and may break security keys and gamepad configurators that use WebHID rather than WebAuthn. Chromium has no Allow state for this key." },
    @{ Name = "Local Font Enumeration"; Key = "DefaultLocalFontsSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Ask";   Value = 3 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Sets the default for sites asking which fonts are installed on your machine - a strong fingerprinting signal that Shields' font protections don't cover. Blocking rarely breaks anything outside web design tools. Chromium has no Allow state for this key." },
    @{ Name = "Multi-Screen Access"; Key = "DefaultWindowManagementSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Ask";   Value = 3 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Sets the default for sites reading your monitor layout and placing windows on a chosen screen. Blocking breaks the full-screen presentation mode in some web apps. Chromium has no Allow state for this key." },
    @{ Name = "Clipboard Read Access"; Key = "DefaultClipboardSetting"; Value = 2; Type = "DWord"
       Choices = @(
           @{ Label = "Not managed"; Value = $null },
           @{ Label = "Ask";   Value = 3 },
           @{ Label = "Block"; Value = 2 })
       Tip = "Sets the default for sites reading your clipboard without you pasting. Block removes the prompt and breaks Paste buttons inside web apps; Ask keeps the prompt. Either one overrides sites you allowed before. Ctrl+V and copy buttons still work. Chromium has no Allow state for this key." },
    @{ Name = "Block Microphone Access"; Key = "AudioCaptureAllowed"; Value = 0; Type = "DWord"
       Tip = "Stops every site and extension from using the microphone or any other audio input, with no prompt; per-site Allow exceptions stop working too. Breaks web calls and meetings (Meet, Zoom or Teams on the web, Discord, Brave Talk), voice messages and dictation on websites." },
    @{ Name = "Block Camera Access"; Key = "VideoCaptureAllowed"; Value = 0; Type = "DWord"
       Tip = "Stops every site and extension from using the camera or any other video input, with no prompt; per-site Allow exceptions stop working too. Breaks web video calls (Meet, Zoom or Teams on the web, Discord, Brave Talk), webcam ID checks and in-browser QR scanners." }
)

# Lockdowns and the escape hatches (guest, incognito, extensions) that
# would otherwise bypass the rest of the policy set.
$accessControlFeatures = @(
    @{ Name = "Force Google SafeSearch"; Key = "ForceGoogleSafeSearch"; Value = 1; Type = "DWord"
       Tip = "Forces SafeSearch on for all Google searches. Mainly useful for parental controls." },
    @{ Name = "Force YouTube Restricted Mode (Strict)"; Key = "ForceYouTubeRestrict"; Value = 2; Type = "DWord"
       Tip = "Forces YouTube's Strict Restricted Mode on youtube.com and its country domains, including videos other sites embed from them; the user cannot turn it off. Many videos become unavailable and comments are hidden. Videos embedded from youtube-nocookie.com are not restricted." },
    @{ Name = "Lock Safe Browsing On (Standard)"; Key = "SafeBrowsingProtectionLevel"; Value = 1; Type = "DWord"; Group = "safebrowsing"
       Tip = "Locks Safe Browsing at Standard protection so it cannot be switched to No protection in brave://settings/security. Lookups go through Brave's proxy, as they do by default. Mutually exclusive with Disable Safe Browsing." },
    @{ Name = "Block Bypassing Safe Browsing Warnings"; Key = "DisableSafeBrowsingProceedAnyway"; Value = 1; Type = "DWord"
       Tip = "Removes the option to continue past Safe Browsing's malware and phishing warnings, so a flagged site cannot be opened, even one flagged by mistake. Does not cover certificate or download warnings. Does nothing while Safe Browsing is off; Lock Safe Browsing On keeps it on." },
    @{ Name = "Block Bypassing Certificate Warnings"; Key = "SSLErrorOverrideAllowed"; Value = 0; Type = "DWord"
       Tip = "Removes the Proceed link, and the typed bypass, from certificate-error pages, so a site whose certificate is invalid, expired or self-signed cannot be opened at all. Breaks router, NAS and printer admin pages and local dev servers that use self-signed certificates." },
    @{ Name = "Disable Guest Mode"; Key = "BrowserGuestModeEnabled"; Value = 0; Type = "DWord"
       Tip = "Removes guest browsing sessions: off-the-record windows that keep no history and run without your profile's extensions. Disable Incognito Mode does not remove them. These policies still apply inside guest windows." },
    @{ Name = "Prevent Deleting History"; Key = "AllowDeletingBrowserHistory"; Value = 0; Type = "DWord"
       Tip = "Stops anyone deleting browsing and download history in History, Downloads or Clear browsing data; Brave's clear-on-exit keeps them too. Brave's Local history retention setting (brave://settings/privacy) can still expire history after as little as a day, and SlimBrave cannot lock it." },
    @{ Name = "Block All Extensions"; Key = "ExtensionInstallBlocklist"; Value = @("*"); Type = "List"
       Tip = "Blocks installation of every extension and disables ones already installed. For lockdown/parental setups - a proxy or VPN extension would bypass DNS filtering." },
    @{ Name = "Block Sideloaded (External) Extensions"; Key = "BlockExternalExtensions"; Value = 1; Type = "DWord"
       Tip = "Blocks extensions other programs install through the Windows registry or a drop-in file (how bundleware gets in) and removes any added that way at the next launch, even ones you approved. Extensions you install yourself keep working." },
    @{ Name = "Block Command-Line Extensions (--load-extension)"; Key = "ExtensionInstallTypeBlocklist"; Value = @("command_line"); Type = "List"
       Tip = "Ignores extensions passed with --load-extension, which malware adds to Brave's shortcuts to slip one in. Google Chrome ignores that switch; Brave honours it unless this is set. --disable-extensions-except can still load one. Breaks shortcuts and test tools that use the switch. Restart needed." },
    @{ Name = "Disable Incognito Mode"; Key = "IncognitoModeAvailability"; Value = 1; Type = "DWord"; Group = "incognito"
       Tip = "Removes private browsing entirely - no incognito windows can be opened. Mutually exclusive with Force Incognito Mode." },
    @{ Name = "Force Incognito Mode"; Key = "IncognitoModeAvailability"; Value = 2; Type = "DWord"; Group = "incognito"
       Tip = "Every window opens in incognito: no history, and logins and most extensions stop persisting. Tor windows go too, and so do Leo and Brave Rewards, plus Brave Wallet unless it is allowed in private windows. Mutually exclusive with Disable Incognito Mode." }
)

# Brave 1.86+ content-protection enforcers (fingerprinting protection also
# works on 1.85). These pin Brave's own privacy defaults as managed policy so
# neither the user nor a malicious page/extension can quietly weaken them.
$shieldsContentFeatures = @(
    @{ Name = "Enforce Ad Blocking"; Key = "DefaultBraveAdblockSetting"; Value = 2; Type = "DWord"
       Tip = "Pins Brave's network ad and tracker blocking on as managed policy, so it can't be lowered in settings or per site. Cosmetic filtering (element hiding, scriptlets) is not locked, and sites with Shields off are not covered." },
    @{ Name = "Enforce Fingerprinting Protection"; Key = "DefaultBraveFingerprintingV2Setting"; Value = 3; Type = "DWord"
       Tip = "Pins Shields fingerprinting protection on as managed policy, so it can't be turned off per site. Per-API exceptions (Brave's compatibility list or your own Shields toggles) still apply, and sites with Shields off are not covered." },
    @{ Name = "Force HTTPS Upgrades (Strict; not enforced on Brave's HTTPS-First rollout)"; Key = "DefaultBraveHttpsUpgradeSetting"; Value = 2; Type = "DWord"
       Tip = "Always upgrades connections to HTTPS; sites that can't serve it show a warning instead of falling back to HTTP. Not enforced where Brave moved to Chromium's HTTPS-First mode (Beta, Nightly, part of Release), which it only presets once; Limit or Disable Variations keeps it enforced." },
    @{ Name = "Cap Referrers (Strict Origin)"; Key = "DefaultBraveReferrersSetting"; Value = 2; Type = "DWord"; Group = "referrers"
       Tip = "Caps the Referer header at the origin for cross-origin requests, as Brave already does by default, and locks it: per-site exceptions stop applying, including any Brave's compatibility list adds to fix sites. Mutually exclusive with Allow Permissive Referrers." },
    @{ Name = "Allow Permissive Referrers (unsafe-url)"; Key = "DefaultBraveReferrersSetting"; Value = 1; Type = "DWord"; Group = "referrers"
       Tip = "Sends your full referring URL cross-origin when a site requests it. Compatibility escape hatch only - this weakens privacy and is excluded from every preset. Mutually exclusive with Cap Referrers." },
    @{ Name = "Forget First-Party Storage on Close"; Key = "DefaultBraveRemember1PStorageSetting"; Value = 2; Type = "DWord"
       Tip = "Clears a site's cookies and storage when you close its last tab - sites forget you (and your logins) between visits." }
)

$braveFeatures = @(
    @{ Name = "Disable Brave Rewards"; Key = "BraveRewardsDisabled"; Value = 1; Type = "DWord"
       Tip = "Removes Brave Rewards and keeps Brave's ads service off, so no sponsored New Tab Page images or notification ads. Brave Search's own result ads are not affected, and an anonymous background fetch of the ads encryption key still runs unless Limit or Disable Variations is also set." },
    @{ Name = "Disable Brave Wallet"; Key = "BraveWalletDisabled"; Value = 1; Type = "DWord"
       Tip = "Disables the built-in cryptocurrency wallet and hides its UI." },
    @{ Name = "Disable Brave VPN"; Key = "BraveVPNDisabled"; Value = 1; Type = "DWord"
       Tip = "Removes the Brave VPN feature and its upsell prompts." },
    @{ Name = "Disable Brave AI Chat"; Key = "BraveAIChatEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables Leo, Brave's built-in AI assistant, and removes it from the sidebar and address bar. Brave still downloads Leo's WebMCP tool-scripts component, though nothing uses it while Leo is off." },
    @{ Name = "Disable Local AI (On-Device Models, Brave 1.94+, off by default on Release)"; Key = "BraveLocalAIEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from downloading and running on-device AI models and from building an AI index of your browsing history; disabling Leo does not cover this. Off by default on Release (on in Nightly and Beta); this keeps it off if Brave or you turn it on. Takes effect after a restart." },
    @{ Name = "Disable Brave Shields"; Key = "BraveShieldsDisabledForUrls"; Value = @("https://*", "http://*"); Type = "List"; Group = "shields"
       Tip = "Kiosk/testing only. Shields OFF for every site: no ad or tracker blocking; Shields & Content Protection rows, Strip Tracking URL Parameters and Reduce Language Fingerprinting do nothing. De-AMP, Debouncing, GPC and third-party cookie blocking still work. Mutually exclusive with Force Shields On." },
    @{ Name = "Force Shields On (All Sites)"; Key = "BraveShieldsEnabledForUrls"; Value = @("https://*", "http://*"); Type = "List"; Group = "shields"
       Tip = "Locks Shields ON for every site: the per-site toggle can no longer drop ad, tracker or fingerprinting protection, but switching it off still unblocks third-party cookies and storage for that site. Mutually exclusive with Disable Brave Shields." },
    @{ Name = "Disable Brave News"; Key = "BraveNewsDisabled"; Value = 1; Type = "DWord"
       Tip = "Removes the Brave News feed from the new tab page. A profile Brave opted into News on first run can still show a News button in the sidebar, which opens an empty panel." },
    @{ Name = "Disable Brave Talk"; Key = "BraveTalkDisabled"; Value = 1; Type = "DWord"
       Tip = "Hides Brave Talk (private video calls) from the new tab page, sidebar and menus. The talk.brave.com website itself still works." },
    @{ Name = "Disable Brave Playlist (off by default on Release)"; Key = "BravePlaylistEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables the Playlist feature for saving and playing media in the sidebar. Playlist is off by default on Release and Beta (on in Nightly); this keeps it off if Brave or you turn it on." },
    @{ Name = "Disable Web Discovery"; Key = "BraveWebDiscoveryEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from anonymously contributing pages you visit to the Brave Search index (Web Discovery Project)." },
    @{ Name = "Disable Speedreader"; Key = "BraveSpeedreaderEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables Speedreader, the distraction-free article reading mode." },
    @{ Name = "Disable Tor"; Key = "TorDisabled"; Value = 1; Type = "DWord"
       Tip = "Removes the 'New private window with Tor' option." },
    @{ Name = "Disable Sync"; Key = "SyncDisabled"; Value = 1; Type = "DWord"
       Tip = "Disables Brave Sync, which shares bookmarks, history, and settings across devices via a sync chain. Applying it also removes this device from its chain, so once the policy is lifted it has to rejoin with a sync code from another device." },
    @{ Name = "Disable Email Aliases"; Key = "EmailAliasesEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables the Email Aliases feature for generating throwaway email addresses, which current Brave releases turn on." }
)

$perfFeatures = @(
    @{ Name = "Disable Background Mode"; Key = "BackgroundModeEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from staying open in the background after its last window closes, which it does only while an installed extension asks to run in the background. Without one, the policy only locks off 'Continue running background apps when Brave is closed' (brave://settings/system)." },
    @{ Name = "Enable Memory Saver"; Key = "HighEfficiencyModeEnabled"; Value = 1; Type = "DWord"
       Tip = "Forces Memory Saver on: inactive tabs are discarded to free RAM and reload when you return to them." },
    @{ Name = "Force Hardware Acceleration"; Key = "HardwareAccelerationModeEnabled"; Value = 1; Type = "DWord"; Group = "hwaccel"
       Tip = "Brave already has 'Use graphics acceleration when available' on; this locks it on, so it can't be turned off in Settings to work around GPU glitches. The GPU blocklist or repeated GPU crashes can still force software rendering. Takes effect after a browser restart." },
    @{ Name = "Disable Hardware Acceleration"; Key = "HardwareAccelerationModeEnabled"; Value = 0; Type = "DWord"; Group = "hwaccel"
       Tip = "Forces GPU acceleration off, unlike Brave's default, costing rendering speed and battery. Use it only when the GPU path is the problem: flicker or artifacts from a faulty driver, a VM or RDP session with no usable GPU, or corruption while screen sharing. Takes effect after a browser restart." },
    @{ Name = "Disable Media Router (Cast)"; Key = "EnableMediaRouter"; Value = 0; Type = "DWord"
       Tip = "Disables Google Cast and its background device discovery on the local network. Takes effect after a browser restart. A profile first opened under this policy keeps Cast off after it is lifted, until the Media Router toggle in brave://settings/extensions is back on and Brave restarted." },
    @{ Name = "Always Open PDF Externally"; Key = "AlwaysOpenPdfExternally"; Value = 1; Type = "DWord"
       Tip = "Downloads PDF files instead of showing them in Brave's built-in viewer; nothing opens them until you do. Sites can tell the viewer is off, and fingerprinting protection does not hide it, which makes you easier to fingerprint." },
    @{ Name = "Disable Translate"; Key = "TranslateEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables the built-in page translation feature and its popup prompts." },
    @{ Name = "Disable Spellcheck"; Key = "SpellcheckEnabled"; Value = 0; Type = "DWord"; Group = "spellcheck"
       Tip = "Turns off spell checking in text fields entirely. Mutually exclusive with Disable Enhanced Spell Check, which keeps offline checking and only removes the Google lookup." },
    @{ Name = "Disable Search Suggestions"; Key = "SearchSuggestEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops sending what you type in the address bar to your search engine for live suggestions." },
    @{ Name = "Disable Printing"; Key = "PrintingEnabled"; Value = 0; Type = "DWord"
       Tip = "Disables printing from the browser entirely (including Ctrl+P and Save as PDF). Brave features built on print preview break too: Leo reading Google Docs and scanned PDFs, and the Screenshot tool's Full page on PDFs and Google Docs." },
    @{ Name = "Disable Default Browser Prompt"; Key = "DefaultBrowserSettingEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from asking to become your default browser, and brave://settings loses its Make default button. Brave's first-run welcome page still offers Set as default, and clicking it with this policy on crashes Brave: choose Skip there." },
    @{ Name = "Disable Developer Tools"; Key = "DeveloperToolsAvailability"; Value = 2; Type = "DWord"
       Tip = "Blocks DevTools (F12), extension debugging and the View page source shortcut and menu, and turns extension Developer mode off (no Load unpacked). Brave's Screenshot Full page then never finishes and greys out Screenshot in that window until it is closed. Not for web developers." },
    @{ Name = "Disable Wayback Machine"; Key = "BraveWaybackMachineEnabled"; Value = 0; Type = "DWord"
       Tip = "Stops Brave from offering an archive.org snapshot when a page is missing or fails (404, 408, 410, 451 and some 5xx errors), including the offer Brave can pop up on its own." }
)

# ---------------------------------------------------------------------------
# Embedded presets
#
# The Windows quick start downloads SlimBrave.ps1 on its own, so there is no
# Presets/ directory on disk for the Quick Presets row to read. The five
# preset files are embedded here verbatim instead, and parsed with the same
# ConvertFrom-Json the Import button uses, so a preset button and an imported
# file reach the controls by exactly the same route.
#
# These blocks are copies of Presets/*.json - regenerate them from those
# files rather than editing them here, because a typo is a silently wrong
# policy. Import still loads a preset (or any other config) from an arbitrary
# path, so this is additive.
#
# A here-string's closing '@ has to sit at column 0, which is why the JSON
# below is flush left.
# ---------------------------------------------------------------------------

$script:embeddedPresets = [ordered]@{
    "Maximum Privacy Preset" = @'
{
    "Features": {
        "MetricsReportingEnabled": false,
        "UrlKeyedAnonymizedDataCollectionEnabled": false,
        "AccessibilityImageLabelsEnabled": false,
        "BraveP3AEnabled": false,
        "BraveStatsPingEnabled": false,
        "AutofillAddressEnabled": false,
        "AutofillCreditCardEnabled": false,
        "PasswordManagerEnabled": false,
        "PasswordLeakDetectionEnabled": false,
        "BrowserSignin": 0,
        "BraveGlobalPrivacyControlEnabled": true,
        "BraveDeAmpEnabled": true,
        "BraveDebouncingEnabled": true,
        "BraveTrackingQueryParametersFilteringEnabled": true,
        "BraveReduceLanguageEnabled": true,
        "WebRtcIPHandling": "disable_non_proxied_udp",
        "QuicAllowed": false,
        "NetworkPredictionOptions": 2,
        "BlockThirdPartyCookies": true,
        "PaymentMethodQueryEnabled": false,
        "DefaultNotificationsSetting": 2,
        "DefaultGeolocationSetting": 2,
        "DefaultSensorsSetting": 2,
        "BraveRewardsDisabled": true,
        "BraveWalletDisabled": true,
        "BraveVPNDisabled": true,
        "BraveAIChatEnabled": false,
        "BraveNewsDisabled": true,
        "BraveTalkDisabled": true,
        "BravePlaylistEnabled": false,
        "BraveWebDiscoveryEnabled": false,
        "BraveSpeedreaderEnabled": false,
        "TorDisabled": true,
        "SyncDisabled": true,
        "EmailAliasesEnabled": false,
        "DefaultBraveAdblockSetting": 2,
        "DefaultBraveFingerprintingV2Setting": 3,
        "DefaultBraveHttpsUpgradeSetting": 2,
        "DefaultBraveReferrersSetting": 2,
        "DefaultBraveRemember1PStorageSetting": 2,
        "BackgroundModeEnabled": false,
        "EnableMediaRouter": false,
        "TranslateEnabled": false,
        "SpellcheckEnabled": false,
        "SearchSuggestEnabled": false,
        "PrintingEnabled": false,
        "DefaultBrowserSettingEnabled": false,
        "DeveloperToolsAvailability": 2,
        "BraveWaybackMachineEnabled": false,
        "BraveLocalAIEnabled": false,
        "RemoteDebuggingAllowed": false,
        "BasicAuthOverHttpEnabled": false,
        "BlockExternalExtensions": true,
        "ExtensionInstallTypeBlocklist": [
            "command_line"
        ],
        "XSLTEnabled": false,
        "DefaultJavaScriptOptimizerSetting": 2,
        "SitePerProcess": true,
        "OriginKeyedProcessesEnabled": true
    }
}
'@
    "Balanced Privacy Preset" = @'
{
    "Features": {
        "MetricsReportingEnabled": false,
        "UrlKeyedAnonymizedDataCollectionEnabled": false,
        "AccessibilityImageLabelsEnabled": false,
        "BraveP3AEnabled": false,
        "BraveStatsPingEnabled": false,
        "AutofillCreditCardEnabled": false,
        "BrowserSignin": 0,
        "BraveGlobalPrivacyControlEnabled": true,
        "BraveDeAmpEnabled": true,
        "BraveDebouncingEnabled": true,
        "BraveTrackingQueryParametersFilteringEnabled": true,
        "BraveReduceLanguageEnabled": true,
        "WebRtcIPHandling": "disable_non_proxied_udp",
        "QuicAllowed": false,
        "NetworkPredictionOptions": 2,
        "BlockThirdPartyCookies": true,
        "PaymentMethodQueryEnabled": false,
        "BraveRewardsDisabled": true,
        "BraveWalletDisabled": true,
        "BraveVPNDisabled": true,
        "BraveAIChatEnabled": false,
        "BraveNewsDisabled": true,
        "BraveTalkDisabled": true,
        "BraveWebDiscoveryEnabled": false,
        "TorDisabled": true,
        "SyncDisabled": true,
        "BackgroundModeEnabled": false,
        "DefaultBrowserSettingEnabled": false,
        "BraveLocalAIEnabled": false,
        "RemoteDebuggingAllowed": false,
        "BasicAuthOverHttpEnabled": false,
        "BlockExternalExtensions": true,
        "ExtensionInstallTypeBlocklist": [
            "command_line"
        ],
        "SpellCheckServiceEnabled": false
    },
    "DnsMode": "automatic"
}
'@
    "Performance Focused Preset" = @'
{
    "Features": {
        "MetricsReportingEnabled": false,
        "BraveP3AEnabled": false,
        "BraveStatsPingEnabled": false,
        "BraveDeAmpEnabled": true,
        "BraveDebouncingEnabled": true,
        "BraveTrackingQueryParametersFilteringEnabled": true,
        "BraveRewardsDisabled": true,
        "BraveWalletDisabled": true,
        "BraveVPNDisabled": true,
        "BraveAIChatEnabled": false,
        "BraveNewsDisabled": true,
        "BraveTalkDisabled": true,
        "BravePlaylistEnabled": false,
        "BraveWebDiscoveryEnabled": false,
        "BraveSpeedreaderEnabled": false,
        "BackgroundModeEnabled": false,
        "HighEfficiencyModeEnabled": true,
        "EnableMediaRouter": false,
        "DefaultBrowserSettingEnabled": false,
        "BraveWaybackMachineEnabled": false,
        "BraveLocalAIEnabled": false
    },
    "DnsMode": "automatic"
}
'@
    "Developer Preset" = @'
{
    "Features": {
        "MetricsReportingEnabled": false,
        "UrlKeyedAnonymizedDataCollectionEnabled": false,
        "AccessibilityImageLabelsEnabled": false,
        "BraveP3AEnabled": false,
        "BraveStatsPingEnabled": false,
        "BraveRewardsDisabled": true,
        "BraveWalletDisabled": true,
        "BraveVPNDisabled": true,
        "BraveAIChatEnabled": false,
        "BraveNewsDisabled": true,
        "BraveTalkDisabled": true,
        "BackgroundModeEnabled": false,
        "DefaultBrowserSettingEnabled": false,
        "BraveLocalAIEnabled": false,
        "SpellCheckServiceEnabled": false
    },
    "DnsMode": "automatic"
}
'@
    "Strict Parental Controls Preset" = @'
{
    "Features": {
        "BraveP3AEnabled": false,
        "BraveStatsPingEnabled": false,
        "IncognitoModeAvailability": 1,
        "BrowserGuestModeEnabled": false,
        "AllowDeletingBrowserHistory": false,
        "ExtensionInstallBlocklist": [
            "*"
        ],
        "ForceGoogleSafeSearch": true,
        "ForceYouTubeRestrict": 2,
        "SafeBrowsingProtectionLevel": 1,
        "DisableSafeBrowsingProceedAnyway": true,
        "SSLErrorOverrideAllowed": false,
        "BrowserSignin": 0,
        "BraveDeAmpEnabled": true,
        "BraveDebouncingEnabled": true,
        "BraveTrackingQueryParametersFilteringEnabled": true,
        "BraveReduceLanguageEnabled": true,
        "SyncDisabled": true,
        "BraveRewardsDisabled": true,
        "BraveWalletDisabled": true,
        "BraveVPNDisabled": true,
        "BraveAIChatEnabled": false,
        "BraveNewsDisabled": true,
        "BraveTalkDisabled": true,
        "BraveWebDiscoveryEnabled": false,
        "TorDisabled": true,
        "DeveloperToolsAvailability": 2,
        "RemoteDebuggingAllowed": false
    },
    "DnsMode": "custom",
    "DnsTemplates": "https://family.cloudflare-dns.com/dns-query"
}
'@
    "Brave Origin Preset" = @'
{
    "Features": {
        "BraveP3AEnabled": false,
        "BraveStatsPingEnabled": false,
        "BraveRewardsDisabled": true,
        "BraveWalletDisabled": true,
        "BraveVPNDisabled": true,
        "BraveAIChatEnabled": false,
        "BraveLocalAIEnabled": false,
        "BraveNewsDisabled": true,
        "BraveTalkDisabled": true,
        "BravePlaylistEnabled": false,
        "BraveWebDiscoveryEnabled": false,
        "BraveSpeedreaderEnabled": false,
        "BraveWaybackMachineEnabled": false,
        "TorDisabled": true,
        "EmailAliasesEnabled": false
    }
}
'@
}

# ---------------------------------------------------------------------------
# Adapter
#
# Reshapes the feature tables above into the rows the interface reads. The
# tables stay verbatim - they are the single source of truth, shared with the
# Python ports and parsed by the test suite - and nothing below is a second
# copy of a policy. Each row's description is its existing Tip.
# ---------------------------------------------------------------------------

$categories = @(
    @{ Name = "Telemetry & Reporting";        Features = $telemetryFeatures },
    @{ Name = "Privacy & Security";           Features = $privacyFeatures },
    @{ Name = "Site Permissions";             Features = $sitePermissionFeatures },
    @{ Name = "Access Controls";              Features = $accessControlFeatures },
    @{ Name = "Shields & Content Protection"; Features = $shieldsContentFeatures },
    @{ Name = "Brave Features";               Features = $braveFeatures },
    @{ Name = "Performance & Bloat";          Features = $perfFeatures }
)
# ---------------------------------------------------------------------------
# ADAPTER - native feature tables to the shape the interface reads
#
# The interface wants a lowercase row shape with a description and an ordered
# choices list. The tables above are the single source of truth and stay in the
# form the test suite parses, so the translation happens here at startup rather
# than by maintaining a second copy of all 90 policies.
#
# Ids are index-based because a few policy keys legitimately appear on two rows
# (incognito, referrers). State is keyed by id, never by key.
# ---------------------------------------------------------------------------
$script:state = @{}
$script:cats = @()
$script:dnsModes = @("unmanaged", "automatic", "off", "secure", "custom")

$ci = 0
foreach ($cat in $categories) {
    $rows = @()
    $ri = 0
    foreach ($f in $cat.Features) {
        $tip = [string]$f.Tip
        $short = $tip
        $dot = $tip.IndexOf(". ")
        if ($dot -gt 0) { $short = $tip.Substring(0, $dot) }
        $choices = $null
        if ($null -ne $f.Choices) {
            $choices = @()
            foreach ($c in $f.Choices) { $choices += ,@($c.Label, $c.Value) }
        }
        $group = ""
        if ($f.ContainsKey("Group")) { $group = [string]$f.Group }
        $row = [pscustomobject]@{
            Id      = "$ci.$ri"
            name    = [string]$f.Name
            key     = [string]$f.Key
            value   = $f.Value
            type    = [string]$f.Type
            full    = $tip
            short   = $short
            group   = $group
            choices = $choices
        }
        if ($null -eq $choices) { $row.PSObject.Properties.Remove('choices') }
        $rows += $row
        $script:state["$ci.$ri"] = @{ On = $false; Sel = 0 }
        $ri++
    }
    $script:cats += [pscustomobject]@{ name = [string]$cat.Name; rows = $rows }
    $ci++
}

# Preset cards read the embedded presets, so there is no second copy of those
# either. Blurbs are presentation, not data.
$script:presetBlurbs = @{
    "Maximum Privacy Preset"          = "Everything privacy-related, at the cost of convenience."
    "Balanced Privacy Preset"         = "Strong privacy that keeps the conveniences most people want."
    "Performance Focused Preset"      = "Speed and clutter, not privacy extremes."
    "Developer Preset"                = "Telemetry off, dev tools and the network stack untouched."
    "Strict Parental Controls Preset" = "Lockdown: filtered, no incognito, no extensions."
    "Brave Origin Preset"             = "Clones Brave Origin's enforced policy set."
}
$script:presets = @()
foreach ($name in $script:embeddedPresets.Keys) {
    $obj = $script:embeddedPresets[$name] | ConvertFrom-Json
    $count = @($obj.Features.PSObject.Properties).Count
    $blurb = ""
    if ($script:presetBlurbs.ContainsKey($name)) { $blurb = $script:presetBlurbs[$name] }
    $script:presets += [pscustomobject]@{
        name     = ($name -replace ' Preset$', '')
        blurb    = $blurb
        count    = $count
        features = $obj.Features
        dns      = [string]$obj.DnsMode
        tmpl     = [string]$obj.DnsTemplates
    }
}
# Policy engine - registry read/write, DNS, leaked-prefs repair. Same
# semantics as v2.0.x main: scoped Reset, and DNS "secure" requiring a template.


# ===========================================================================
# SLIMBRAVE-NEO-ZH LOCALIZATION RUNTIME (Auto-generated by build_zh.py)
# ===========================================================================
$script:zhData = [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String('eyJjYXRlZ29yaWVzIjp7IlRlbGVtZXRyeSAmIFJlcG9ydGluZyI6IumBpea1i+S4juaKpeWRiiIsIlByaXZhY3kgJiBTZWN1cml0eSI6IumakOengeS4juWuieWFqCIsIlNpdGUgUGVybWlzc2lvbnMiOiLnvZHnq5nmnYPpmZAiLCJBY2Nlc3MgQ29udHJvbHMiOiLorr/pl67mjqfliLYiLCJCcmF2ZSBGZWF0dXJlcyI6IkJyYXZlIOWGhee9ruWKn+iDvSIsIlNoaWVsZHMgJiBDb250ZW50IFByb3RlY3Rpb24iOiLnm77niYzkuI7lhoXlrrnkv53miqQiLCJQZXJmb3JtYW5jZSAmIEJsb2F0Ijoi5oCn6IO95LiO57K+566AIn0sImNob2ljZXMiOnsiTm90IG1hbmFnZWQiOiLkuI3nrqHnkIYiLCJBbGxvdyI6IuWFgeiuuCIsIkFzayI6IuivoumXriIsIkJsb2NrIjoi6Zi75q2iIn0sImRuc19tb2RlcyI6eyJ1bm1hbmFnZWQiOiLkuI3nrqHnkIYiLCJhdXRvbWF0aWMiOiLoh6rliqggKGF1dG8pIiwib2ZmIjoi5YWz6ZetIChvZmYpIiwic2VjdXJlIjoi5a6J5YWoIChzZWN1cmUpIiwiY3VzdG9tIjoi6Ieq5a6a5LmJIChjdXN0b20pIn0sInByZXNldHMiOnsiTWF4aW11bSBQcml2YWN5IFByZXNldCI6eyJuYW1lIjoi5p6B6Ie06ZqQ56eB6aKE6K6+IiwiYmx1cmIiOiLlkK/nlKjlh6DkuY7miYDmnInpmpDnp4HlvLrljJbnrZbnlaXvvIzlj6/og73kvJrnibrnibLpg6jliIbml6XluLjkvr/liKnmgKfjgIIifSwiQmFsYW5jZWQgUHJpdmFjeSBQcmVzZXQiOnsibmFtZSI6IuWdh+ihoemakOengemihOiuviIsImJsdXJiIjoi5by65Yqb6ZqQ56eB5L+d5oqk77yM5ZCM5pe25L+d55WZ5aSn5aSa5pWw5Lq66ZyA6KaB55qE5pel5bi45L6/5Yip5Yqf6IO944CCIn0sIlBlcmZvcm1hbmNlIEZvY3VzZWQgUHJlc2V0Ijp7Im5hbWUiOiLmgKfog73nsr7nroDpooTorr4iLCJibHVyYiI6IuiBmueEpuaPkOmAn+S4juWOu+iHg+iCv++8jOS4jemHh+eUqOaegeerr+makOengemZkOWItuOAgiJ9LCJEZXZlbG9wZXIgUHJlc2V0Ijp7Im5hbWUiOiLlvIDlj5HogIXpooTorr4iLCJibHVyYiI6IuWFs+mXremBpea1i+S4juWGl+S9mee7hOS7tu+8jOS/neeVmeW8gOWPkeiAheW3peWFt+WSjOe9kee7nOiwg+ivleiDveWKm+OAgiJ9LCJTdHJpY3QgUGFyZW50YWwgQ29udHJvbHMgUHJlc2V0Ijp7Im5hbWUiOiLkuKXmoLzlrrbplb/mjqfliLbpooTorr4iLCJibHVyYiI6IumrmOW6pumUgeWumu+8muW8uuWItuWuieWFqOi/h+a7pOOAgeemgeeUqOaXoOeXleaooeW8j+S4juaJgOacieaJqeWxleOAgiJ9LCJCcmF2ZSBPcmlnaW4gUHJlc2V0Ijp7Im5hbWUiOiJCcmF2ZSBPcmlnaW4g6aKE6K6+IiwiYmx1cmIiOiLlpI3liLsgQnJhdmUgT3JpZ2luIOWumOaWueeyvueugOeJiOaJgOW8uuWItuaJp+ihjOeahOetlueVpee7hOWQiOOAgiJ9fSwicG9saWNpZXMiOnsiTWV0cmljc1JlcG9ydGluZ0VuYWJsZWQiOnsibmFtZSI6IuemgeeUqOaMh+agh+S4juW0qea6g+aKpeWRiiIsImRlc2MiOiLpmLvmraIgQnJhdmUg5LiK5Lyg5bSp5rqD5oql5ZGK77ya6ZSB5a6a5YWz6Zet4oCc6Ieq5Yqo5Y+R6YCB6K+K5pat5oql5ZGK4oCd77yM6ZqQ6JeP5bSp5rqD5ZCO55qE5LiK5Lyg5o+Q56S677yM5bm25bGP6JS9IGJyYXZlOi8vY3Jhc2hlcyDkuIrnmoTigJznq4vljbPlj5HpgIHigJ3jgIJCZXRhIOS4jiBOaWdodGx5IOm7mOiupOW8gOWQr++8m1JlbGVhc2Ug6aaW5qyh5qyi6L+O6aG15Lmf5Lya6buY6K6k5Yu+6YCJ44CCUDNBIOS4juS9v+eUqOe7n+iuoSBwaW5nIOeUseWNleeLrOadoeebruaOp+WItuOAgiJ9LCJVcmxLZXllZEFub255bWl6ZWREYXRhQ29sbGVjdGlvbkVuYWJsZWQiOnsibmFtZSI6IuemgeeUqCBVUkwg5Yy/5ZCN5pWw5o2u5pS26ZuGIiwiZGVzYyI6IumUgeWumuWFs+mXreKAnOaUuei/m+aQnOe0ouWSjOa1j+iniOS9k+mqjOKAne+8iOWfuuS6jiBVUkwg55qE5Yy/5ZCN5pWw5o2u5pS26ZuG77yJ44CCQnJhdmUg6buY6K6k5bey5YWz6Zet5q2k6aG577yb5YW25ZSv5LiA5byA5YWz5L2N5LqO6ZqQ6JeP55qE6ZqQ56eB5oyH5Y2X77yIYnJhdmU6Ly9zZXR0aW5ncy9wcml2YWN5L2d1aWRl77yJ77yM6K6+572u5Lu75oSP562W55Wl5ZCO6K+l5YWl5Y+j5Lya6ZqQ6JeP44CC5q2k6aG55Lmf5Lya6KaG55uW5q2k5YmN5Zyo5YW25Lit5byA5ZCv55qE5o6I5p2D44CCIn0sIkFjY2Vzc2liaWxpdHlJbWFnZUxhYmVsc0VuYWJsZWQiOnsibmFtZSI6IuemgeeUqCBHb29nbGUg5Zu+5YOP5o+P6L+wIiwiZGVzYyI6IkJyYXZlIOm7mOiupOW3suWFs+mXrSBHb29nbGUg5Zu+5YOP5o+P6L+w5LiU5LiN5YaN5o+Q5L6b5byA5ZCv5YWl5Y+j44CC5L2G5pen54mI6YWN572u5Lit6Iul5pu+5ZCM5oSP6L+H77yM6L+Q6KGM5bGP5bmV6ZiF6K+75Zmo5pe25LuN5Lya5bCG5peg5qCH562+5Zu+54mH5Y+R6YCB57uZIEdvb2dsZe+8m+WQr+eUqOatpOetlueVpeWPr+W9u+W6leWFs+mXreW5tumUgeWumuOAgiJ9LCJCcmF2ZVAzQUVuYWJsZWQiOnsibmFtZSI6IuemgeeUqCBQM0Eg5Lqn5ZOB5YiG5p6QIiwiZGVzYyI6IuemgeeUqCBQM0HvvIjpmpDnp4Hkv53miqTkuqflk4HliIbmnpDvvInvvIzljbMgQnJhdmUg55qE5Yy/5ZCN5Lqn5ZOB5L2/55So6YGl5rWL5Yqf6IO944CCIn0sIkJyYXZlU3RhdHNQaW5nRW5hYmxlZCI6eyJuYW1lIjoi56aB55So5q+P5pel5rS76LeD57uf6K6hIFBpbmciLCJkZXNjIjoi5YGc5q2i55So5LqO57uf6K6hIEJyYXZlIOa0u+i3g+eUqOaIt+aVsOeahOavj+aXpeS9v+eUqCBQaW5n77yM5Lul5Y+K5YW25Lit6ZmE5bim55qE5pCc57Si5byV5pOO5L2/55So6K6h5pWw5ZKM5o6o5bm/56CB5qOA5p+l44CC6Iul5pyq5ZCM5pe256aB55SoIFAzQSDliIbmnpDvvIxQM0Eg5LuN5Lya5Y2V54us5Y+R6YCB5LiA5Lu95pCc57Si6K6h5pWw44CCIn0sIkNocm9tZVZhcmlhdGlvbnM6MSI6eyJuYW1lIjoi6ZmQ5Yi25LqR56uv5a6e6aqM5LuF6ZmQ5YWz6ZSu5L+u5aSNIiwiZGVzYyI6IuWwhiBCcmF2ZSDov5znqIvphY3nva7np43lrZDvvIhHcmlmZmlu77yJ6ZmQ5Yi25Li65LuF5o6l5pS25YWz6ZSu5L+u5aSN5a6e6aqM77yM6L+Z5Lya5ZCM5pe25YWz6Zet5LuF6Z2g6L+c56iL5LiL5Y+R5ZCv55So55qE54m55oCn77yaV2ViR0wvV2ViR1BVIOaMh+e6ueS8quijheOAgeWbvueJh+WFg+aVsOaNruWJpeemu++8iOS4pOiAheWPr+WcqCBicmF2ZTovL2ZsYWdzIOaJi+WKqOaBouWkje+8ieS7peWPiiBHb29nbGUg55m75b2V5L+u5aSN44CC6YeN5ZCv5ZCO55Sf5pWI44CC5LiO4oCc5a6M5YWo56aB55So5LqR56uv5a6e6aqM4oCd5LqS5pal44CCIn0sIkNocm9tZVZhcmlhdGlvbnM6MiI6eyJuYW1lIjoi5a6M5YWo56aB55So5LqR56uv5a6e6aqMIC8gR3JpZmZpbiIsImRlc2MiOiLmi5Lnu53miYDmnIkgR3JpZmZpbiDkupHnq6/lrp7pqozvvIjlkKvlhbPplK7kv67lpI3vvInvvIzku4XpnaDov5znqIvnp43lrZDlkK/nlKjnmoTnibnmgKflsIbkv53mjIHlhbPpl63vvJpXZWJHTC9XZWJHUFUg5oyH57q55Lyq6KOF44CB5Zu+54mH5YWD5pWw5o2u5Yml56a75Y+KIEdvb2dsZSDnmbvlvZXkv67lpI3jgILnp43lrZDmlofku7bmnKzouqvku43kvJrkuIvovb3jgILph43lkK/lkI7nlJ/mlYjjgILkuI7igJzpmZDliLbkupHnq6/lrp7pqozku4XpmZDlhbPplK7kv67lpI3igJ3kupLmlqXjgIIifSwiU3BlbGxDaGVja1NlcnZpY2VFbmFibGVkIjp7Im5hbWUiOiLnpoHnlKjlop7lvLrlnovlnKjnur/mi7zlhpnmo4Dmn6UiLCJkZXNjIjoi6ZSB5a6a5YWz6Zet5Lya5bCG6KGo5Y2V6L6T5YWl5Y+R6YCB5YiwIEdvb2dsZSDnmoTlop7lvLrlnovmi7zlhpnmo4Dmn6XjgIJCcmF2ZSDpu5jorqTlt7LlhbPpl63kuJTml6DnlYzpnaLlvIDlhbPvvJvmnKzlnLDnprvnur/mi7zlhpnmo4Dmn6Xku43lj6/mraPluLjkvb/nlKjjgILkuI7igJznpoHnlKjmi7zlhpnmo4Dmn6XigJ3kupLmlqXvvIjlkI7ogIXkvJrlrozlhajlhbPpl63mi7zlhpnmo4Dmn6Xlubbkvb/mnKzpobnml6DmlYjvvInjgIIifSwiU2FmZUJyb3dzaW5nUHJvdGVjdGlvbkxldmVsOjAiOnsibmFtZSI6IuemgeeUqOWuieWFqOa1j+iniO+8iOmZjeS9juWuieWFqOaAp++8iSIsImRlc2MiOiLlrozlhajlhbPpl63lronlhajmtY/op4jjgIJCcmF2ZSDkvJrpgJrov4foh6rmnInmnI3liqHlmajku6PnkIbmn6Xor6LvvIxHb29nbGUg5Y6f5pys5Lmf5peg5rOV5b6X55+l6K+35rGC5p2l5rqQ77yb5YWz6Zet5a6D5Yeg5LmO5LiN5aKe5Yqg6ZqQ56eB77yM5Y205Lya5aSx5Y676ZKT6bG85LiO5oG25oSP6L2v5Lu26K2m5ZGK6aG16Z2i44CC5omA5pyJ6aKE6K6+5Z2H5LiN5YyF5ZCr5q2k6aG544CC5LiO4oCc6ZSB5a6a5byA5ZCv5a6J5YWo5rWP6KeI4oCd5LqS5pal44CCIn0sIkF1dG9maWxsQWRkcmVzc0VuYWJsZWQiOnsibmFtZSI6IuemgeeUqOWcsOWdgOiHquWKqOWhq+WFhSIsImRlc2MiOiLpmLvmraIgQnJhdmUg5Zyo572R6aG16KGo5Y2V5Lit5L+d5a2Y5ZKM6Ieq5Yqo5aGr5YWF5Zyw5Z2A5Y+K5YW25LuW6IGU57O75L+h5oGv44CCQ2hyb21pdW0g5bey5byD55So5q2k562W55Wl77yIYnJhdmU6Ly9wb2xpY3kg5Lya5qCH5rOo5Li6IERlcHJlY2F0ZWTvvInvvIzkvYYgQnJhdmUg55uu5YmN5LuN5Lya5omn6KGM77yb5YW25pu/5Luj562W55WlIEF1dG9maWxsU2V0dGluZ3Mg5bCa5pyq5ZyoIEJyYXZlIOS4reeUn+aViOOAgiJ9LCJBdXRvZmlsbENyZWRpdENhcmRFbmFibGVkIjp7Im5hbWUiOiLnpoHnlKjkv6HnlKjljaHoh6rliqjloavlhYUiLCJkZXNjIjoi6Zi75q2iIEJyYXZlIOWcqOe9kemhteihqOWNleS4reS/neWtmOWSjOiHquWKqOWhq+WFheS/oeeUqOWNoeWPt+OAgkNocm9taXVtIOW3suW8g+eUqOatpOetlueVpe+8iGJyYXZlOi8vcG9saWN5IOS8muagh+azqOS4uiBEZXByZWNhdGVk77yJ77yM5L2GIEJyYXZlIOebruWJjeS7jeS8muaJp+ihjO+8m+WFtuabv+S7o+etlueVpSBBdXRvZmlsbFNldHRpbmdzIOWwmuacquWcqCBCcmF2ZSDkuK3nlJ/mlYjjgIIifSwiUGFzc3dvcmRNYW5hZ2VyRW5hYmxlZCI6eyJuYW1lIjoi56aB55So5YaF572u5a+G56CB566h55CG5ZmoIiwiZGVzYyI6IuWBnOatouWGhee9ruWvhueggeeuoeeQhuWZqOaPkOekuuS/neWtmOaIlueUn+aIkOWvhueggeOAguatpOWJjeW3suS/neWtmOeahOWvhueggeS7jeWPr+iHquWKqOWhq+WFheOAguWmguaenOS9oOS9v+eUqOeLrOeri+eahOesrOS4ieaWueWvhueggeeuoeeQhuWZqO+8jOW7uuiuruW8gOWQr+atpOmhueOAgiJ9LCJQYXNzd29yZExlYWtEZXRlY3Rpb25FbmFibGVkIjp7Im5hbWUiOiLnpoHnlKjlr4bnoIHms4TpnLLmo4DmtYsiLCJkZXNjIjoi6ZSB5a6a5YWz6Zet55m75b2V572R56uZ5oiW57yW6L6R5bey5L+d5a2Y5a+G56CB5pe26Kem5Y+R55qE5Zyo57q/5rOE6Zyy5bqT5q+U5a+55qOA5p+l44CCQnJhdmUg6buY6K6k5bey5YWz6Zet77yM5q2k562W55Wl55So5LqO6ZSB5a6a5L+d5oyB5YWz6Zet44CCIn0sIkJyb3dzZXJTaWduaW4iOnsibmFtZSI6IuemgeeUqOa1j+iniOWZqCBHb29nbGUg55m75b2VIiwiZGVzYyI6IkJyYXZlIOacrOi6q+S4jeWQqyBHb29nbGUg5rWP6KeI5Zmo6LSm5Y+355m75b2V77yb5q2k562W55Wl55So5LqO6ZSB5a6a5YWz6Zet4oCc5YWB6K645omp5bGV5L2/55SoIEdvb2dsZSDnmbvlvZXigJ3vvIhicmF2ZTovL3NldHRpbmdzL2V4dGVuc2lvbnPvvInvvIzkuI4gQnJhdmUg6buY6K6k5LiA6Ie044CC5omp5bGV5LuN5Y+v6YCa6L+HIGNocm9tZS5pZGVudGl0eSDmiZPlvIAgR29vZ2xlIOeZu+W9leW8ueeql+OAguS4jeW9seWTjSBCcmF2ZSDotKblj7fjgILph43lkK/lkI7nlJ/mlYjjgIIifSwiQnJhdmVHbG9iYWxQcml2YWN5Q29udHJvbEVuYWJsZWQiOnsibmFtZSI6IuWQr+eUqOWFqOeQg+makOengeaOp+WItiAoR1BDKSIsImRlc2MiOiJCcmF2ZSDpu5jorqTlnKjmr4/mrKHor7fmsYLkuK3lj5HpgIEgR1BDIOS/oeWPt++8iOimgeaxgue9keermeS4jeimgeWHuuWUruaIluWFseS6q+S9oOeahOaVsOaNru+8ieS4lOaXoOaJi+WKqOW8gOWFs++8m+atpOetlueVpeWPr+ehruS/neWNs+S9v+WcqOKAnOS7heaLpuaIquW5v+WRiuaooeW8j+KAne+8iOS7heiLseaWh+eVjOmdouaPkOS+m++8ieS4i+S7jeS/neaMgeW8gOWQr++8jOS4lOWcqOWFs+mXreebvueJjOeahOe9keermeS4iuS+neeEtueUn+aViOOAgiJ9LCJCcmF2ZURlQW1wRW5hYmxlZCI6eyJuYW1lIjoi5ZCv55SoIERlLUFNUO+8iOi3s+i/hyBBTVAg6aG16Z2i77yJIiwiZGVzYyI6IuS/neaMgSBEZS1BTVAg5byA5ZCv77ya6Ieq5Yqo6Lez6L+HIEdvb2dsZSBBTVAg5Luj55CG6aG15bm255u06L6+5Y+R5biD6ICF5Y6f572R6aG144CCQnJhdmUg6buY6K6k5byA5ZCv77yb5q2k562W55Wl6ZSB5a6a6K6+572u5byA5YWz77yM5bm26Ziy5q2i4oCc5LuF5oum5oiq5bm/5ZGK5qih5byP4oCd5bCG5YW25YWz6Zet44CCIn0sIkJyYXZlRGVib3VuY2luZ0VuYWJsZWQiOnsibmFtZSI6IuWQr+eUqOmYsui3s+mTvumHjeWumuWQkSAoRGVib3VuY2luZykiLCJkZXNjIjoi5L+d5oyB6Ziy6Lez6ZO+5byA5ZCv77ya6Ieq5Yqo6Lez6L+H5bey55+l55qE6L+96Liq5Lit6L2s6Lez6L2s77yM55u05o6l6K6/6Zeu5pyA57uI55uu5qCHIFVSTOOAgkJyYXZlIOm7mOiupOW8gOWQr++8m+atpOetlueVpemUgeWumuiuvue9ruW8gOWFs++8jOW5tumYsuatouKAnOS7heaLpuaIquW5v+WRiuaooeW8j+KAneWwhuWFtuWFs+mXreOAgiJ9LCJCcmF2ZVRyYWNraW5nUXVlcnlQYXJhbWV0ZXJzRmlsdGVyaW5nRW5hYmxlZCI6eyJuYW1lIjoi5Yml56a7572R5Z2A6L+96Liq5Y+C5pWwIiwiZGVzYyI6IkJyYXZlIOm7mOiupOiHquWKqOenu+mZpCBVUkwg5Lit55qE5bey55+l6L+96Liq5Y+C5pWw77yI5aaCIGZiY2xpZOOAgWdjbGlk44CBbWNfZWlkIOetie+8ieS4lOaXoOaJi+WKqOW8gOWFs++8m+atpOetlueVpeWPr+ehruS/neWNs+S9v+W8gOWQr+KAnOS7heaLpuaIquW5v+WRiuaooeW8j+KAneS5n+S/neaMgeWJpeemu+OAgumcgOS/neaMgeebvueJjOW8gOWQr+OAgiJ9LCJCcmF2ZVJlZHVjZUxhbmd1YWdlRW5hYmxlZCI6eyJuYW1lIjoi5YeP5bCR6K+t6KiA5oyH57q55pq06ZyyIiwiZGVzYyI6IkJyYXZlIOm7mOiupOW8gOWQr++8jOatpOetlueVpeeUqOS6jumUgeWumuW8gOWFs+OAguS7heWcqCBBY2NlcHQtTGFuZ3VhZ2Ug6K+35rGC5aS05Lit5ZCR572R56uZ5Y+R6YCB5L2g55qE6aaW6YCJ6K+t6KiA77yM5bm25ZyoIFdpbmRvd3PjgIFtYWNPUyDlj4rpg6jliIYgTGludXgg5Y+R6KGM54mI5LiK5LuF5pq06Zyy5qCH5YeG5a2X5L2T5YiX6KGo44CC6ZyA5byA5ZCv55u+54mM5LiO5oyH57q55L+d5oqk44CCIn0sIldlYlJ0Y0lQSGFuZGxpbmciOnsibmFtZSI6IumYsuatoiBXZWJSVEMg5rOE6Zyy55yf5a6eIElQIiwiZGVzYyI6IuWwhiBXZWJSVEMg6ZmQ5Yi25Li65LuF5L2/55So5Luj55CG6L+e5o6l77yM6Ziy5q2i6Z+z6KeG6aKR6YCa6K+d5Zyo5byA5ZCvIFZQTiDmiJbku6PnkIbml7bmmrTpnLLkvaDnmoTnnJ/lrp4gSVAg5Zyw5Z2A44CCIn0sIlF1aWNBbGxvd2VkIjp7Im5hbWUiOiLnpoHnlKggUVVJQyAoSFRUUC8zKSDljY/orq4iLCJkZXNjIjoi56aB55So572R6aG16K+35rGC55qEIFFVSUPvvIhIVFRQLzPvvInvvIzlvLrliLblm57pgIDoh7MgVENQ77yISFRUUC8yIOaIliBIVFRQLzEuMe+8ieOAgumAgueUqOS6juaXoOazleWuoeiuoSBRVUlDIOa1gemHj+eahOmYsueBq+WimeaIlui/h+a7pOeOr+Wig++8m+WPr+iDveeVpeW+rumZjeS9jumDqOWIhiBHb29nbGUg56uZ54K55Yqg6L296YCf5bqm44CCV2ViUlRDIOmAmuivneWSjCBXZWJUcmFuc3BvcnQg5LuN5L2/55SoIFVEUOOAgiJ9LCJOZXR3b3JrUHJlZGljdGlvbk9wdGlvbnMiOnsibmFtZSI6IuemgeeUqOe9kee7nOmihOWKoOi9ve+8iOmihOWPlu+8iSIsImRlc2MiOiLpmLvmraIgQnJhdmUg5qC55o2u572R56uZ55qE5o6o5rWL6KeE5YiZ5oiW6aKE5riy5p+T5o+Q56S65o+Q5YmN5Yqg6L29572R6aG177yM5bm25YGc5q2i6aKE6L+e5o6l5pCc57Si5byV5pOO44CCQnJhdmUg6buY6K6k5bey6YeH55So5q2k6KGM5Li677yb5q2k562W55Wl55So5LqO6ZSB5a6a77yM6Ziy5q2i6KKr5ZCM5q2l5oiW5omp5bGV5pS55Zue44CCIn0sIkJsb2NrVGhpcmRQYXJ0eUNvb2tpZXMiOnsibmFtZSI6IumYu+atouesrOS4ieaWuSBDb29raWUiLCJkZXNjIjoiQnJhdmUg6buY6K6k6Zi75q2i56ys5LiJ5pa5IENvb2tpZe+8m+atpOetlueVpeWwhuWFtumUgeWumu+8jOmYsuatouWcqOebvueJjOWFqOWxgOiuvue9ruS4reWIh+WbnuKAnOWFgeiuuOaJgOaciSBDb29raWXigJ3miJbooqvmianlsZXjgIHlkIzmraXlj4rigJzku4Xmi6bmiKrlub/lkYrmqKHlvI/igJ3lhbPpl63jgILpkojlr7nljZXkuKrnvZHnq5nnmoTnm77niYzkvovlpJbvvIjlpoLkv67lpI3ltYzlhaXnmbvlvZXvvInkvp3nhLbmnInmlYjjgIIifSwiUGF5bWVudE1ldGhvZFF1ZXJ5RW5hYmxlZCI6eyJuYW1lIjoi6Zi75q2i572R56uZ5o6i5rWL5pSv5LuY5pa55byPIiwiZGVzYyI6IumYsuatoue9keermeaOouefpeS9oOaYr+WQpuS/neWtmOS6huaUr+S7mOaWueW8j++8muS9vyBjYW5NYWtlUGF5bWVudCgpIOaBkui/lOWbniB5ZXPjgIFoYXNFbnJvbGxlZEluc3RydW1lbnQoKSDmgZLov5Tlm54gbm/vvIzku47ogIzkuI3ms4TpnLLku7vkvZXnnJ/lrp7nirbmgIHjgIIifSwiUmVtb3RlRGVidWdnaW5nQWxsb3dlZCI6eyJuYW1lIjoi56aB5q2i6L+c56iL6LCD6K+V5o6l5Y+jIiwiZGVzYyI6IuWxj+iUvei/nOeoi+iwg+ivleerr+WPo+S4jueuoemBk++8jOmYsuatouiHquWKqOWMluW3peWFt+aTjeaOp+a1j+iniOWZqOW5tuivu+WPluS9oOeahCBDb29raWUg5LiO55m75b2V5Lya6K+d44CC4oCc56aB55So5byA5Y+R6ICF5bel5YW34oCd5LiN5YyF5ZCr5q2k6aG544CC5Lya5a+86Ie0IFB1cHBldGVlcuOAgVBsYXl3cmlnaHQg5Y+KIGJyYXZlOi8vaW5zcGVjdCDov5znqIvosIPor5XlvIDlhbPkuI3lj6/nlKjjgILml6DpnIDph43lkK/ljbPnlJ/mlYjjgIIifSwiQmFzaWNBdXRoT3Zlckh0dHBFbmFibGVkIjp7Im5hbWUiOiLln7rnoYDorqTor4EgKEJhc2ljIEF1dGgpIOW8uuWItuS9v+eUqCBIVFRQUyIsImRlc2MiOiLmi5Lnu53lnKjmmI7mlocgSFRUUCDov57mjqXkuIrkvb/nlKggSFRUUCBCYXNpYyDorqTor4HvvIznoa7kv53otKblj7flr4bnoIHkuI3kvJrku6XmmI7mlofkvKDovpPjgILkvJrlr7zoh7Tku4XmlK/mjIEgSFRUUCDnmoTogIHml6fot6/nlLHlmajjgIHmiZPljbDmnLrlkI7lj7Dlj4rmmI7mlocgSFRUUCDku6PnkIborqTor4Hml6Dms5XnmbvlvZXjgIIifSwiTG9jYWxOZXR3b3JrQWNjZXNzQmxvY2tlZEZvclVybHMiOnsibmFtZSI6IumYu+atouWFrOe9keiuv+mXruacrOWcsOWxgOWfn+e9kSIsImRlc2MiOiLnpoHmraLlhaznvZHnvZHnq5norr/pl67kvaDlsYDln5/nvZHkuK3nmoTorr7lpIfvvIjot6/nlLHlmajjgIFOQVPjgIHmiZPljbDmnLrjgIHmmbrog73lrrblsYXkuK3mnqLvvInmiJbmnKzmnLrmnI3liqHvvIzkuJTkuI3lvLnnqpfjgIHkuI3lhYHorrjljZXnq5nkvovlpJbvvIjpu5jorqTmg4XlhrXkuIsgQnJhdmUg5Lya6K+i6Zeu77yJ44CC55u05o6l5LuO5bGA5Z+f572R5Zyw5Z2A5omT5byA55qE6aG16Z2i5LiN5Y+X5b2x5ZON44CC5Lya5b2x5ZON6ZyA6YWN5a+55pys5Zyw6K6+5aSH5oiW5Yqp5omL56iL5bqP55qE572R6aG15bqU55So44CCIn0sIlhTTFRFbmFibGVkIjp7Im5hbWUiOiLnpoHnlKggWFNMVCDlvJXmk44iLCJkZXNjIjoi5YWz6Zet5pen54mIIFhNTCDovazmjaLlvJXmk44gWFNMVO+8iFhTTFRQcm9jZXNzb3Ig5LiOIHhtbC1zdHlsZXNoZWV077yJ77yM6L+Z5pivIENocm9taXVtIOato+WcqOenu+mZpOeahOaUu+WHu+mdou+8m+WNs+S9v+e9keermeS4u+WKqOeUs+ivt+WQr+eUqOS5n+S8muS/neaMgeWFs+mXreOAguS+nei1liBYU0xUIOagt+W8j+eahCBYTUzvvIjlpoLpg6jliIYgUlNTIOa6kOWSjOermeeCueWcsOWbvu+8ieWwhuaYvuekuuS4uuaXoOagt+W8j+OAgumHjeWQr+WQjuWujOWFqOeUn+aViOOAgiJ9LCJEZWZhdWx0SmF2YVNjcmlwdE9wdGltaXplclNldHRpbmciOnsibmFtZSI6IuemgeeUqCBKYXZhU2NyaXB0IEpJVCDkvJjljJbvvIjlronlhajliqDlm7rvvIkiLCJkZXNjIjoi5Zyo572R6aG15LiK5YWz6ZetIFY4IOS8mOWMlue8luivkeWZqO+8iFR1cmJvRmFu44CBTWFnbGV277yJ77yMQnJhdmUg6KGo56S66L+Z6IO95pi+6JGX5o+Q6auY5oqX5pS75Ye76IO95Yqb44CC572R56uZ5LiOIFdlYkFzc2VtYmx5IOS7jeWPr+i/kOihjO+8jOS9humHjeiEmuacrOmhtemdouWSjCBXZWIg5bqU55So5Lya5Y+Y5oWi77yM5LiU5LiN5pSv5oyB5Y2V56uZ5L6L5aSW44CC5a+55L+u5pS55ZCO5paw5omT5byA55qE5qCH562+6aG155Sf5pWI44CCIn0sIkV4dGVybmFsUHJvdG9jb2xEaWFsb2dTaG93QWx3YXlzT3BlbkNoZWNrYm94Ijp7Im5hbWUiOiLnp7vpmaTlpJbpg6jlupTnlKjlkK/liqjmj5DnpLrnmoTigJzlp4vnu4jlhYHorrjigJ0iLCJkZXNjIjoi5LuO572R56uZ5ZSk6LW35aSW6YOo5bqU55So5YmN55qE56Gu6K6k5by556qX5Lit56e76Zmk4oCc5aeL57uI5YWB6K644oCd5aSN6YCJ5qGG77yM5L2/5q+P5qyh6Lez6L2s77yI5aaCIG1haWx0bzrjgIFab29t44CBVGVhbXPjgIFTdGVhbeOAgW1zLSog6ZO+5o6l77yJ6YO96ZyA5omL5Yqo54K55Ye756Gu6K6k44CC5q2k5YmN5bey6K6+5Li65aeL57uI5omT5byA55qE5bqU55So5LiN5Y+X5b2x5ZON44CCIn0sIlNpdGVQZXJQcm9jZXNzIjp7Im5hbWUiOiLlvLrliLbkuLrmr4/kuKrnvZHnq5nlkK/nlKjnq5nngrnpmpTnprsiLCJkZXNjIjoi56Gu5L+d5q+P5Liq572R56uZ6L+Q6KGM5Zyo54us56uL6L+b56iL5Lit77yIQnJhdmUg5qGM6Z2i54mI6buY6K6k5aaC5q2k77yJ77yM5bm26Zi75q2i6YCa6L+HIGJyYXZlOi8vZmxhZ3Mjc2l0ZS1pc29sYXRpb24tdHJpYWwtb3B0LW91dCDmiJYgLS1kaXNhYmxlLXNpdGUtaXNvbGF0aW9uLXRyaWFscyDlsIblhbblhbPpl63jgILph43lkK/lkI7nlJ/mlYjjgIIifSwiT3JpZ2luS2V5ZWRQcm9jZXNzZXNFbmFibGVkIjp7Im5hbWUiOiLkuLrkuI3lkIzlrZDln5/lkI3lkK/nlKjni6znq4vov5vnqIvpmpTnprsiLCJkZXNjIjoi5bCG5q+P5Liq5rqQ77yI5L6L5aaCIG1haWwuZXhhbXBsZS5jb20g5LiOIGRvY3MuZXhhbXBsZS5jb23vvInpmpTnprvlnKjlkIToh6rov5vnqIvkuK3vvIzogIzpnZ7mjInkuLvln5/lkI3lhbHkuqvvvIzku6Xmm7TlvLrlipvlnLDpmLLlvqHlrZDln5/lkI3pl7TnmoQgU3BlY3RyZSDnsbvkvqfkv6HpgZPms4TpnLLjgILkvJrlop7liqDov5vnqIvmlbDkuI7lhoXlrZjljaDnlKjjgILph43lkK/lkI7nlJ/mlYjvvIzkvYblj6/ooqsgYnJhdmU6Ly9mbGFncyDopobnm5bjgIIifSwiRHluYW1pY0NvZGVTZXR0aW5ncyI6eyJuYW1lIjoi6Zi75q2i5rWP6KeI5Zmo5Li76L+b56iL55Sf5oiQ5Yqo5oCB5Luj56CBIChBQ0cpIiwiZGVzYyI6IuemgeatoiBCcmF2ZSDkuLvov5vnqIvliJvlu7rmiJbkv67mlLnlj6/miafooYzlhoXlrZjvvIjku7vmhI/ku6PnoIHpmLLmiqQgQUNH77yJ77yM5Y+v5pyJ5pWI6Zi75pat6L+b56iL5rOo5YWl55qEIFNoZWxsY29kZSDkuI7ku6PnoIHmjILpkqnjgILpg6jliIblkJHmtY/op4jlmajms6jlhaUgRExMIOeahOadgOavkui9r+S7tuOAgeaJk+WNsOacuumpseWKqOaIlui+k+WFpeazleWPr+iDveW8guW4uOaIluWvvOiHtOW0qea6g++8jOWmgumBh+mXrumimOivt+WPlua2iOWLvumAieOAgiJ9LCJEZWZhdWx0Tm90aWZpY2F0aW9uc1NldHRpbmciOnsibmFtZSI6Iue9kemhteahjOmdoumAmuefpSIsImRlc2MiOiLorr7nva7nvZHnq5nmoYzpnaLpgJrnn6XnmoTpu5jorqTnrZbnlaXjgILigJzpmLvmraLigJ3kvJrnpoHmraLmiYDmnInnvZHnq5nor7fmsYLmiJblvLnlh7rpgJrnn6XvvJvigJzlhYHorrjigJ3liJnlhajpg6jmlL7ooYzvvIzkuozogIXlnYfkvJropobnm5bkvaDnmoTljZXnq5norr7nva7jgILigJzkuI3nrqHnkIbigJ3kv53nlZkgQnJhdmUg6buY6K6k6K+i6Zeu77yI5omY566h562W55Wl5LiL55qE4oCc6K+i6Zeu4oCd5Lya5a+86Ie05Lu75L2V6YCa55+l6YO95peg5rOV6YCB6L6+77yJ44CCIn0sIkRlZmF1bHRHZW9sb2NhdGlvblNldHRpbmciOnsibmFtZSI6IuWcsOeQhuS9jee9ruadg+mZkCIsImRlc2MiOiLorr7nva7nvZHnq5nor7vlj5bniannkIbkvY3nva7nmoTpu5jorqTnrZbnlaXjgILigJzpmLvmraLigJ3kvJrnm7TmjqXpmpDol4/mj5DnpLrvvIjlnLDlm77kuI7lpJbljZbnvZHnq5npnIDmiYvliqjovpPlhaXlnLDlnYDvvInvvJvigJzor6Lpl67igJ3mr4/mrKHpg73kvJrlvLnnqpfkuJTkuI3orrDkvY/pgInmi6njgILku7vmhI/pnZ7igJzkuI3nrqHnkIbigJ3pgInpobnpg73kvJropobnm5bljZXnq5norr7nva7jgIIifSwiRGVmYXVsdFNlbnNvcnNTZXR0aW5nIjp7Im5hbWUiOiLov5DliqjkuI7mlrnlkJHkvKDmhJ/lmagiLCJkZXNjIjoi6L+Q5Yqo5LiO5pa55ZCR5Lyg5oSf5Zmo5bi46KKr55So5LqO6K6+5aSH5oyH57q56L+96Liq77yMQnJhdmUg6buY6K6k5bey6Zi75q2i44CC4oCc6Zi75q2i4oCd5Lya6ZSB5a6a6K+l6KGM5Li677yM6K6+572u6aG15LiO5bey5pyJ5Y2V56uZ5L6L5aSW6YO95peg5rOV5pS+6KGM77yb6YCJ5oup4oCc6K+i6Zeu4oCd5oiW4oCc5YWB6K644oCd5YiZ5Lya5pS+5a696buY6K6k5L+d5oqk44CCIn0sIkRlZmF1bHRXZWJVc2JHdWFyZFNldHRpbmciOnsibmFtZSI6IldlYlVTQiDorr7lpIforr/pl64iLCJkZXNjIjoi6K6+572u572R56uZ6K6/6ZeuIFVTQiDorr7lpIfnmoTpu5jorqTnrZbnlaXjgILigJzpmLvmraLigJ3kvJrnp7vpmaTmj5DnpLrvvIzlr7zoh7TnvZHpobXniYjnoazku7bpkrHljIXvvIhMZWRnZXLjgIFUcmV6b3LvvInlkozlnKjnur/lm7rku7bliLflhpnlt6XlhbfkuI3lj6/nlKjvvJvigJzor6Lpl67igJ3kv53nlZnlvLnnqpfjgIJDaHJvbWl1bSDmraTpobnkuI3mj5DkvpvigJzlhYHorrjigJ3jgIIifSwiRGVmYXVsdFNlcmlhbEd1YXJkU2V0dGluZyI6eyJuYW1lIjoiV2ViIFNlcmlhbCDkuLLlj6Porr/pl64iLCJkZXNjIjoi6K6+572u572R56uZ5omT5byA5Liy5Y+j55qE6buY6K6k562W55Wl44CC4oCc6Zi75q2i4oCd5Lya56e76Zmk5o+Q56S677yM5a+86Ie0572R6aG156uv5Y2V54mH5py654On5b2V5LiO56Gs5Lu26LCD6K+V5bel5YW35LiN5Y+v55So77yb4oCc6K+i6Zeu4oCd5L+d55WZ5by556qX44CCQ2hyb21pdW0g5q2k6aG55LiN5o+Q5L6b4oCc5YWB6K644oCd44CCIn0sIkRlZmF1bHRXZWJIaWRHdWFyZFNldHRpbmciOnsibmFtZSI6IldlYkhJRCDkurrmnLrmjqXlj6Porr7lpIforr/pl64iLCJkZXNjIjoi6K6+572u572R56uZ6K6/6ZeuIEhJRCDorr7lpIfnmoTpu5jorqTnrZbnlaXjgILigJzpmLvmraLigJ3kvJrnp7vpmaTmj5DnpLrvvIzmlq3lvIAgQnJhdmUg6ZKx5YyF5a+5IExlZGdlciDnoazku7bpkrHljIXnmoTov57mjqXvvIzlubblj6/og73lvbHlk43kvp3otZYgV2ViSElE77yI6Z2eIFdlYkF1dGhu77yJ55qE5a6J5YWo5a+G6ZKl5LiO5omL5p+E6YWN572u5bel5YW344CCQ2hyb21pdW0g5q2k6aG55LiN5o+Q5L6b4oCc5YWB6K644oCd44CCIn0sIkRlZmF1bHRMb2NhbEZvbnRzU2V0dGluZyI6eyJuYW1lIjoi5pys5Zyw5a2X5L2T5p6a5Li+5p2D6ZmQIiwiZGVzYyI6Iuiuvue9rue9keermeafpeivouacrOacuuW3suWuieijheWtl+S9k+WIl+ihqOeahOm7mOiupOetlueVpeKAlOKAlOi/meaYr+ebvueJjOWtl+S9k+S/neaKpOacquiDveimhueblueahOW8uuaMh+e6ueeJueW+geOAgumZpOWcqOe6v+iuvuiuoeW3peWFt+Wklu+8jOKAnOmYu+atouKAneW+iOWwkeW9seWTjeato+W4uOa1j+iniOOAgkNocm9taXVtIOatpOmhueS4jeaPkOS+m+KAnOWFgeiuuOKAneOAgiJ9LCJEZWZhdWx0V2luZG93TWFuYWdlbWVudFNldHRpbmciOnsibmFtZSI6IuWkmuWxj+W5leeql+WPo+euoeeQhuadg+mZkCIsImRlc2MiOiLorr7nva7nvZHnq5nor7vlj5blpJrmmL7npLrlmajluIPlsYDlj4rlnKjmjIflrprlsY/luZXmlL7nva7nqpflj6PnmoTpu5jorqTnrZbnlaXjgILigJzpmLvmraLigJ3kvJrlvbHlk43pg6jliIbnvZHpobXlupTnlKjnmoTlhajlsY/mvJTnpLrmqKHlvI/jgIJDaHJvbWl1bSDmraTpobnkuI3mj5DkvpvigJzlhYHorrjigJ3jgIIifSwiRGVmYXVsdENsaXBib2FyZFNldHRpbmciOnsibmFtZSI6IuWJqui0tOadv+ivu+WPluadg+mZkCIsImRlc2MiOiLorr7nva7nvZHnq5nlnKjkvaDmnKrmiafooYznspjotLTml7bkuLvliqjor7vlj5bliarotLTmnb/nmoTpu5jorqTnrZbnlaXjgILigJzpmLvmraLigJ3kvJrnp7vpmaTmj5DnpLrlubbkvb/nvZHpobXlhoXnva7igJznspjotLTigJ3mjInpkq7lpLHmlYjvvJvigJzor6Lpl67igJ3kv53nlZnlvLnnqpfjgILkuozogIXlnYfopobnm5bml6LmnInljZXnq5nlhYHorrjjgIJDdHJsK1Yg5LiO5aSN5Yi25oyJ6ZKu5LuN5q2j5bi444CCQ2hyb21pdW0g5q2k6aG55LiN5o+Q5L6b4oCc5YWB6K644oCd44CCIn0sIkF1ZGlvQ2FwdHVyZUFsbG93ZWQiOnsibmFtZSI6IuWFqOWxgOemgeatoum6puWFi+mjjuiuv+mXriIsImRlc2MiOiLnpoHmraLmiYDmnInnvZHnq5nlkozmianlsZXkvb/nlKjpuqblhYvpo47miJbku7vkvZXpn7PpopHovpPlhaXorr7lpIfkuJTkuI3lvLnnqpfvvIzlt7Lorr7nva7nmoTljZXnq5nigJzlhYHorrjigJ3kuZ/kvJrlpLHmlYjjgILkvJrlr7zoh7TnvZHpobXkvJrorq7vvIhNZWV044CBWm9vbeOAgVRlYW1z44CBRGlzY29yZOOAgUJyYXZlIFRhbGvvvInjgIHor63pn7Pmtojmga/lkozor63pn7PlkKzlhpnkuI3lj6/nlKjjgIIifSwiVmlkZW9DYXB0dXJlQWxsb3dlZCI6eyJuYW1lIjoi5YWo5bGA56aB5q2i5pGE5YOP5aS06K6/6ZeuIiwiZGVzYyI6IuemgeatouaJgOaciee9keermeWSjOaJqeWxleS9v+eUqOaRhOWDj+WktOaIluS7u+S9leinhumikei+k+WFpeiuvuWkh+S4lOS4jeW8ueeql++8jOW3suiuvue9rueahOWNleermeKAnOWFgeiuuOKAneS5n+S8muWkseaViOOAguS8muWvvOiHtOe9kemhteinhumikemAmuivneOAgeaRhOWDj+WktOS6uuiEuOaguOmqjOWPiue9kemhteS6jOe7tOeggeaJq+aPj+S4jeWPr+eUqOOAgiJ9LCJGb3JjZUdvb2dsZVNhZmVTZWFyY2giOnsibmFtZSI6IuW8uuWItuW8gOWQryBHb29nbGUg5a6J5YWo5pCc57SiIiwiZGVzYyI6IuS4uuaJgOaciSBHb29nbGUg5pCc57Si5by65Yi25ZCv55So5a6J5YWo5pCc57Si6L+H5ruk77yM5Li76KaB55So5LqO5a626ZW/5o6n5Yi25Zy65pmv44CCIn0sIkZvcmNlWW91VHViZVJlc3RyaWN0Ijp7Im5hbWUiOiLlvLrliLblvIDlkK8gWW91VHViZSDkuKXmoLzlj5fpmZDmqKHlvI8iLCJkZXNjIjoi5ZyoIHlvdXR1YmUuY29tIOWPiuWFtuWbveWutuWfn+WQje+8iOWQq+WFtuS7lue9keermeW1jOWFpeeahOinhumike+8ieS4iuW8uuWItuW8gOWQr+S4peagvOWPl+mZkOaooeW8j++8jOeUqOaIt+aXoOazleWFs+mXreOAguWkp+mHj+inhumikeWwhuS4jeWPr+aSreaUvuS4lOivhOiuuuWMuuS8muiiq+makOiXj+OAgumAmui/hyB5b3V0dWJlLW5vY29va2llLmNvbSDltYzlhaXnmoTop4bpopHkuI3lj5fpmZDliLbjgIIifSwiU2FmZUJyb3dzaW5nUHJvdGVjdGlvbkxldmVsOjEiOnsibmFtZSI6IumUgeWumuW8gOWQr+WuieWFqOa1j+iniO+8iOagh+WHhuS/neaKpO+8iSIsImRlc2MiOiLlsIblronlhajmtY/op4jplIHlrprkuLrigJzmoIflh4bkv53miqTigJ3vvIznpoHmraLlnKggYnJhdmU6Ly9zZXR0aW5ncy9zZWN1cml0eSDkuK3liIfkuLrigJzml6Dkv53miqTigJ3jgILmn6Xor6LnhafluLjnu4/nlLEgQnJhdmUg5Luj55CG44CC5LiO4oCc56aB55So5a6J5YWo5rWP6KeI4oCd5LqS5pal44CCIn0sIkRpc2FibGVTYWZlQnJvd3NpbmdQcm9jZWVkQW55d2F5Ijp7Im5hbWUiOiLnpoHmraLnu5Xov4flronlhajmtY/op4jorablkYoiLCJkZXNjIjoi56e76Zmk5oG25oSP6L2v5Lu25LiO6ZKT6bG86K2m5ZGK6aG15Lit55qE4oCc5LuN54S26K6/6Zeu4oCd6YCJ6aG577yM6KKr5qCH6K6w55qE572R56uZ77yI5ZCr6K+v5oql77yJ5bCG5a6M5YWo5peg5rOV5omT5byA44CC5LiN5b2x5ZON6K+B5Lmm6K2m5ZGK5oiW5LiL6L296K2m5ZGK44CC6Iul5a6J5YWo5rWP6KeI5bey5YWz6Zet5YiZ5pys6aG55peg5pWI77yM5Y+v6YWN5ZCI4oCc6ZSB5a6a5byA5ZCv5a6J5YWo5rWP6KeI4oCd5L2/55So44CCIn0sIlNTTEVycm9yT3ZlcnJpZGVBbGxvd2VkIjp7Im5hbWUiOiLnpoHmraLnu5Xov4cgSFRUUFMg6K+B5Lmm6K2m5ZGKIiwiZGVzYyI6IuS7juivgeS5pumUmeivr+mhteenu+mZpOKAnOe7p+e7reWJjeW+gOKAnemTvuaOpeWPiumUruebmOaal+eggee7lei/h++8jOivgeS5puaXoOaViOOAgei/h+acn+aIluiHquetvuWQjeeahOermeeCueWwhuWujOWFqOaXoOazleaJk+W8gOOAguS8muWvvOiHtOS9v+eUqOiHquetvuWQjeivgeS5pueahOi3r+eUseWZqOOAgU5BU+OAgeaJk+WNsOacuuWQjuWPsOWPiuacrOWcsOW8gOWPkeacjeWKoeWZqOaXoOazleiuv+mXruOAgiJ9LCJCcm93c2VyR3Vlc3RNb2RlRW5hYmxlZCI6eyJuYW1lIjoi56aB55So6K6/5a6i5qih5byPIiwiZGVzYyI6Iuenu+mZpOS4jeS/neWtmOWOhuWPsuS4lOS4jeWKoOi9veS4quS6uumFjee9ruaJqeWxleeahOiuv+Wuoua1j+iniOeql+WPo+OAguKAnOemgeeUqOaXoOeXleaooeW8j+KAneS4jeS8muenu+mZpOiuv+WuouaooeW8j+OAguaJmOeuoeetlueVpeWcqOiuv+Wuoueql+WPo+S4reWQjOagt+eUn+aViOOAgiJ9LCJBbGxvd0RlbGV0aW5nQnJvd3Nlckhpc3RvcnkiOnsibmFtZSI6IuemgeatouWIoOmZpOa1j+iniOS4juS4i+i9veWOhuWPsiIsImRlc2MiOiLpmLvmraLlnKjljoblj7LorrDlvZXjgIHkuIvovb3orrDlvZXmiJbmuIXpmaTmtY/op4jmlbDmja7kuK3liKDpmaTljoblj7LvvIzpgIDlh7rml7bmuIXpmaTlip/og73kuZ/kvJrkv53nlZnljoblj7LjgILkvYYgYnJhdmU6Ly9zZXR0aW5ncy9wcml2YWN5IOS4reeahOKAnOacrOWcsOWOhuWPsuS/neeVmeacn+mZkOKAneS7jeWPr+iuvuS4uuacgOefreS4gOWkqeiHquWKqOi/h+acn++8jFNsaW1CcmF2ZSDml6Dms5XplIHlrpror6XpobnjgIIifSwiRXh0ZW5zaW9uSW5zdGFsbEJsb2NrbGlzdCI6eyJuYW1lIjoi56aB5q2i5a6J6KOF5bm25YGc55So5YWo6YOo5omp5bGVIiwiZGVzYyI6IuemgeatouWuieijheS7u+S9leaWsOaJqeWxle+8jOW5tuWBnOeUqOaJgOacieW3suWuieijheaJqeWxleOAgumAguWQiOmUgeWumue7iOerr+aIluWutumVv+aOp+WItuWcuuaZr+KAlOKAlOmYsuatoumAmui/h+S7o+eQhi9WUE4g5omp5bGV57uV6L+HIEROUyDov4fmu6TjgIIifSwiQmxvY2tFeHRlcm5hbEV4dGVuc2lvbnMiOnsibmFtZSI6IumYu+atouWklumDqOmdmem7mOS+p+i9veaJqeWxlSIsImRlc2MiOiLpmLvmraLlhbbku5bnqIvluo/pgJrov4cgV2luZG93cyDms6jlhozooajmiJblpJbpg6jokL3nm5jmlofku7bpnZnpu5jms6jlhaXmianlsZXvvIjmjYbnu5Hova/ku7bluLjnlKjmiYvmrrXvvInvvIzlubblnKjkuIvmrKHlkK/liqjml7bnp7vpmaTlt7LpgJrov4for6XpgJTlvoTmt7vliqDnmoTmianlsZXvvIjljbPkvb/kvaDmm77lkIzmhI/vvInjgILkvaDoh6rlt7HkuLvliqjlronoo4XnmoTmianlsZXkuI3lj5flvbHlk43jgIIifSwiRXh0ZW5zaW9uSW5zdGFsbFR5cGVCbG9ja2xpc3QiOnsibmFtZSI6IumYu+atouWRveS7pOihjOWKoOi9veaJqeWxlSAoLS1sb2FkLWV4dGVuc2lvbikiLCJkZXNjIjoi5b+955Wl6YCa6L+HIC0tbG9hZC1leHRlbnNpb24g5Y+C5pWw5Lyg5YWl55qE5omp5bGV77yI5oG25oSP6L2v5Lu25bi456+h5pS55b+r5o235pa55byP5YCf5q2k5qSN5YWl5omp5bGV77yJ44CCR29vZ2xlIENocm9tZSDpu5jorqTlv73nlaXor6Xlj4LmlbDvvIzogIwgQnJhdmUg6buY6K6k5YWB6K646Zmk6Z2e5ZCv55So5q2k562W55Wl44CCLS1kaXNhYmxlLWV4dGVuc2lvbnMtZXhjZXB0IOS7jeWPr+WKoOi9veOAguS8muW9seWTjeS+nei1luivpeWPguaVsOeahOW/q+aNt+aWueW8j+WSjOa1i+ivleW3peWFt+OAgumcgOmHjeWQr+eUn+aViOOAgiJ9LCJJbmNvZ25pdG9Nb2RlQXZhaWxhYmlsaXR5OjEiOnsibmFtZSI6IuemgeeUqOaXoOeXleaooeW8jyIsImRlc2MiOiLlvbvlupXnp7vpmaTpmpDnp4HmtY/op4jlip/og73vvIzml6Dms5Xlho3miZPlvIDml6Dnl5Xnqpflj6PjgILkuI7igJzlvLrliLblhajnqIvml6Dnl5XmqKHlvI/igJ3kupLmlqXjgIIifSwiSW5jb2duaXRvTW9kZUF2YWlsYWJpbGl0eToyIjp7Im5hbWUiOiLlvLrliLblhajnqIvml6Dnl5XmqKHlvI8iLCJkZXNjIjoi5omA5pyJ56qX5Y+j5Z2H5Lul5peg55eV5qih5byP5omT5byA77ya5LiN5L+d5a2Y5Y6G5Y+y77yM55m75b2V5oCB5ZKM5aSa5pWw5omp5bGV5LiN5Lya5oyB5LmF5YyW44CCVG9yIOeql+WPo+OAgUxlbyDkuI4gQnJhdmUgUmV3YXJkcyDkuZ/kvJrpmo/kuYvmtojlpLHvvIxCcmF2ZSDpkrHljIXpmaTpnZ7lhYHorrjlnKjpmpDnp4Hnqpflj6Pov5DooYzlkKbliJnlkIzmoLflgZznlKjjgILkuI7igJznpoHnlKjml6Dnl5XmqKHlvI/igJ3kupLmlqXjgIIifSwiQnJhdmVSZXdhcmRzRGlzYWJsZWQiOnsibmFtZSI6IuemgeeUqCBCcmF2ZSBSZXdhcmRz77yI5aWW5Yqx5LiO5bm/5ZGK77yJIiwiZGVzYyI6Iuenu+mZpCBCcmF2ZSBSZXdhcmRzIOW5tuWFs+mXrSBCcmF2ZSDlub/lkYrmnI3liqHvvIzkuI3lho3mmL7npLrmlrDmoIfnrb7pobXotZ7liqnlo4HnurjmiJbpgJrnn6Xlub/lkYrjgIJCcmF2ZSBTZWFyY2gg5pCc57Si57uT5p6c5bm/5ZGK5LiN5Y+X5b2x5ZON77yb6Zmk6Z2e5ZCM5pe25ZCv55So6ZmQ5Yi2L+emgeeUqOS6keerr+WunumqjO+8jOWQjuWPsOS7jeS8muWMv+WQjeaLieWPluW5v+WRiuWKoOWvhuWvhumSpeOAgiJ9LCJCcmF2ZVdhbGxldERpc2FibGVkIjp7Im5hbWUiOiLnpoHnlKggQnJhdmUg6ZKx5YyFIiwiZGVzYyI6IuemgeeUqOWGhee9ruWKoOWvhui0p+W4gemSseWMheW5tumakOiXj+WFtuWFqOmDqOeVjOmdouWFpeWPo+OAgiJ9LCJCcmF2ZVZQTkRpc2FibGVkIjp7Im5hbWUiOiLnpoHnlKggQnJhdmUgVlBO77yITGludXgg54mI5peg5pWI77yJIiwiZGVzYyI6Iuenu+mZpCBCcmF2ZSBWUE4g5Yqf6IO95Y+K5YW25o6o5bm/5o+Q56S644CCTGludXgg54mI5pys6Lqr5LiN5YyF5ZCrIFZQTu+8jOWboOatpOivpeetlueVpeWcqCBMaW51eCDkuIrml6DmlYjmnpzjgIIifSwiQnJhdmVBSUNoYXRFbmFibGVkIjp7Im5hbWUiOiLnpoHnlKggQnJhdmUgQUkg6IGK5aSpIChMZW8pIiwiZGVzYyI6IuemgeeUqOWGhee9riBBSSDliqnmiYsgTGVv77yM5bm25bCG5YW25LuO5L6n6L655qCP5ZKM5Zyw5Z2A5qCP56e76Zmk44CCQnJhdmUg5LuN5Lya5LiL6L29IExlbyDnmoQgV2ViTUNQIOW3peWFt+iEmuacrOe7hOS7tu+8jOS9huWcqCBMZW8g5YWz6Zet5pyf6Ze05LiN5Lya6KKr6LCD55So44CCIn0sIkJyYXZlTG9jYWxBSUVuYWJsZWQiOnsibmFtZSI6IuemgeeUqOacrOWcsCBBSSDmqKHlnovvvIhCcmF2ZSAxLjk0K++8jOato+W8j+eJiOm7mOiupOWFs+mXre+8iSIsImRlc2MiOiLpmLvmraIgQnJhdmUg5LiL6L295ZKM6L+Q6KGM56uv5L6nIEFJIOaooeWei++8jOW5tuemgeatouWvuea1j+iniOWOhuWPsuW7uueriyBBSSDntKLlvJXvvJvku4XnpoHnlKggTGVvIOaXoOazleimhuebluatpOmhueOAglJlbGVhc2Ug6buY6K6k5YWz6Zet77yITmlnaHRseS9CZXRhIOm7mOiupOW8gOWQr++8ie+8jOatpOetlueVpeWPr+mYsuatouacquadpeiiq+iHquWKqOaIluivr+W8gOWQr+OAgumHjeWQr+WQjueUn+aViOOAgiJ9LCJCcmF2ZVNoaWVsZHNEaXNhYmxlZEZvclVybHMiOnsibmFtZSI6IuWFqOWxgOemgeeUqCBCcmF2ZSDnm77niYzvvIjku4XpmZDmtYvor5Uv5L+h5oGv5Lqt77yJIiwiZGVzYyI6IuS7hemZkOa1i+ivleaIluS/oeaBr+S6reWcuuaZr+OAguWvueaJgOaciee9keermeWFs+mXreebvueJjO+8muWBnOatouW5v+WRiuS4jui/vei4quaLpuaIqu+8jOKAnOebvueJjOS4juWGheWuueS/neaKpOKAneS4i+eahOadoeebruOAgeWJpeemu+i/vei4quWPguaVsOWSjOWHj+WwkeivreiogOaMh+e6uemDveWwhuWkseaViOOAgkRlLUFNUOOAgemYsui3s+mTvuOAgUdQQyDkuI7nrKzkuInmlrkgQ29va2llIOmYu+atouS7jeacieaViOOAguS4juKAnOW8uuWItuaJgOaciee9keermeW8gOWQr+ebvueJjOKAneS6kuaWpeOAgiJ9LCJCcmF2ZVNoaWVsZHNFbmFibGVkRm9yVXJscyI6eyJuYW1lIjoi5by65Yi25omA5pyJ572R56uZ5byA5ZCvIEJyYXZlIOebvueJjCIsImRlc2MiOiLkuLrmiYDmnInnvZHnq5nplIHlrprlvIDlkK/nm77niYzvvJrljZXnq5nlvIDlhbPkuI3lho3og73lhbPpl63lub/lkYrjgIHov73ouKrlmajmiJbmjIfnurnkv53miqTvvIzkvYblsIblhbbliIfkuLrlhbPpl63ml7bku43kvJrmlL7ooYzor6XnvZHnq5nnmoTnrKzkuInmlrkgQ29va2llIOWSjOWtmOWCqOOAguS4juKAnOWFqOWxgOemgeeUqCBCcmF2ZSDnm77niYzigJ3kupLmlqXjgIIifSwiQnJhdmVOZXdzRGlzYWJsZWQiOnsibmFtZSI6IuemgeeUqCBCcmF2ZSDmlrDpl7siLCJkZXNjIjoi5LuO5paw5qCH562+6aG156e76ZmkIEJyYXZlIOaWsOmXu+i1hOiur+a1geOAguiLpemFjee9ruWcqOmmluasoei/kOihjOaXtuabvuWQr+eUqOi/h+aWsOmXu++8jOS+p+i+ueagj+WPr+iDveS7jeaui+eVmeaWsOmXu+Wbvuagh++8iOeCueWHu+WQjuS7heaYvuekuuepuueZvemdouadv++8ieOAgiJ9LCJCcmF2ZVRhbGtEaXNhYmxlZCI6eyJuYW1lIjoi56aB55SoIEJyYXZlIFRhbGsg6KeG6aKR6YCa6K+dIiwiZGVzYyI6IuS7juaWsOagh+etvumhteOAgeS+p+i+ueagj+WSjOiPnOWNleS4remakOiXjyBCcmF2ZSBUYWxr77yI56eB5a+G6KeG6aKR6YCa6K+d77yJ5YWl5Y+j44CC55u05o6l6K6/6ZeuIHRhbGsuYnJhdmUuY29tIOe9keermeS7jeWPr+S9v+eUqOOAgiJ9LCJCcmF2ZVBsYXlsaXN0RW5hYmxlZCI6eyJuYW1lIjoi56aB55SoIEJyYXZlIOaSreaUvuWIl+ihqO+8iOato+W8j+eJiOm7mOiupOWFs+mXre+8iSIsImRlc2MiOiLnpoHnlKjnlKjkuo7lnKjkvqfovrnmoI/kv53lrZjlkozmkq3mlL7pn7Pop4bpopHnmoTmkq3mlL7liJfooajlip/og73jgIJSZWxlYXNlIOWSjCBCZXRhIOm7mOiupOWFs+mXre+8iE5pZ2h0bHkg6buY6K6k5byA5ZCv77yJ77yb5q2k562W55Wl5Y+v56Gu5L+d5YW25oyB57ut5L+d5oyB5YWz6Zet44CCIn0sIkJyYXZlV2ViRGlzY292ZXJ5RW5hYmxlZCI6eyJuYW1lIjoi56aB55SoIFdlYiDlj5HnjrDpobnnm64gKFdlYiBEaXNjb3ZlcnkpIiwiZGVzYyI6IuWBnOatoiBCcmF2ZSDlsIbkvaDorr/pl67nmoTnvZHpobXljL/lkI3otKHnjK7nu5kgQnJhdmUgU2VhcmNoIOaQnOe0ouW8leaTjue0ouW8le+8iFdlYiBEaXNjb3ZlcnkgUHJvamVjdO+8ieOAgiJ9LCJCcmF2ZVNwZWVkcmVhZGVyRW5hYmxlZCI6eyJuYW1lIjoi56aB55So5p6B6YCf6ZiF6K+75qih5byPIChTcGVlZHJlYWRlcikiLCJkZXNjIjoi56aB55So5peg5bmy5omw5paH56ug57K+566A6ZiF6K+75qih5byPIFNwZWVkcmVhZGVy44CCIn0sIlRvckRpc2FibGVkIjp7Im5hbWUiOiLnpoHnlKggVG9yIOmakOengeeql+WPoyIsImRlc2MiOiLnp7vpmaTigJzmlrDlu7rkvb/nlKggVG9yIOeahOmakOengeeql+WPo+KAneWKn+iDveWFpeWPo+OAgiJ9LCJTeW5jRGlzYWJsZWQiOnsibmFtZSI6IuemgeeUqCBCcmF2ZSDlkIzmraUiLCJkZXNjIjoi56aB55So6YCa6L+H5ZCM5q2l6ZO+6Leo6K6+5aSH5ZCM5q2l5Lmm562+44CB5Y6G5Y+y5ZKM6K6+572u55qEIEJyYXZlIFN5bmPjgILlupTnlKjlkI7kuZ/kvJrlsIbmnKzorr7lpIfnp7vlh7rlvZPliY3lkIzmraXpk77vvIzlsIbmnaXop6PpmaTnrZbnlaXlkI7pnIDkvb/nlKjlhbbku5borr7lpIfnmoTlkIzmraXnoIHph43mlrDliqDlhaXjgIIifSwiRW1haWxBbGlhc2VzRW5hYmxlZCI6eyJuYW1lIjoi56aB55So6YKu566x5Yir5ZCN5Yqf6IO9IiwiZGVzYyI6IuemgeeUqOW9k+WJjSBCcmF2ZSDniYjmnKzpu5jorqTlvIDlkK/nmoTkuIDmrKHmgKfpgq7nrrHliKvlkI3nlJ/miJDlip/og73jgIIifSwiRGVmYXVsdEJyYXZlQWRibG9ja1NldHRpbmciOnsibmFtZSI6IuW8uuWItuWQr+eUqOW5v+WRiuS4jui/vei4quaLpuaIqiIsImRlc2MiOiLlsIYgQnJhdmUg572R57uc5bGC5bm/5ZGK5LiO6L+96Liq5Zmo5oum5oiq6ZSB5a6a5Li65omY566h562W55Wl77yM5peg5rOV5Zyo6K6+572u5Lit5oiW6ZKI5a+55Y2V56uZ6ZmN5L2O562J57qn44CC5YWD57Sg6ZqQ6JeP5LiO6ISa5pys5rOo5YWl562J5aSW6KeC6L+H5ruk5LiN6KKr6ZSB5a6a77yM5bey5YWz6Zet55u+54mM55qE572R56uZ5LiN5Y+X6KaG55uW44CCIn0sIkRlZmF1bHRCcmF2ZUZpbmdlcnByaW50aW5nVjJTZXR0aW5nIjp7Im5hbWUiOiLlvLrliLblkK/nlKjmjIfnurnpmLLmiqQiLCJkZXNjIjoi5bCG55u+54mM5oyH57q56Ziy5oqk6ZSB5a6a5Li65omY566h562W55Wl77yM5peg5rOV6ZKI5a+55Y2V5Liq572R56uZ5YWz6Zet44CC5Y2VIEFQSSDlhbzlrrnmgKfkvovlpJbvvIhCcmF2ZSDlhbzlrrnliJfooajmiJboh6rlrprkuYnnm77niYzpobnvvInku43nlJ/mlYjvvIzlt7LlhbPpl63nm77niYznmoTnvZHnq5nkuI3lj5fopobnm5bjgIIifSwiRGVmYXVsdEJyYXZlSHR0cHNVcGdyYWRlU2V0dGluZyI6eyJuYW1lIjoi5by65Yi25Lil5qC8IEhUVFBTIOWNh+e6pyIsImRlc2MiOiLlp4vnu4jlsIbov57mjqXljYfnuqfkuLogSFRUUFPvvJvkuI3mlK/mjIEgSFRUUFMg55qE572R56uZ5bCG5by55Ye66K2m5ZGK6ICM5LiN5Lya6Ieq5Yqo5Zue6YCA6IezIEhUVFDjgILlnKggQnJhdmUg5bey5YiH5o2i5Li6IENocm9taXVtIEhUVFBTLUZpcnN0IOaooeW8j+eahOa4oOmBk++8iEJldGHjgIFOaWdodGx5IOWPiumDqOWIhiBSZWxlYXNl77yJ5LiK5LuF5L2c5LiA5qyh5oCn6aKE6K6+6ICM6Z2e5by65Yi277yb6YWN5ZCI6ZmQ5Yi25oiW56aB55So5LqR56uv5a6e6aqM5Y+v5L+d5oyB5by65Yi255Sf5pWI44CCIn0sIkRlZmF1bHRCcmF2ZVJlZmVycmVyc1NldHRpbmc6MiI6eyJuYW1lIjoi6ZmQ5Yi25p2l5rqQ5aS05LuF5Y+R6YCB5Li75rqQIChTdHJpY3QgT3JpZ2luKSIsImRlc2MiOiLot6jmupDor7fmsYLml7blsIYgUmVmZXJlciDmiKrmlq3kuLrku4XljIXlkKvkuLvmupDvvIhCcmF2ZSDpu5jorqTooYzkuLrvvInlubbplIHlrprvvJrmiYDmnInljZXnq5nkvovlpJbvvIjljIXmi6wgQnJhdmUg5Li65L+u5aSN56uZ54K55YaF572u55qE5YW85a655L6L5aSW77yJ5bCG5aSx5pWI44CC5LiO4oCc5YWB6K645a6M5pW05p2l5rqQ5aS04oCd5LqS5pal44CCIn0sIkRlZmF1bHRCcmF2ZVJlZmVycmVyc1NldHRpbmc6MSI6eyJuYW1lIjoi5YWB6K645a6M5pW05p2l5rqQ5aS0ICh1bnNhZmUtdXJsKSIsImRlc2MiOiLlvZPnvZHnq5nor7fmsYLml7bot6jmupDlj5HpgIHlrozmlbTnmoTmnaXmupAgVVJM44CC5LuF5L2c5Li65YW85a655oCn5bqU5oCl5byA5YWz4oCU4oCU5Lya5YmK5byx6ZqQ56eB5L+d5oqk77yM5omA5pyJ6aKE6K6+5Z2H5pyq5ZCv55So44CC5LiO4oCc6ZmQ5Yi25p2l5rqQ5aS05LuF5Y+R6YCB5Li75rqQ4oCd5LqS5pal44CCIn0sIkRlZmF1bHRCcmF2ZVJlbWVtYmVyMVBTdG9yYWdlU2V0dGluZyI6eyJuYW1lIjoi5YWz6Zet5qCH562+6aG15pe25riF6Zmk56ys5LiA5pa55a2Y5YKoIiwiZGVzYyI6IuWcqOWFs+mXreafkOS4que9keermeeahOacgOWQjuS4gOS4quagh+etvumhteaXtua4hemZpOWFtiBDb29raWUg5LiO5pys5Zyw5a2Y5YKo4oCU4oCU5LiL5qyh6K6/6Zeu5pe2572R56uZ5bCG5LiN5YaN6K6w5L2P5L2g77yI5Y+K55m75b2V54q25oCB77yJ44CCIn0sIkJhY2tncm91bmRNb2RlRW5hYmxlZCI6eyJuYW1lIjoi56aB55So5YWz6Zet5ZCO5ZCO5Y+w6L+Q6KGMIiwiZGVzYyI6IumYu+atoiBCcmF2ZSDlnKjlhbPpl63mnIDlkI7kuIDkuKrnqpflj6PlkI7nu6fnu63pqbvnlZnlkI7lj7DvvIjpgJrluLjku4XlvZPmnInmianlsZXnlLPor7flkI7lj7Dov5DooYzml7bmiY3kvJrlj5HnlJ/vvInjgILoi6Xml6DmraTnsbvmianlsZXvvIzmraTnrZbnlaXku4XplIHlrprlhbPpl60gYnJhdmU6Ly9zZXR0aW5ncy9zeXN0ZW0g5Lit55qE4oCc5YWz6ZetIEJyYXZlIOWQjue7p+e7rei/kOihjOWQjuWPsOW6lOeUqOKAneOAgiJ9LCJIaWdoRWZmaWNpZW5jeU1vZGVFbmFibGVkIjp7Im5hbWUiOiLlkK/nlKjlhoXlrZjoioLnnIHnqIvluo8iLCJkZXNjIjoi5by65Yi25byA5ZCv5YaF5a2Y6IqC55yB56iL5bqP77ya6Ieq5Yqo5LyR55yg5LiN5rS76LeD55qE5qCH562+6aG15Lul6YeK5pS+5YaF5a2Y77yM5YiH5Zue5pe26YeN5paw5Yqg6L2944CCIn0sIkhhcmR3YXJlQWNjZWxlcmF0aW9uTW9kZUVuYWJsZWQ6MSI6eyJuYW1lIjoi5by65Yi25byA5ZCv56Gs5Lu25Yqg6YCfIiwiZGVzYyI6IkJyYXZlIOm7mOiupOW8gOWQr+KAnOWcqOWPr+eUqOaXtuS9v+eUqOWbvuW9ouWKoOmAn+KAne+8m+atpOetlueVpeWwhuWFtumUgeWumu+8jOmYsuatouWcqOiuvue9ruS4reaJi+WKqOWFs+mXreS7peinhOmBv+aYvuWNoeW8guW4uOOAgkdQVSDpu5HlkI3ljZXmiJblj43lpI3ltKnmuoPku43lj6/og73op6blj5Hova/ku7bmuLLmn5Plm57pgIDjgILph43lkK/mtY/op4jlmajlkI7nlJ/mlYjjgIIifSwiSGFyZHdhcmVBY2NlbGVyYXRpb25Nb2RlRW5hYmxlZDowIjp7Im5hbWUiOiLnpoHnlKjnoazku7bliqDpgJ8iLCJkZXNjIjoi5by65Yi25YWz6ZetIEdQVSDnoazku7bliqDpgJ/vvIjkuI7pu5jorqTnm7jlj43vvInvvIzkvJrnibrnibLmuLLmn5PpgJ/luqbkuI7nu63oiKrjgILku4Xlu7rorq7lnKjmmL7ljaHot6/lvoTlrZjlnKjmlYXpmpzml7blvIDlkK/vvJrkvovlpoLpqbHliqjpl67popjlr7zoh7Tpl6rng4HoirHlsY/jgIHomZrmi5/mnLov6L+c56iL5qGM6Z2i5peg5Y+v55SoIEdQVe+8jOaIluWFseS6q+Wxj+W5leaXtueUu+mdouaNn+Wdj+OAgumHjeWQr+a1j+iniOWZqOWQjueUn+aViOOAgiJ9LCJFbmFibGVNZWRpYVJvdXRlciI6eyJuYW1lIjoi56aB55So5aqS5L2T5oqV5bGPIChHb29nbGUgQ2FzdCkiLCJkZXNjIjoi56aB55SoIEdvb2dsZSBDYXN0IOWPiuWFtuWxgOWfn+e9keWQjuWPsOiuvuWkh+WPkeeOsOOAgumHjeWQr+a1j+iniOWZqOWQjueUn+aViOOAgummluasoeWcqOatpOetlueVpeS4i+WIm+W7uueahOmFjee9ruaWh+S7tu+8jOWNs+S+v+aXpeWQjuenu+mZpOetlueVpe+8jOaKleWxj+S7jeS8muS/neaMgeWFs+mXre+8jOmcgOWcqCBicmF2ZTovL3NldHRpbmdzL2V4dGVuc2lvbnMg5Lit6YeN5paw5byA5ZCv5aqS5L2T6Lev55Sx5Zmo5bm26YeN5ZCv44CCIn0sIkFsd2F5c09wZW5QZGZFeHRlcm5hbGx5Ijp7Im5hbWUiOiLlp4vnu4jkvb/nlKjlpJbpg6jnqIvluo/miZPlvIAgUERGIiwiZGVzYyI6IuebtOaOpeS4i+i9vSBQREYg5paH5Lu26ICM6Z2e5L2/55SoIEJyYXZlIOWGhee9riBQREYg6ZiF6K+75Zmo6aKE6KeI77yb5LiL6L295ZCO6ZyA5omL5Yqo5omT5byA44CC572R56uZ5Y+v5Lul5qOA5rWL5Yiw5YaF572u6ZiF6K+75Zmo6KKr56aB55So5LiU5oyH57q55L+d5oqk5LiN5Lya6ZqQ6JeP5q2k54m55b6B77yM5Y+v6IO95Lya5aKe5Yqg6KKr5oyH57q56K+G5Yir55qE6aOO6Zmp44CCIn0sIlRyYW5zbGF0ZUVuYWJsZWQiOnsibmFtZSI6IuemgeeUqOWGhee9rue9kemhtee/u+ivkSIsImRlc2MiOiLnpoHnlKjlhoXnva7nvZHpobXnv7vor5Hlip/og73lj4rlhbblvLnnqpfmj5DnpLrjgIIifSwiU3BlbGxjaGVja0VuYWJsZWQiOnsibmFtZSI6IuemgeeUqOWFqOmDqOaLvOWGmeajgOafpSIsImRlc2MiOiLlvbvlupXlhbPpl63mlofmnKzovpPlhaXmoYbkuK3nmoTmi7zlhpnmo4Dmn6XjgILkuI7igJznpoHnlKjlop7lvLrlnovlnKjnur/mi7zlhpnmo4Dmn6XigJ3kupLmlqXvvIjlkI7ogIXkv53nlZnmnKzlnLDnprvnur/mo4Dmn6XvvIzku4Xnp7vpmaQgR29vZ2xlIOWcqOe6v+afpeivou+8ieOAgiJ9LCJTZWFyY2hTdWdnZXN0RW5hYmxlZCI6eyJuYW1lIjoi56aB55So5Zyw5Z2A5qCP5pCc57Si5bu66K6uIiwiZGVzYyI6IuWBnOatouWwhuS9oOWcqOWcsOWdgOagj+i+k+WFpeeahOWtl+espuWunuaXtuWPkemAgee7meaQnOe0ouW8leaTjuS7peiOt+WPluiBlOaDs+W7uuiuruOAgiJ9LCJQcmludGluZ0VuYWJsZWQiOnsibmFtZSI6IuemgeeUqOa1j+iniOWZqOaJk+WNsOWKn+iDvSIsImRlc2MiOiLlrozlhajnpoHnlKjmtY/op4jlmajmiZPljbDvvIjlkKsgQ3RybCtQIOS4juWPpuWtmOS4uiBQREbvvInjgILkvp3otZbmiZPljbDpooTop4jnmoQgQnJhdmUg5Yqf6IO95Lmf5Lya5ZCM5pe25aSx5pWI77ya5YyF5ousIExlbyDor7vlj5YgR29vZ2xlIERvY3Mv5omr5o+P54mIIFBERu+8jOS7peWPiuaIquWbvuW3peWFt+WcqCBQREYg5LiOIEdvb2dsZSBEb2NzIOS4iueahOmVv+aIquWbvuOAgiJ9LCJEZWZhdWx0QnJvd3NlclNldHRpbmdFbmFibGVkIjp7Im5hbWUiOiLnpoHnlKjpu5jorqTmtY/op4jlmajmj5DnpLoiLCJkZXNjIjoi5YGc5q2iIEJyYXZlIOivoumXruaYr+WQpuiuvuS4uum7mOiupOa1j+iniOWZqO+8jOW5tuWcqCBicmF2ZTovL3NldHRpbmdzIOS4remakOiXj+KAnOiuvuS4uum7mOiupOKAneaMiemSruOAguazqOaEj++8mummluasoei/kOihjOasoui/jumhteS7jeWPr+iDveaYvuekuuKAnOiuvuS4uum7mOiupOKAne+8jOWcqOatpOetlueVpeW8gOWQr+aXtueCueWHu+S8muWvvOiHtOW0qea6g++8jOivt+WcqOivpeWkhOmAieaLqeKAnOi3s+i/h+KAneOAgiJ9LCJEZXZlbG9wZXJUb29sc0F2YWlsYWJpbGl0eSI6eyJuYW1lIjoi56aB55So5byA5Y+R6ICF5bel5YW3IChGMTIpIiwiZGVzYyI6IuWxj+iUveW8gOWPkeiAheW3peWFt++8iEYxMu+8ieOAgeaJqeWxleiwg+ivleWPiuKAnOafpeeci+e9kemhtea6kOS7o+eggeKAneiPnOWNleS4juW/q+aNt+mUru+8jOW5tuWFs+mXreaJqeWxleW8gOWPkeiAheaooeW8j++8iOemgeatouWKoOi9veW3suino+WOi+aJqeWxle+8ieOAguS8muWvvOiHtOaVtOmhteaIquWbvuWNoeatu+W5tuS9v+W9k+WJjeeql+WPo+aIquWbvuaMiemSruWPmOeBsOebtOiHs+WFs+mXreOAgue9kemhteW8gOWPkeiAheivt+WLv+WQr+eUqOOAgiJ9LCJCcmF2ZVdheWJhY2tNYWNoaW5lRW5hYmxlZCI6eyJuYW1lIjoi56aB55SoIFdheWJhY2sgTWFjaGluZSDnvZHpobXlv6vnhaciLCJkZXNjIjoi5b2T572R6aG15aSx5pWI5oiW5oql6ZSZ77yINDA044CBNDA444CBNDEw44CBNDUxIOWPiumDqOWIhiA1eHjvvInml7bvvIzlgZzmraIgQnJhdmUg5o+Q56S66K6/6ZeuIGFyY2hpdmUub3JnIOWtmOaho+W/q+eFp++8iOWMheaLrOiHquWKqOW8ueeql+aPkOekuu+8ieOAgiJ9fSwidWkiOnsid2luZG93X3RpdGxlIjoiU2xpbUJyYXZlIE5lb++8iOS4reaWh+eJiO+8iSIsInJhaWxfc3VidGl0bGUiOiLnrZbnlaXnrqHnkIblmagiLCJuYXZfcHJlc2V0cyI6IuW/q+aNt+mihOiuviIsIm5hdl9hbGwiOiLlhajpg6jpgInpobkiLCJuYXZfZG5zIjoiRE5TIG92ZXIgSFRUUFMiLCJzZWFyY2hfcGxhY2Vob2xkZXIiOiLmkJzntKLnrZbnlaXlkI3np7DjgIHor7TmmI7miJYgS2V5Li4uIiwic2VhcmNoX3RpdGxlIjoi5pCc57Si57uT5p6cIiwic2VhcmNoX2VtcHR5Ijoi5pyq5om+5Yiw5LiOIFwiezB9XCIg5Yy56YWN55qE562W55Wl44CCIiwic2VhcmNoX2NydW1iIjoiU2xpbUJyYXZlIE5lbyAgPiAg5pCc57SiICAtICDmib7liLAgezB9IOmhueWMuemFjSBcInsxfVwiIiwiYWxsX2NydW1iIjoiU2xpbUJyYXZlIE5lbyAgPiAg5YWo6YOo6YCJ6aG5ICAtICDlhbEgezB9IOadoeetlueVpSIsInN0YXR1c19yZWFkeSI6IuWwsee7qiIsInN0YXR1c19ub19wb2xpY3kiOiLmnKzmnLrlsJrmnKrorr7nva7ku7vkvZUgQnJhdmUg5omY566h562W55WlIiwidG9nZ2xlX29uIjoi5byAIiwidG9nZ2xlX29mZiI6IuWFsyIsInByZXNldF9wb2xpY2llc19zdWZmaXgiOiLmnaHnrZbnlaUiLCJwcmVzZXRfbG9hZF9idG4iOiLliqDovb0iLCJwcmVzZXRfbG9hZGVkX3N0YXR1cyI6IuW3suWKoOi9veKAnHswfeKAnSAtIOaaguWtmCB7MX0g5p2h562W55Wl44CC54K55Ye74oCc5bqU55So6K6+572u4oCd5ZCO5omN5Lya5YaZ5YWl5rOo5YaM6KGo44CCIiwiYnV0dG9ucyI6eyJFeHBvcnQiOiLlr7zlh7oiLCJJbXBvcnQiOiLlr7zlhaUiLCJSZS1zeW5jIjoi6YeN5paw5ZCM5q2lIiwiUmVzZXQiOiLph43nva4iLCJBcHBseSBTZXR0aW5ncyI6IuW6lOeUqOiuvue9riJ9LCJkbnMiOnsibW9kZV90aXRsZSI6IkROUyBvdmVyIEhUVFBTIOaooeW8jyIsIm1vZGVfZGVzYyI6IumAieaLqeKAnOS4jeeuoeeQhuKAneWwhuS4jeWGmeWFpeS7u+S9lSBETlMg562W55Wl77yM5a6M5YWo5L+d55WZIEJyYXZlIOWOn+acieiuvue9riIsInRtcGxfdGl0bGUiOiLoh6rlrprkuYkgRG9IIOaooeadvyBVUkwiLCJ0bXBsX25vdGVfb3B0aW9uYWwiOiLku4XlnKggY3VzdG9t77yI6Ieq5a6a5LmJ77yJ5ZKMIHNlY3VyZe+8iOWuieWFqO+8ieaooeW8j+S4i+S9v+eUqCIsInRtcGxfbm90ZV9yZXF1aXJlZCI6IuW/heWhqyAtIOacquiuvue9ruaooeadv+aXtu+8jOWuieWFqCBETlMg5bCG5peg5rOV6Kej5p6Q5Lu75L2V5Z+f5ZCNIiwic3RhdHVzX21vZGUiOiJETlMg5qih5byP77yaezB9Iiwic3RhdHVzX3RtcGxfZXJyIjoiRG9IIOaooeadv++8mnswfSJ9LCJkaWFsb2dzIjp7ImNvbmZpcm1fcmVzZXRfdGl0bGUiOiLnoa7orqTph43nva4iLCJjb25maXJtX3Jlc2V0X2JvZHkiOiLnoa7lrprnp7vpmaQgU2xpbUJyYXZlIE5lbyDnrqHnkIbnmoTmiYDmnInnrZbnlaXvvJ/nlLHnu4TnrZbnlaXmiJblhbbku5blt6Xlhbforr7nva7nmoTnrZbnlaXlsIbkv53mjIHkuI3lj5jjgIIiLCJ1bnNhdmVkX3RpdGxlIjoiU2xpbUJyYXZlIE5lbyIsInVuc2F2ZWRfYm9keSI6IuW9k+WJjeacieWwmuacquW6lOeUqOeahOabtOaUueOAguehruWumuWFs+mXreW5tuaUvuW8g+abtOaUueWQl++8nyIsIm5vdF9lbGV2YXRlZF90aXRsZSI6IumcgOimgeeuoeeQhuWRmOadg+mZkCIsIm5vdF9lbGV2YXRlZF9hcHBseSI6IuWGmeWFpeiuoeeul+acuue6p+etlueVpemcgOimgeeuoeeQhuWRmOadg+mZkO+8jOivt+S7peeuoeeQhuWRmOi6q+S7vemHjeaWsOWQr+WKqOWQjuWGjeW6lOeUqOOAgiIsIm5vdF9lbGV2YXRlZF9yZXNldCI6Iuenu+mZpOiuoeeul+acuue6p+etlueVpemcgOimgeeuoeeQhuWRmOadg+mZkO+8jOivt+S7peeuoeeQhuWRmOi6q+S7vemHjeaWsOWQr+WKqOWQjuWGjemHjee9ruOAgiIsInJlbGF1bmNoX2xvb3BfYm9keSI6IlNsaW1CcmF2ZSDlt7LlsJ3or5Xmj5DmnYPph43lkK/vvIzkvYbmlrDnqpflj6Pku43mnKrojrflvpfnrqHnkIblkZjmnYPpmZDvvIzkuLrpgb/lhY3mrbvlvqrnjq/lt7LlgZzmraLjgILor7fkvb/nlKjnrqHnkIblkZjotKbmiLfov5DooYzjgIIiLCJub19wYXRoX3RpdGxlIjoi5peg5rOV56Gu5a6a6ISa5pys6Lev5b6EIiwibm9fcGF0aF9ib2R5Ijoi6K+35bCG6ISa5pys5L+d5a2Y5Li65pys5ZywIC5wczEg5paH5Lu25ZCO5YaN6L+Q6KGM77yM5Lul5L6/6Ieq5Yqo5o+Q5p2D5Li6566h55CG5ZGY44CCIiwicmVsYXVuY2hfZmFpbGVkX3ByZWZpeCI6IuaXoOazleS7peeuoeeQhuWRmOi6q+S7vemHjeaWsOWQr+WKqO+8miIsInJlbGF1bmNoX2ZhaWxlZF9zdWZmaXgiOiLlupTnlKjlkozph43nva7nrZbnlaXpnIDopoHnrqHnkIblkZjmnYPpmZDmiY3og73lhpnlhaXorqHnrpfmnLrnrZbnlaXjgIIiLCJkb2hfY2hlY2tfdGl0bGUiOiLor7fmo4Dmn6UgRG9IIOaooeadvyIsImRvaF9jaGVja19zdWZmaXgiOiLmqKHlvI/igJx7MH3igJ3ku4XpgJrov4cgRE5TIG92ZXIgSFRUUFMg6Kej5p6Q4oCU4oCU6Iul5peg5pyJ5pWI6Kej5p6Q5Zmo77yM5omA5pyJ5Z+f5ZCN6YO95bCG5peg5rOV6K6/6Zeu77yM5LiU5Zug5Y+X5py65Zmo562W55Wl6ZSB5a6a6ICM5peg5rOV5ZyoIGJyYXZlOi8vc2V0dGluZ3Mg5Lit5L+u5pS544CCIiwianNvbl9maWx0ZXIiOiJKU09OIOmFjee9ruaWh+S7tiAoKi5qc29uKXwqLmpzb24ifSwic3RhdHVzIjp7InN5bmNlZF9mbXQiOiLlt7Lku47ms6jlhozooajor7vlj5bnrZbnlaUgLSDlhbHlj5HnjrAgezB9IOmhuemFjee9riIsImV4cG9ydGVkX2ZtdCI6IuW3suWvvOWHuiB7MH0g5p2h562W55WlIiwiZXhwb3J0X2ZhaWxlZF9mbXQiOiLlr7zlh7rlpLHotKUgLSB7MH0iLCJpbXBvcnRfZmFpbGVkX2ZtdCI6IuWvvOWFpeWksei0pSAtIHswfSIsImltcG9ydGVkX2Zyb21fZm10Ijoi5bey5LuOIHswfSDlr7zlhaXphY3nva4iLCJhcHBsaWVkX2ZtdCI6IuW3suW6lOeUqCB7MH0g5p2h562W55Wl44CC6K+36YeN5ZCvIEJyYXZlIOW5tuWcqCBicmF2ZTovL3BvbGljeSDkuK3moLjpqozjgIIiLCJhcHBseV9mYWlsZWRfZm10Ijoi5YaZ5YWl5aSx6LSl77yaezB944CC5bey5oiQ5Yqf5bqU55SoIHsxfSDmnaHnrZbnlaXjgIIiLCJyZXNldF9kb25lIjoi5bey6YeN572u44CC5LuF56e76Zmk5LqGIFNsaW1CcmF2ZSBOZW8g566h55CG55qE562W55Wl6ZSu44CCIiwicmVwYWlyX3NraXBwZWQiOiLor7flrozlhajlhbPpl60gQnJhdmUg5ZCO5YaN5qyh6L+Q6KGM5Lul5riF55CG5q6L55WZ6YWN572u4oCU4oCUQnJhdmUg5q2j5Zyo6L+Q6KGM77yM5Lya5Zyo5LiL5qyh5L+d5a2Y5pe26KaG55uW5L+u5aSN57uT5p6c44CCIn19fQ==')
) | ConvertFrom-Json

function Get-ZhProp($obj, [string]$key) {
    if ($null -eq $obj -or [string]::IsNullOrEmpty($key)) { return $null }
    $p = $obj.PSObject.Properties[$key]
    if ($null -ne $p) { return $p.Value }
    return $null
}
function Get-ZhNormVal($v) {
    if ($v -is [bool]) { if ($v) { return "1" } else { return "0" } }
    return [string]$v
}
function Get-ZhButton([string]$id) {
    $v = Get-ZhProp $script:zhData.ui.buttons $id
    if ($null -ne $v) { return [string]$v }
    return $id
}
function Get-ZhDnsMode([string]$mode) {
    $v = Get-ZhProp $script:zhData.dns_modes $mode
    if ($null -ne $v) { return [string]$v }
    return $mode
}
function Split-ZhShort([string]$tip) {
    if ([string]::IsNullOrEmpty($tip)) { return "" }
    $iZh = $tip.IndexOf([char]0x3002); $iEn = $tip.IndexOf(". ")
    $cut = -1
    if ($iZh -gt 0 -and $iEn -gt 0) { $cut = [Math]::Min($iZh, $iEn) }
    elseif ($iZh -gt 0) { $cut = $iZh }
    elseif ($iEn -gt 0) { $cut = $iEn }
    if ($cut -gt 0) { return $tip.Substring(0, $cut) }
    return $tip
}

foreach ($cat in $script:cats) {
    $cat | Add-Member -NotePropertyName 'enName' -NotePropertyValue $cat.name -Force
    $zhCat = Get-ZhProp $script:zhData.categories $cat.name
    if ($zhCat) { $cat.name = [string]$zhCat }
    foreach ($row in $cat.rows) {
        $row | Add-Member -NotePropertyName 'enName' -NotePropertyValue $row.name -Force
        $row | Add-Member -NotePropertyName 'enFull' -NotePropertyValue $row.full -Force
        $tr = Get-ZhProp $script:zhData.policies "$($row.key):$(Get-ZhNormVal $row.value)"
        if ($null -eq $tr) { $tr = Get-ZhProp $script:zhData.policies $row.key }
        if ($null -ne $tr) {
            if ($tr.name) { $row.name = [string]$tr.name }
            if ($tr.desc) { $row.full = [string]$tr.desc; $row.short = Split-ZhShort $row.full }
        }
        if ($null -ne $row.PSObject.Properties['choices'] -and $null -ne $row.choices) {
            for ($ci2 = 0; $ci2 -lt $row.choices.Count; $ci2++) {
                $zhCh = Get-ZhProp $script:zhData.choices ([string]$row.choices[$ci2][0])
                if ($zhCh) { $row.choices[$ci2][0] = [string]$zhCh }
            }
        }
    }
}
foreach ($pr in $script:presets) {
    $trPr = Get-ZhProp $script:zhData.presets "$($pr.name) Preset"
    if ($null -eq $trPr) { $trPr = Get-ZhProp $script:zhData.presets $pr.name }
    if ($null -ne $trPr) {
        if ($trPr.name)  { $pr.name  = [string]$trPr.name }
        if ($trPr.blurb) { $pr.blurb = [string]$trPr.blurb }
    }
}
# ===========================================================================

$script:dnsState = @{ Mode = 0; Tmpl = "" }
# Keys of the rows Enforce-ExclusionGroups unticked, for the Import status.
# An array from the start: += onto $null concatenates strings instead.
$script:importConflicts = @()

# ---------------------------------------------------------------------------
# REGISTRY
# ---------------------------------------------------------------------------
# The user-scope path is the SID-aware one computed at the top of the file.
# A literal HKCU here is the elevated process's OWN hive, which under
# over-the-shoulder UAC belongs to the approving admin, not the user whose
# policy is being scrubbed. This assignment was the missing half of the
# $OriginalSid restoration in 94a736a.
$script:machineReg = $machineRegistryPath
$script:userReg    = $userRegistryPath

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-AllRows {
    $out = @()
    foreach ($cat in $script:cats) { foreach ($row in $cat.rows) { $out += $row } }
    return $out
}

function Test-IsChoiceRow($row) {
    return ($null -ne $row.PSObject.Properties['choices'])
}

function Get-RowPolicyValue($row) {
    # $null means "this row manages nothing" - unticked, or a choice row left
    # on "Not managed". Those fall into Apply's removal branch.
    $st = $script:state[$row.Id]
    if (Test-IsChoiceRow $row) {
        if ($st.Sel -le 0) { return $null }
        return $row.choices[$st.Sel][1]
    }
    if (-not $st.On) { return $null }
    # Unary comma: PowerShell unrolls a one-element array on return, which turns
    # ExtensionInstallBlocklist = @("*") into a bare string, so Get-RowRegType
    # calls it String and it is written as REG_SZ instead of a policy list.
    # Chromium then ignores it while the UI reports success.
    if ($row.value -is [array]) { return ,$row.value }
    return $row.value
}

function Get-DeclaredListValues {
    # Every List row's declared value, keyed by policy key. Used as the
    # ownership baseline when deciding whether a list on disk is ours.
    $map = @{}
    foreach ($row in Get-AllRows) {
        if ($row.value -is [array]) { $map[$row.key] = [string[]]$row.value }
    }
    return $map
}

function Remove-OwnedListPolicy([string]$Scope, [string]$Key, $DeclaredLists) {
    # An unticked List row does NOT mean "no list is set". Re-sync only ticks
    # the box on a match, so an admin's own - or a GPO's, or Intune's -
    # ExtensionInstallBlocklist leaves it unticked, and removing the subkey
    # would destroy a policy SlimBrave never wrote. Only remove a list that is
    # exactly ours. Non-list keys are unaffected.
    if (-not (Test-Path $Scope)) { return $false }
    if ($DeclaredLists.ContainsKey($Key) -and
        -not (Test-ListPolicyIsExactly -RegistryPath $Scope -Name $Key `
                                       -Expected $DeclaredLists[$Key])) {
        return $false
    }
    Remove-ListPolicy $Scope $Key
    return $true
}

function Get-RowRegType($value) {
    if ($value -is [array])  { return "List" }
    if ($value -is [string]) { return "String" }
    return "DWord"
}

function ConvertTo-RegValue($value) {
    if ($value -is [bool]) { if ($value) { return 1 } else { return 0 } }
    return $value
}

# ---------------------------------------------------------------------------
# List-policy helpers
#
# Chromium takes a list policy on Windows in either of two forms: numbered
# REG_SZ values in a subkey (e.g. ...\BraveShieldsDisabledForUrls\1 =
# "https://*"), the ADMX form, which Set-ListPolicy writes; or one REG_SZ
# value holding a JSON array (registry_dict.cc:128), the form SlimBrave
# wrote before 0f14e74. When both exist it reads the subkey.
# Each write here stops on failure (-ErrorAction Stop), so Apply's catch
# names the key instead of counting it as written.
# ---------------------------------------------------------------------------
function Set-ListPolicy([string]$RegistryPath, [string]$Name, [string[]]$Values) {
    $listKey = Join-Path $RegistryPath $Name
    if (Test-Path $listKey) { Remove-Item -Path $listKey -Recurse -Force -ErrorAction Stop }
    if (Get-ItemProperty -Path $RegistryPath -Name $Name -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $RegistryPath -Name $Name -ErrorAction SilentlyContinue
    }
    New-Item -Path $listKey -Force -ErrorAction Stop | Out-Null
    for ($i = 0; $i -lt $Values.Count; $i++) {
        Set-ItemProperty -Path $listKey -Name ($i + 1) -Value $Values[$i] -Type String -Force -ErrorAction Stop
    }
}

function Remove-ListPolicy([string]$RegistryPath, [string]$Name) {
    $listKey = Join-Path $RegistryPath $Name
    if (Test-Path $listKey) { Remove-Item -Path $listKey -Recurse -Force }
    if (Get-ItemProperty -Path $RegistryPath -Name $Name -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $RegistryPath -Name $Name -ErrorAction SilentlyContinue
    }
}

# Keys earlier versions wrote and this one no longer offers (AUDIT.md,
# Considered and rejected). Get-AllRows no longer names them, so Apply and
# Reset would leave an upgraded machine's value in force. Each is removed
# from both scopes only while it still holds the DWORD SlimBrave wrote, so a
# value an admin set for their own reasons is left alone. slimbrave-mac.py
# keeps the same names and values (RETIRED_POLICIES); a test holds the two
# equal.
$script:retiredPolicies = [ordered]@{
    "AlternateErrorPagesEnabled"           = 0
    "DNSInterceptionChecksEnabled"         = 0
    "EnableDoNotTrack"                     = 1
    "FeedbackSurveysEnabled"               = 0
    "IPFSEnabled"                          = 0
    "MediaRecommendationsEnabled"          = 0
    "PromotionsEnabled"                    = 0
    "SafeBrowsingExtendedReportingEnabled" = 0
    "SafeSitesFilterBehavior"              = 1
    "ShoppingListEnabled"                  = 0
}

function Remove-RetiredPolicy {
    foreach ($scope in @($script:machineReg, $script:userReg)) {
        if (-not (Test-Path $scope)) { continue }
        foreach ($name in $script:retiredPolicies.Keys) {
            $item = Get-ItemProperty -Path $scope -Name $name -ErrorAction SilentlyContinue
            if ($null -eq $item) { continue }
            $v = $item.$name
            if (($v -is [int]) -and ($v -eq $script:retiredPolicies[$name])) {
                Remove-ItemProperty -Path $scope -Name $name -ErrorAction SilentlyContinue
            }
        }
    }
}

# ---------------------------------------------------------------------------
# DoH TEMPLATE VALIDATION
# The only free-text input in the tool, and the only place a keystroke reaches
# a policy value. A malformed template with mode "secure" leaves Brave unable
# to resolve any hostname, and the user cannot undo it from brave://settings
# because the policy is machine-managed. Validate before writing, never after.
# ---------------------------------------------------------------------------
function Test-DohTemplate([string]$Raw) {
    $v = [string]$Raw
    # Control characters in a registry string are a corrupted policy, not a
    # validation error, so strip rather than reject.
    $v = ($v -replace '[\x00-\x1F\x7F]', '').Trim()
    if ([string]::IsNullOrWhiteSpace($v)) {
        return @{ Ok = $false; Value = ""; Reason = "The template is empty." }
    }
    if ($v.Length -gt 2048) {
        return @{ Ok = $false; Value = $v; Reason = "The template is unreasonably long (over 2048 characters)." }
    }
    # Chromium's own rule, per whitespace-separated template (IsValidDohTemplate,
    # net/dns/public/dns_over_https_server_config.cc): balanced, non-nested
    # {...} sections; once they are expanded, an https URL with a host; and
    # the dns variable outside the host. A template it rejects still reaches
    # the pref, so secure mode would be left with no resolver at all. Each
    # {...} section is swapped for a probe word before the URL checks.
    foreach ($piece in @($v -split '\s+' | Where-Object { $_ })) {
        if ($piece -notmatch '^[^{}]*(\{[^{}]*\}[^{}]*)*$') {
            return @{ Ok = $false; Value = $v; Reason = 'A { or } in the template is unmatched or nested. Chromium would reject it and leave secure DNS with no working resolver.' }
        }
        $probe = $piece -replace '\{[^{}]*\}', 'slimbraveprobe'
        $uri = $null
        if (-not [System.Uri]::TryCreate($probe, [System.UriKind]::Absolute, [ref]$uri)) {
            return @{ Ok = $false; Value = $v; Reason = "That is not a complete URL. A DoH template looks like https://cloudflare-dns.com/dns-query." }
        }
        if ($uri.Scheme -ne "https") {
            return @{ Ok = $false; Value = $v; Reason = "DoH templates must use https. Chromium rejects '$($uri.Scheme)', which would leave secure DNS with no working resolver." }
        }
        if ([string]::IsNullOrWhiteSpace($uri.Host)) {
            return @{ Ok = $false; Value = $v; Reason = "The URL has no hostname." }
        }
        if ($uri.Host -like '*slimbraveprobe*') {
            return @{ Ok = $false; Value = $v; Reason = 'The {dns} variable cannot be part of the hostname.' }
        }
    }
    return @{ Ok = $true; Value = $v; Reason = "" }
}

# ---------------------------------------------------------------------------
# LEAKED SHIELDS EXCEPTIONS
# Some profiles carry braveShields exceptions for exactly the patterns the
# "Disable Brave Shields" row writes (http://*,* and https://*,*), left behind
# after that policy was applied and removed; while there they keep Shields off
# after the row is unticked. Brave does not write the managed policy into
# Preferences (policy content settings stay in memory), and no writer of these
# entries has been identified, so this is a guard for profiles that carry
# them, not a fix for a known cause. Every profile of every installed channel
# is checked, in the invoking account only.
# ---------------------------------------------------------------------------
function Test-NoReparsePoint([string]$root, [string]$path) {
    # True when nothing from $path up to and including $root is a junction,
    # symbolic link or other reparse point. Everything below the root is the
    # user's to replace, and this runs elevated, so a link there could aim the
    # rewrite at a file the user cannot touch. A component whose attributes
    # cannot be read counts as a link.
    $p = $path
    while (-not [string]::IsNullOrEmpty($p)) {
        if (Test-Path -LiteralPath $p) {
            try {
                if ([System.IO.File]::GetAttributes($p) -band [System.IO.FileAttributes]::ReparsePoint) { return $false }
            } catch {
                return $false
            }
        }
        if ($p.TrimEnd('\') -ieq $root.TrimEnd('\')) { return $true }
        $p = [System.IO.Path]::GetDirectoryName($p)
    }
    return $true
}

function Repair-OneBravePrefs([string]$pref, [string]$root) {
    # Returns the number of entries removed, or -1 when an existing file
    # cannot be read, or holds the entries and cannot be rewritten: the
    # contract of _scrub_one_prefs in the Python scripts, so all three report
    # a failed scrub the same way (Get-RepairNote). A missing file, one that
    # is not JSON and a profile reached through a link are nothing to do.
    if (-not (Test-NoReparsePoint $root $pref)) { return 0 }
    if (-not (Test-Path -LiteralPath $pref -PathType Leaf)) { return 0 }
    try { $text = Get-Content -LiteralPath $pref -Raw -Encoding UTF8 -ErrorAction Stop } catch { return -1 }
    if ([string]::IsNullOrWhiteSpace($text)) { return 0 }
    try { $j = $text | ConvertFrom-Json -ErrorAction Stop } catch { return 0 }
    $bs = $null
    if ($j.profile -and $j.profile.content_settings -and $j.profile.content_settings.exceptions) {
        $bs = $j.profile.content_settings.exceptions.braveShields
    }
    if (-not $bs) { return 0 }
    $removed = 0
    foreach ($pattern in @('http://*,*', 'https://*,*')) {
        if ($bs.PSObject.Properties.Name -contains $pattern) {
            $bs.PSObject.Properties.Remove($pattern)
            $removed++
        }
    }
    if ($removed -eq 0) { return 0 }
    # Brave reads Preferences as compact UTF-8 without BOM. Out-File would
    # write UTF-16 with a BOM and break Brave on next launch.
    $json = $j | ConvertTo-Json -Depth 100 -Compress
    # A random name opened with CreateNew, never a fixed one: CreateNew fails
    # rather than reuse a file or link someone left at the path.
    $tmp = $pref + '.slimbrave-' + [guid]::NewGuid().ToString('N')
    $stream = $null
    try {
        $bytes = (New-Object System.Text.UTF8Encoding $false).GetBytes($json)
        $stream = New-Object System.IO.FileStream($tmp, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Close()
        $stream = $null
        # Checked again just before the rename, for a link swapped in since.
        # The entries are still there, so this profile counts as not cleaned.
        if (-not (Test-NoReparsePoint $root $pref)) {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            return -1
        }
        Move-Item -LiteralPath $tmp -Destination $pref -Force -ErrorAction Stop
    } catch {
        if ($null -ne $stream) { $stream.Close() }
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        return -1
    }
    return $removed
}

function Get-UserAppDataRoots {
    <#
      The LOCALAPPDATA root whose Brave profiles get scrubbed: the invoking
      account's own, which the elevated relaunch forwards, just as the Linux
      and macOS scripts scrub only the invoking user's home. Other accounts
      are never touched: any of them could plant a junction in its own
      profile tree and aim this elevated rewrite at a file it cannot reach.
    #>
    $roots = New-Object System.Collections.ArrayList
    $primary = $env:LOCALAPPDATA
    if (-not [string]::IsNullOrWhiteSpace($script:OriginalLocalAppData)) {
        $primary = $script:OriginalLocalAppData
    }
    if (-not [string]::IsNullOrWhiteSpace($primary)) {
        [void]$roots.Add(@{ Path = $primary; Label = "this user" })
    }
    return $roots
}

function Repair-OneUserRoot([string]$localAppData) {
    # One unreadable or locked profile must not abort the sweep; the other
    # profiles still get their repair. A profile that could not be cleaned
    # is counted under its User Data folder, which the status names. Brave
    # Origin keeps its profiles beside Brave's (Brave-Origin*).
    $removed = 0
    $failed = [ordered]@{}
    foreach ($channelDir in @('Brave-Browser', 'Brave-Browser-Beta', 'Brave-Browser-Nightly', 'Brave-Browser-Dev', 'Brave-Origin', 'Brave-Origin-Beta', 'Brave-Origin-Nightly', 'Brave-Origin-Dev')) {
        $userData = Join-Path $localAppData "BraveSoftware\$channelDir\User Data"
        if (-not (Test-Path $userData)) { continue }
        $profileDirs = Get-ChildItem -Path $userData -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }
        foreach ($dir in $profileDirs) {
            try { $n = Repair-OneBravePrefs (Join-Path $dir.FullName 'Preferences') $localAppData } catch { $n = -1 }
            if ($n -ge 0) {
                $removed += $n
            } elseif ($failed.Contains($userData)) {
                $failed[$userData] = $failed[$userData] + 1
            } else {
                $failed[$userData] = 1
            }
        }
    }
    return @{ Removed = $removed; Failed = $failed }
}

function Repair-BravePrefs {
    # Every Brave channel, Origin's included, runs as brave.exe on Windows.
    $running = ($null -ne (Get-Process brave -ErrorAction SilentlyContinue))
    # Chromium serves prefs from an in-memory PrefService and rewrites the file
    # on shutdown, so a scrub done now is discarded the moment the user closes
    # Brave - which is exactly what we tell them to do next. Report it instead
    # of claiming a clean that will not survive.
    if ($running) { return @{ Removed = 0; Failed = @{}; Running = $true; Skipped = $true } }

    $removed = 0
    $failed = [ordered]@{}
    foreach ($root in Get-UserAppDataRoots) {
        $r = Repair-OneUserRoot $root.Path
        $removed += $r.Removed
        foreach ($dir in @($r.Failed.Keys)) { $failed[$dir] = $r.Failed[$dir] }
    }
    return @{ Removed = $removed; Failed = $failed; Running = $false; Skipped = $false }
}

function Join-Status([string]$lead, $repair) {
    # The repair note follows the routine result - unless it needs the user
    # to act (Brave was running, nothing was cleared), in which case it leads.
    $n = (Get-RepairNote $repair).Trim()
    if (-not $n) { return $lead }
    if ($repair.Skipped) { return "$n $lead" }
    return "$lead $n"
}

function Get-InvokerDocs {
    # Under over-the-shoulder UAC the elevated process is the ADMIN, so the
    # dialogs' default folder was the admin's Documents. The invoking user's
    # profile is already forwarded through the relaunch; derive theirs from it.
    if([string]::IsNullOrWhiteSpace($script:OriginalLocalAppData)){
        return [Environment]::GetFolderPath('MyDocuments')
    }
    $prof = Split-Path (Split-Path $script:OriginalLocalAppData -Parent) -Parent
    $docs = Join-Path $prof 'Documents'
    if(Test-Path $docs){ return $docs }
    if(Test-Path $prof){ return $prof }
    return [Environment]::GetFolderPath('MyDocuments')
}

function Get-RepairNote($repair) {
    if ($repair.Skipped) {
        # Leads with the action: this is the one line the user has to do
        # something about, so it goes first (see Join-Status) and says so.
        return " 请完全关闭 Brave 后再次运行以清理残留配置——Brave 正在运行，会在下次保存时覆盖修复结果。"
    }
    $note = ""
    if ($repair.Removed -gt 0) {
        $plural = ""
        if ($repair.Removed -ne 1) { $plural = "s" }
        $note = " Also cleaned $($repair.Removed) leaked profile pref$plural from your Brave profile."
    }
    # The same words as the Python scripts' _scrub_failure_note.
    if (($null -ne $repair.Failed) -and ($repair.Failed.Count -gt 0)) {
        $n = 0
        foreach ($c in $repair.Failed.Values) { $n += $c }
        $plural = ""
        if ($n -ne 1) { $plural = "s" }
        $note += " Failed to clean $n profile$plural; check ownership of " + (@($repair.Failed.Keys) -join ", ") + "."
    }
    return $note
}

function Invoke-ApplyPolicy {
    # DNS is validated first. Writing features and then bailing out would
    # leave the store half-applied, which is what the v1.9.5 critical bug
    # looked like in practice - "secure" with no template is as fatal as
    # "custom" with none.
    $mode = $script:dnsModes[$script:dnsState.Mode]
    $needsTemplate = ($mode -eq "custom" -or $mode -eq "secure")
    if ($needsTemplate) {
        $check = Test-DohTemplate $script:dnsState.Tmpl
        if (-not $check.Ok) {
            [void][System.Windows.Forms.MessageBox]::Show(
                "$($check.Reason)`n`nMode '$mode' sends DNS over HTTPS only - with no working resolver, nothing resolves at all, and the setting cannot be changed from brave://settings because it is machine policy.",
                "请检查 DoH 模板",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning)
            return $false
        }
        # write the sanitised value, not the raw keystrokes
        $script:dnsState.Tmpl = $check.Value
    }
    # No check in the other modes: the template is not written there, and the
    # box is disabled, so refusing over a held value was an unrecoverable
    # block - pick custom, mistype, switch to off, and Apply died with the
    # only remedy behind a greyed-out control.
    if (-not (Test-Elevated)) {
        [void][System.Windows.Forms.MessageBox]::Show(
            "写入计算机级策略需要管理员权限，请以管理员身份重新启动后再应用。",
            "Not elevated",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning)
        return $false
    }
    if (-not (Test-Path $script:machineReg)) {
        New-Item -Path $script:machineReg -Force | Out-Null
    }

    $selected = @{}
    foreach ($row in Get-AllRows) {
        $v = Get-RowPolicyValue $row
        if ($null -eq $v) { continue }
        $selected[$row.key] = @{ Key = $row.key; Value = $v; Type = (Get-RowRegType $v) }
    }
    $declaredLists = Get-DeclaredListValues
    $skippedLists = @{}
    $uniqueKeys = (Get-AllRows | ForEach-Object { $_.key } | Select-Object -Unique)
    $written = 0
    # Registry provider errors do not stop a script on their own, so every
    # write below carries -ErrorAction Stop (never $ErrorActionPreference,
    # which Repair-BravePrefs would inherit); a key whose write fails is
    # named here instead of being counted as written.
    $failed = @()
    foreach ($key in $uniqueKeys) {
        if ($selected.ContainsKey($key)) {
            $f = $selected[$key]
            try {
                if ($f.Type -eq "List") {
                    Set-ListPolicy $script:machineReg $f.Key ([string[]]$f.Value)
                    # The user-scope copy goes under the same ownership test
                    # as every other list removal: one that is not exactly
                    # SlimBrave's stays (the machine value outranks it).
                    [void](Remove-OwnedListPolicy $script:userReg $f.Key $declaredLists)
                } else {
                    Set-ItemProperty -Path $script:machineReg -Name $f.Key `
                        -Value (ConvertTo-RegValue $f.Value) -Type $f.Type -Force -ErrorAction Stop
                    if ((Test-Path $script:userReg) -and
                        (Get-ItemProperty -Path $script:userReg -Name $key -ErrorAction SilentlyContinue)) {
                        Remove-ItemProperty -Path $script:userReg -Name $key -ErrorAction SilentlyContinue
                    }
                }
                $written++
            } catch { $failed += $key }
        } else {
            # A scope that does not exist holds nothing to remove. Nothing
            # creates the user-scope key, so without this skip a Shields row
            # reported 'Left alone' on nearly every Apply; Reset skips it too.
            foreach ($scope in @($script:machineReg, $script:userReg)) {
                if (-not (Test-Path $scope)) { continue }
                if (-not (Remove-OwnedListPolicy $scope $key $declaredLists)) {
                    if ($declaredLists.ContainsKey($key)) { $skippedLists[$key] = $true }
                }
            }
        }
    }

    Remove-RetiredPolicy

    # Clear BOTH scopes first, unconditionally. The managed branch below used
    # to write HKLM only and never touch the user-scope twin, unlike every other
    # key here - so a leftover HKCU DnsOverHttpsTemplates from an older tool
    # survived, stayed invisible to Read-LivePolicy (machine scope only), and
    # could still be the template Chromium honoured.
    foreach ($scope in @($script:machineReg, $script:userReg)) {
        if (Test-Path $scope) {
            Remove-ItemProperty -Path $scope -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $scope -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
        }
    }
    if ($mode -eq "unmanaged") {
        # nothing further: the scrub above is the whole action
    } else {
        # "custom" is Chromium's "secure" plus a template; the UI keeps them
        # apart so the template field can be required for one and not the other.
        $writeMode = $mode
        if ($mode -eq "custom") { $writeMode = "secure" }
        try {
            Set-ItemProperty -Path $script:machineReg -Name "DnsOverHttpsMode" -Value $writeMode -Type String -Force -ErrorAction Stop
            # Chromium does honour a template in "automatic" mode, but this UI
            # greys the template box out there and captions it "Only used by the
            # custom and secure modes". Writing it anyway pinned a resolver the
            # interface said was inactive, with the box disabled so it could not be
            # cleared. Match what the user is shown; "custom" is the way to pair a
            # template with a mode here.
            $wantsTemplate = ($mode -eq "custom" -or $mode -eq "secure")
            if ($wantsTemplate -and -not [string]::IsNullOrWhiteSpace($script:dnsState.Tmpl)) {
                Set-ItemProperty -Path $script:machineReg -Name "DnsOverHttpsTemplates" `
                    -Value $script:dnsState.Tmpl -Type String -Force -ErrorAction Stop
            } else {
                Remove-ItemProperty -Path $script:machineReg -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
            }
            $written++
        } catch { $failed += 'DnsOverHttpsMode' }
    }
    $repair = Repair-BravePrefs
    # A failed write leaves the staged state unapplied (Apply returns false,
    # so the Apply handler does not take a new snapshot) and says which keys.
    if ($failed.Count -gt 0) {
        Set-Status (Join-Status ([string]::Format($script:zhData.ui.status.apply_failed_fmt, (($failed | Sort-Object) -join ", "), $written)) $repair)
        return $false
    }
    $lead = [string]::Format($script:zhData.ui.status.applied_fmt, $written)
    if ($skippedLists.Count -gt 0) {
        $lead += " Left alone because the list on disk is not the one SlimBrave writes: " +
                 (($skippedLists.Keys | Sort-Object) -join ", ") + "."
    }
    Set-Status (Join-Status $lead $repair)
    return $true
}

function Invoke-ResetPolicy {
    # Scoped to keys this tool manages. A recursive delete of the hive would
    # take out GPO-set policies SlimBrave never wrote - the v2.0.0 bug.
    if (-not (Test-Elevated)) {
        [void][System.Windows.Forms.MessageBox]::Show(
            "移除计算机级策略需要管理员权限，请以管理员身份重新启动后再重置。",
            "Not elevated",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning)
        return $false
    }
    $uniqueKeys = (Get-AllRows | ForEach-Object { $_.key } | Select-Object -Unique)
    $declaredLists = Get-DeclaredListValues
    $skippedLists = @{}
    foreach ($scope in @($script:machineReg, $script:userReg)) {
        if (-not (Test-Path $scope)) { continue }
        foreach ($key in $uniqueKeys) {
            if (-not (Remove-OwnedListPolicy $scope $key $declaredLists)) {
                if ($declaredLists.ContainsKey($key)) { $skippedLists[$key] = $true }
            }
        }
        Remove-ItemProperty -Path $scope -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $scope -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
    }
    Remove-RetiredPolicy
    foreach ($id in @($script:state.Keys)) { $script:state[$id].On = $false; $script:state[$id].Sel = 0 }
    $script:dnsState.Mode = 0
    $script:dnsState.Tmpl = ""
    $repair = Repair-BravePrefs
    $note = "已重置。仅移除了 SlimBrave Neo 管理的策略键。"
    if ($skippedLists.Count -gt 0) {
        $note += " Left $($skippedLists.Count) externally-managed list policy" +
                 $(if ($skippedLists.Count -eq 1) { "" } else { "s" }) + " alone."
    }
    Set-Status (Join-Status $note $repair)
    return $true
}

function Read-LivePolicy {
    $live = @{}
    if (Test-Path $script:machineReg) {
        foreach ($pr in (Get-ItemProperty $script:machineReg).PSObject.Properties) {
            # Only the provider's own note properties are skipped, by exact
            # name: a policy whose name starts with 'Ps' is still a policy.
            if (@('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') -cnotcontains $pr.Name) { $live[$pr.Name] = $pr.Value }
        }
        foreach ($sk in (Get-ChildItem $script:machineReg -ErrorAction SilentlyContinue)) {
            $vals = @()
            foreach ($pr in (Get-ItemProperty $sk.PSPath).PSObject.Properties) {
                if ($pr.Name -match '^[0-9]+$') { $vals += [string]$pr.Value }
            }
            if ($vals.Count -gt 0) { $live[$sk.PSChildName] = $vals }
        }
    }
    return $live
}

function Sync-FromRegistry {
    $live = Read-LivePolicy
    foreach ($id in @($script:state.Keys)) { $script:state[$id].On = $false; $script:state[$id].Sel = 0 }
    foreach ($row in Get-AllRows) {
        if (-not $live.ContainsKey($row.key)) { continue }
        $lv = $live[$row.key]
        if (Test-IsChoiceRow $row) {
            for ($i = 1; $i -lt $row.choices.Count; $i++) {
                if ([string]$row.choices[$i][1] -eq [string]$lv) { $script:state[$row.Id].Sel = $i; break }
            }
        } elseif ($row.value -is [array]) {
            # Order means nothing to Chromium, so a reordered copy of
            # SlimBrave's list shows ticked instead of being removed by the
            # next Apply. Compared as the ownership test compares
            # (Compare-Object, case-blind); Import compares exactly
            # (Test-ImportSameList), and making Re-sync exact too is open
            # (AUDIT.md What's next, Tool fixes (4)).
            $mine = @(); foreach ($x in $row.value) { $mine += [string]$x }
            if (($lv -is [array]) -and ($lv.Count -eq $mine.Count) -and -not (Compare-Object $lv $mine)) {
                $script:state[$row.Id].On = $true
            }
        } else {
            if ([string]$lv -eq [string](ConvertTo-RegValue $row.value)) { $script:state[$row.Id].On = $true }
        }
    }
    $script:dnsState.Mode = 0
    $script:dnsState.Tmpl = ""
    if ($live.ContainsKey("DnsOverHttpsMode")) {
        $m = [string]$live["DnsOverHttpsMode"]
        $tm = ""
        if ($live.ContainsKey("DnsOverHttpsTemplates")) { $tm = [string]$live["DnsOverHttpsTemplates"] }
        # A stored "secure" with a template is what this UI calls "custom".
        if ($m -eq "secure" -and $tm) { $m = "custom" }
        $idx = [Array]::IndexOf($script:dnsModes, $m)
        if ($idx -ge 0) { $script:dnsState.Mode = $idx }
        $script:dnsState.Tmpl = $tm
    }
    Enforce-ExclusionGroups
    Set-Status ([string]::Format($script:zhData.ui.status.synced_fmt, $live.Count))
}

function Enforce-ExclusionGroups {
    # The toggle handler collapses a group as you click, but Import and
    # Re-sync write $script:state directly and never ran that rule - so two
    # members of one group could be staged together and Apply wrote both.
    # The later row in table order wins, as Brave does when both keys are
    # set (BraveShieldsEnabledForUrls is applied after the Disabled list;
    # SpellCheckServiceEnabled does nothing once SpellcheckEnabled is false);
    # same rule as _enforce_groups in the Python scripts. The rows are walked
    # in reverse, so the first ticked member met is the one kept. Each row
    # unticked here is recorded for the Import status; Re-sync ignores it.
    $rows = @(Get-AllRows)
    [array]::Reverse($rows)
    $seen = @{}
    foreach ($row in $rows) {
        if (-not $row.group) { continue }
        if (-not $script:state[$row.Id].On) { continue }
        if ($seen.ContainsKey($row.group)) {
            $script:state[$row.Id].On = $false
            $script:importConflicts += $row.key
            continue
        }
        $seen[$row.group] = $true
    }
}

# Checkbox rows whose policy is an integer enum. The tables above hold
# booleans and enums alike as DWord, so import needs this list to take only a
# JSON integer for these keys, as the Python scripts' _value_fits_row does. A
# test holds it equal to the Python rows whose value is an int (not a bool),
# plus DynamicCodeSettings, which only this script offers.
$script:intEnumKeys = @(
    'BrowserSignin',
    'ChromeVariations',
    'DefaultBraveAdblockSetting',
    'DefaultBraveFingerprintingV2Setting',
    'DefaultBraveHttpsUpgradeSetting',
    'DefaultBraveReferrersSetting',
    'DefaultBraveRemember1PStorageSetting',
    'DefaultJavaScriptOptimizerSetting',
    'DeveloperToolsAvailability',
    'DynamicCodeSettings',
    'ForceYouTubeRestrict',
    'IncognitoModeAvailability',
    'NetworkPredictionOptions',
    'SafeBrowsingProtectionLevel'
)

function Import-PresetIntoState($preset) {
    # What the Import status names besides the exclusion groups, one list per
    # clause, each in the file's order: names in the wrong letter case (each
    # a pair of the name and the spelling it needs, so a List[object]),
    # values outside their policy's JSON type (importNotes, the clause that
    # came first), values of the right type that no row sets, keys an
    # earlier version offered, and keys SlimBrave Neo does not offer. A name
    # is kept as the file wrote it: only the few a clause shows are made safe
    # to show, when the status is built (Get-ImportClause), as the Python
    # scripts do, since a file can name a hundred thousand keys. A value
    # item is made safe here (Format-ImportItem); there is at most one per
    # row key. Lists, not arrays: += copies the whole array. Nothing named
    # in any of them is staged.
    $script:importMiscased = [System.Collections.Generic.List[object]]::new()
    $script:importNotes = [System.Collections.Generic.List[string]]::new()
    $script:importUnwritten = [System.Collections.Generic.List[string]]::new()
    $script:importRetired = [System.Collections.Generic.List[string]]::new()
    $script:importUnknown = [System.Collections.Generic.List[string]]::new()
    $script:importConflicts = @()
    foreach ($id in @($script:state.Keys)) { $script:state[$id].On = $false; $script:state[$id].Sel = 0 }
    # A name matches in its exact letter case, as in the Python scripts, and
    # ordinally: -ceq and -ccontains compare in the invariant culture, which
    # takes some different strings for equal. $rowFold gives the spelling a
    # name in the wrong case needs (Get-ImportCanonical).
    $rowKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $rowFold = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($row in Get-AllRows) {
        [void]$rowKeys.Add($row.key)
        if (-not $rowFold.ContainsKey($row.key)) { $rowFold.Add($row.key, $row.key) }
    }
    $retired = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($k in $script:retiredPolicies.Keys) { [void]$retired.Add([string]$k) }
    $feat = $preset.features
    if ($feat -is [array]) {
        # Legacy pre-2026 export: Features was a bare ARRAY of policy key names,
        # not an object of key/value pairs. main carried an explicit branch for
        # this; without one, PSObject.Properties[$key] is $null for every row,
        # so the import staged nothing and still reported success - after having
        # already cleared the user's selections above.
        # Only a JSON string names a key. A [string] cast made one out of
        # anything: a nested ["BraveRewardsDisabled"] ticked its row, and a
        # number or null matched nothing and went unmentioned. An entry that
        # is not a row's key is named once, in file order: a name by its
        # class (Add-ImportNameNote), anything else by its value (5, null,
        # true), as the Python scripts name it, once per text. That text is
        # Format-ImportValue's, which Format-ImportName shows as it is, so
        # it waits in importUnknown beside the names. A list, an object or a
        # fraction has no text that both languages print alike, so it is
        # left out. A string "5" and a number 5 are two entries, as there.
        $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $shownValues = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($n in $feat) {
            if ($n -is [string]) {
                if (-not $names.Add($n)) { continue }
                if (-not $rowKeys.Contains($n)) { Add-ImportNameNote $n $rowFold $retired }
            } else {
                $shown = Format-ImportValue $n
                if (($null -ne $shown) -and $shownValues.Add($shown)) { $script:importUnknown.Add($shown) }
            }
        }
        # First row per KEY wins. Several keys carry two rows with opposite
        # values (Force Incognito vs Disable Incognito, the two Variations
        # rows, the two Referrers rows), and the guard here used to test the
        # row's own state - which this function had just cleared, so it never
        # fired and BOTH rows of every pair were staged. Apply then wrote the
        # second one's value.
        $handled = @{}
        foreach ($row in Get-AllRows) {
            if (-not $names.Contains($row.key)) { continue }
            if ($handled.ContainsKey($row.key)) { continue }
            $handled[$row.key] = $true
            if (Test-IsChoiceRow $row) {
                for ($i = 1; $i -lt $row.choices.Count; $i++) {
                    if ([string]$row.choices[$i][1] -eq [string]$row.value) {
                        $script:state[$row.Id].Sel = $i; break
                    }
                }
            } else {
                # A bare key in the legacy format means "apply this row's own
                # declared value", which is what the row is ticked to write.
                $script:state[$row.Id].On = $true
            }
        }
        $feat = $null
    }
    # The object format. Each row's outcome is kept per KEY, not per row: two
    # rows can share a key, and a value the other row takes is not a drop.
    # $taken holds the keys a row staged; $missed and $wrong the item to name
    # for a key no row took, by whether its value had the policy's JSON type.
    $used = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $taken = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $missed = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::Ordinal)
    $wrong = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::Ordinal)
    foreach ($row in Get-AllRows) {
        if ($null -eq $feat) { continue }
        # PSObject.Properties[...] ignores letter case. ConvertFrom-Json
        # refuses two keys that differ only in case, so this finds at most
        # one property, and its name has to be the row's key exactly.
        $prop = $feat.PSObject.Properties[$row.key]
        if ($null -eq $prop) { continue }
        if (-not [string]::Equals($prop.Name, $row.key, [System.StringComparison]::Ordinal)) { continue }
        [void]$used.Add($prop.Name)
        $want = $prop.Value
        if (Test-IsChoiceRow $row) {
            # Type-strict, as both Python ports are: only a JSON integer is a
            # member of the enum, and nothing is cast, so nothing can throw. A
            # quoted "1", a $true, a [long] past Int32 or a fraction or
            # exponent (2.0, 2e0) matches no choice and is named.
            $ok = ($want -is [int] -or $want -is [long])
            $matched = $false
            if ($ok) {
                for ($i = 1; $i -lt $row.choices.Count; $i++) {
                    if ([string]$row.choices[$i][1] -eq [string]$want) {
                        $script:state[$row.Id].Sel = $i; $matched = $true; break
                    }
                }
            }
            # An integer no choice offers (one off the enum, or Notifications'
            # 3, which Brave takes as Ask) is a value no row sets; anything
            # else is not one this policy accepts.
            if ($matched) {
                [void]$taken.Add($row.key)
            } elseif ($ok) {
                $missed[$row.key] = Format-ImportItem $row.key $want
            } else { $wrong[$row.key] = Format-ImportItem $row.key $want }
        } elseif ($row.value -is [array]) {
            # Match the VALUE, not merely the key. Ticking on key presence alone
            # means an imported single-site exception such as
            # BraveShieldsDisabledForUrls = ["https://intranet.example"] stages
            # this row, and Apply then writes SlimBrave's own wildcard - turning
            # one site into the whole web. Only a JSON array is a list: a bare
            # "*" is named, not taken for ["*"]. Its entries match only as
            # JSON strings, ordinally, as the Python scripts' sorted() and ==
            # compare them (Test-ImportSameList); a list that is not
            # SlimBrave's is a value no row sets, since the policy itself
            # would take it.
            $fits = ($want -is [array])
            $strings = $true
            $wantList = @(); foreach ($x in @($want)) { if (-not ($x -is [string])) { $strings = $false }; $wantList += [string]$x }
            $mine = @();     foreach ($x in $row.value) { $mine += [string]$x }
            if ($fits -and $wantList.Count -eq $mine.Count -and
                $strings -and (Test-ImportSameList $wantList $mine)) {
                $script:state[$row.Id].On = $true
                [void]$taken.Add($row.key)
            } elseif ($fits) {
                $missed[$row.key] = Format-ImportItem $row.key $want
            } else { $wrong[$row.key] = Format-ImportItem $row.key $want }
        } else {
            # A value only in its policy's JSON type, as the Python scripts'
            # _value_fits_row takes it: the string row a string; an integer
            # enum a JSON integer, so a $true cannot pick value 1; a boolean
            # $true / $false or an integer (Windows exports write 0/1). The
            # string row's value matches in its exact letter case, ordinally,
            # as the Python scripts' == compares it: Chromium checks a string
            # enum with strcmp, so "DISABLE_NON_PROXIED_UDP" is not that value.
            if ($row.value -is [string]) {
                $fits = ($want -is [string])
            } elseif ($script:intEnumKeys -contains $row.key) {
                $fits = (($want -is [int]) -or ($want -is [long]))
            } else {
                $fits = (($want -is [bool]) -or ($want -is [int]) -or ($want -is [long]))
            }
            if (-not $fits) {
                $wrong[$row.key] = Format-ImportItem $row.key $want
            } elseif ([string]::Equals([string](ConvertTo-RegValue $want), [string](ConvertTo-RegValue $row.value), [System.StringComparison]::Ordinal)) {
                $script:state[$row.Id].On = $true
                [void]$taken.Add($row.key)
            } else { $missed[$row.key] = Format-ImportItem $row.key $want }
        }
    }
    # The file's keys, in its order. One no row read is named by its class
    # (Add-ImportNameNote). A value no row of its key took is named once,
    # by whether it had the policy's JSON type: ChromeVariations 0 or a
    # true where the row writes false as a value no row sets, a "1" for a
    # number as one the policy does not accept.
    if ($null -ne $feat) {
        foreach ($p in $feat.PSObject.Properties) {
            $n = $p.Name
            if (-not $used.Contains($n)) { Add-ImportNameNote $n $rowFold $retired; continue }
            if ($taken.Contains($n)) { continue }
            if ($missed.ContainsKey($n)) {
                $script:importUnwritten.Add($missed[$n])
            } elseif ($wrong.ContainsKey($n)) { $script:importNotes.Add($wrong[$n]) }
        }
    }
    $script:dnsState.Mode = 0
    $script:dnsState.Tmpl = ""
    if ($preset.tmpl) { $script:dnsState.Tmpl = [string]$preset.tmpl }
    # A DnsMode is there unless the file leaves it out or gives null or "",
    # as in the Python scripts. PowerShell's own truth test took [0] for no
    # mode and {} for one; now false, 0, a list or an object is a value that
    # names no mode, and is named.
    if (($null -ne $preset.dns) -and -not (($preset.dns -is [string]) -and ($preset.dns.Length -eq 0))) {
        # Case-insensitive, as main was: a hand-edited "Automatic" must not
        # silently land on unmanaged and drop the resolver the file asked for.
        # Only a string names a mode, as in the Python scripts: a list such
        # as ["off"] is named, not taken. OrdinalIgnoreCase, and only on
        # printable ASCII, as Python's .lower() matches the mode words: -eq
        # compares linguistically, so "se" + U+00AD + "cure" was secure. An
        # unknown one is named after the Features values, through
        # Format-ImportItem like every value from the file: its text could be
        # anything.
        $want = [string]$preset.dns
        $canon = @()
        if (($preset.dns -is [string]) -and ($want -cmatch '^[\x20-\x7E]*\z')) {
            $canon = @($script:dnsModes | Where-Object { [string]::Equals($_, $want, [System.StringComparison]::OrdinalIgnoreCase) })
        }
        if ($canon.Count -gt 0) {
            $script:dnsState.Mode = [Array]::IndexOf($script:dnsModes, $canon[0])
        } else { $script:importNotes.Add((Format-ImportItem 'DnsMode' $preset.dns)) }
    } elseif ($script:dnsState.Tmpl) {
        # A template with no mode means custom - main and the Python ports
        # both take it that way; leaving it unmanaged deletes the resolver.
        $script:dnsState.Mode = [Array]::IndexOf($script:dnsModes, "custom")
    }
    Enforce-ExclusionGroups
}

# Whether a list from the file holds the same strings as a row's list, in
# any order, compared ordinally as Python's sorted() and == compare them.
# Compare-Object went by the current culture, which skips ignorable
# characters: "https://*" with a soft hyphen (U+00AD) in it matched
# SlimBrave's own wildcard. Sorts copies; the callers' lists stay as they
# were.
function Test-ImportSameList([string[]]$Want, [string[]]$Mine) {
    if ($Want.Length -ne $Mine.Length) { return $false }
    $a = [string[]]$Want.Clone()
    $b = [string[]]$Mine.Clone()
    [Array]::Sort($a, [System.StringComparer]::Ordinal)
    [Array]::Sort($b, [System.StringComparer]::Ordinal)
    for ($i = 0; $i -lt $a.Length; $i++) {
        if (-not [string]::Equals($a[$i], $b[$i], [System.StringComparison]::Ordinal)) { return $false }
    }
    return $true
}

# A Features key or legacy entry no row has, named in the Import status:
# one that differs from a row's key only in letter case, with the spelling
# it needs; one an earlier version offered; and any other as a policy
# SlimBrave Neo does not offer (Format-ImportEntry adds where a DNS name
# belongs). Kept as the file wrote it; only the names a clause shows are
# made safe to show. None is ever written: issue #33 asked for such keys to
# pass through as custom policy, and an elevated tool writing whatever
# machine policy a shared file names is the risk that was declined.
function Add-ImportNameNote([string]$Name, $RowFold, $Retired) {
    $canon = Get-ImportCanonical $Name $RowFold
    if ($null -ne $canon) {
        $script:importMiscased.Add(@($Name, $canon))
    } elseif ($Retired.Contains($Name)) {
        $script:importRetired.Add($Name)
    } else { $script:importUnknown.Add($Name) }
}

# Where a DNS name inside Features belongs: the two policies are set by the
# top-level DnsMode and DnsTemplates, and those two belong at the top level.
function Get-ImportDnsHint([string]$Name) {
    if ([string]::Equals($Name, 'DnsOverHttpsMode', [System.StringComparison]::Ordinal)) { return 'use DnsMode' }
    if ([string]::Equals($Name, 'DnsOverHttpsTemplates', [System.StringComparison]::Ordinal)) { return 'use DnsTemplates' }
    if ([string]::Equals($Name, 'DnsMode', [System.StringComparison]::Ordinal)) { return 'a top-level field' }
    if ([string]::Equals($Name, 'DnsTemplates', [System.StringComparison]::Ordinal)) { return 'a top-level field' }
    return $null
}

# The known name $Name differs from only in letter case, from $Fold (an
# OrdinalIgnoreCase dictionary of each name to itself), or $null. Only a
# printable ASCII name is compared, as the Python scripts compare only an
# ASCII one: OrdinalIgnoreCase alone would take a dotless i for I and a long
# s for S. \z rather than $, which in .NET also matches before a final
# newline.
function Get-ImportCanonical([string]$Name, $Fold) {
    if (-not ($Name -cmatch '^[\x20-\x7E]*\z')) { return $null }
    if ($Fold.ContainsKey($Name)) { return $Fold[$Name] }
    return $null
}

# The three fields of a config, read by their exact names, as the Python
# scripts read them: PSObject.Properties[...] and $cfg.Name ignore letter
# case, so a "features" or a "dnsmode" used to be taken as if spelled right.
# Every other top-level name goes into $Top for the status, as the file
# wrote it: one that differs from a field only in letter case paired with
# the spelling it needs (Found keeps a mis-cased Features for the refusal),
# anything else as not a SlimBrave Neo setting. ConvertFrom-Json refuses two
# names that differ only in case, so a field cannot also be there under
# another spelling. Returns the fields found, by name.
function Read-ImportFields($Cfg, $Top) {
    $fields = @{}
    if (-not ($Cfg -is [System.Management.Automation.PSCustomObject])) { return $fields }
    $fold = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($f in @('Features', 'DnsMode', 'DnsTemplates')) { $fold.Add($f, $f) }
    foreach ($p in $Cfg.PSObject.Properties) {
        $n = $p.Name
        if ($fold.ContainsKey($n) -and [string]::Equals($fold[$n], $n, [System.StringComparison]::Ordinal)) {
            $fields[$n] = $p.Value
            continue
        }
        $canon = Get-ImportCanonical $n $fold
        if ($null -ne $canon) {
            $Top.Case.Add(@($n, $canon))
            if ([string]::Equals($canon, 'Features', [System.StringComparison]::Ordinal)) { $Top.Found = $n }
        } else { $Top.Other.Add($n) }
    }
    return $fields
}

# DnsTemplates as the Python scripts read it: missing, null or "" is no
# template, a string is the template, and an array of strings is joined
# with spaces. Anything else is refused - a 5 used to become the template
# "5" - and so is a template with a control character (C0, DEL, C1, a
# line or paragraph separator, or a bidi control, which the template box
# would draw reordered), as there: no DoH template holds one, and
# Test-DohTemplate would strip the C0 ones and DEL unseen at Apply.
# Returns the template as Text, and as Why the refusal for the Import
# status ($null when there is none).
function Read-ImportTemplate($Value) {
    $text = $Value
    if ($Value -is [array]) {
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($x in $Value) {
            if (-not ($x -is [string])) { return @{ Text = ''; Why = 'DnsTemplates must be a string' } }
            $parts.Add($x)
        }
        $text = $parts -join ' '
    }
    if ($null -eq $text) { return @{ Text = ''; Why = $null } }
    if (-not ($text -is [string])) { return @{ Text = ''; Why = 'DnsTemplates must be a string' } }
    if ($text -cmatch '[\x00-\x1F\x7F-\x9F\u2028\u2029\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]') {
        return @{ Text = ''; Why = 'DnsTemplates contains a control character' }
    }
    return @{ Text = $text; Why = $null }
}

# Text from an imported file as the status shows it, by the one rule the
# Python scripts apply too. Hand-written: ConvertTo-Json in Windows
# PowerShell 5.1 escapes <, >, & and ' its own way. Each UTF-16 code unit
# outside 0x20-0x7E becomes \uXXXX in uppercase hex, a quote \" and a
# backslash \\, so no control, format or line-separator character reaches
# the bar: a newline breaks its line count, a bidi override reorders it. A
# body longer than $Max is cut to $Max - 3 and ends in '...'. Escaping stops
# once the body is past $Max, since a key can be half a megabyte.
function Format-ImportText([string]$Text, [int]$Max) {
    $sb = [System.Text.StringBuilder]::new()
    for ($i = 0; ($i -lt $Text.Length) -and ($sb.Length -le $Max); $i++) {
        $ch = $Text[$i]
        $code = [int]$ch
        if ($code -eq 0x22) {
            [void]$sb.Append('\"')
        } elseif ($code -eq 0x5C) {
            [void]$sb.Append('\\')
        } elseif (($code -lt 0x20) -or ($code -gt 0x7E)) {
            [void]$sb.Append('\u' + $code.ToString('X4'))
        } else { [void]$sb.Append([string]$ch) }
    }
    $body = $sb.ToString()
    if ($body.Length -gt $Max) { $body = $body.Substring(0, $Max - 3) + '...' }
    return $body
}

# A string from the file: always quoted, its escaped body cut at 64.
function Format-ImportString([string]$Text) {
    return '"' + (Format-ImportText $Text 64) + '"'
}

# A name from the file: as it is when it looks like a policy name, quoted
# and escaped otherwise, so that no name can pose as two items, as the
# ' and N more' tail or as another clause.
function Format-ImportName([string]$Name) {
    if ($Name -cmatch '^[A-Za-z0-9_.-]{1,64}\z') { return $Name }
    return Format-ImportString $Name
}

# A value from the file as an item shows it after Key=, or $null where the
# item is the key alone: true and false, null, an integer in decimal (cut at
# 64 like the rest), a string quoted. A fraction, a list or an object is not
# shown, since no two languages print one alike. An integer is an [int] or
# a [long], as Windows PowerShell 5.1 reads JSON: past Int64 its reader
# gives a [decimal] or a [double], which is not shown, and which every
# row's type check refuses as it refuses a fraction - so such a number is
# named by its key alone, under 'the value is not one this policy accepts',
# and a legacy entry of one is left out, as the Python scripts treat an
# integer outside 64 bits. The cut is the shared rule; an Int64's 20
# characters never reach it.
function Format-ImportValue($Value) {
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) {
        if ($Value) { return 'true' }
        return 'false'
    }
    if (($Value -is [int]) -or ($Value -is [long])) {
        $digits = $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
        if ($digits.Length -gt 64) { $digits = $digits.Substring(0, 61) + '...' }
        return $digits
    }
    if ($Value -is [string]) { return Format-ImportString $Value }
    return $null
}

# One item of a value clause: Key=<value>, or the key alone where the value
# is not shown.
function Format-ImportItem([string]$Key, $Value) {
    $shown = Format-ImportValue $Value
    if ($null -eq $shown) { return (Format-ImportName $Key) }
    return (Format-ImportName $Key) + '=' + $shown
}

# The imported file's own name, for the 'Imported from' lead, by the rule
# the Python scripts apply to it: each UTF-16 code unit outside printable
# ASCII as \uXXXX in uppercase hex, unquoted and uncut. A Windows file name
# can hold a bidi override (U+202E), which would reorder the whole status
# bar; it cannot hold a quote or a backslash.
function Format-ImportFileName([string]$Name) {
    # Only what could move, reorder or hide text is escaped, as \uXXXX: the
    # control and bidi characters a template may not hold, the zero-width
    # format characters and a lone surrogate. Any other character, a
    # Cyrillic, CJK or emoji name's included, shows as it is - the Python
    # scripts' _shown_path rule.
    $sb = [System.Text.StringBuilder]::new()
    for ($i = 0; $i -lt $Name.Length; $i++) {
        $ch = $Name[$i]
        $code = [int]$ch
        $unsafe = (($code -lt 0x20) -or (($code -ge 0x7F) -and ($code -le 0x9F)) -or
                   ($code -eq 0x2028) -or ($code -eq 0x2029) -or
                   ($code -eq 0x061C) -or ($code -eq 0x200E) -or ($code -eq 0x200F) -or
                   (($code -ge 0x202A) -and ($code -le 0x202E)) -or
                   (($code -ge 0x2066) -and ($code -le 0x2069)) -or
                   (($code -ge 0x200B) -and ($code -le 0x200D)) -or
                   ($code -eq 0x2060) -or ($code -eq 0xFEFF))
        if ((-not $unsafe) -and [char]::IsSurrogate($ch)) {
            $paired = (([char]::IsHighSurrogate($ch) -and (($i + 1) -lt $Name.Length) -and
                        [char]::IsLowSurrogate($Name[$i + 1])) -or
                       ([char]::IsLowSurrogate($ch) -and ($i -gt 0) -and
                        [char]::IsHighSurrogate($Name[$i - 1])))
            $unsafe = -not $paired
        }
        if ($unsafe) {
            [void]$sb.Append('\u' + $code.ToString('X4'))
        } else { [void]$sb.Append([string]$ch) }
    }
    return $sb.ToString()
}

# One item of a clause, made only when the status is built: $Kind says what
# its list holds. Case: a name and the spelling it needs. Unknown: a name,
# with where a DNS name belongs (or a legacy value's text, which comes out
# as it went in). Name: a name. Item: an item Format-ImportItem made.
function Format-ImportEntry([string]$Kind, $Entry) {
    if ([string]::Equals($Kind, 'Item', [System.StringComparison]::Ordinal)) { return [string]$Entry }
    if ([string]::Equals($Kind, 'Case', [System.StringComparison]::Ordinal)) {
        return (Format-ImportName $Entry[0]) + ' (use ' + $Entry[1] + ')'
    }
    $item = Format-ImportName $Entry
    if ([string]::Equals($Kind, 'Unknown', [System.StringComparison]::Ordinal)) {
        $hint = Get-ImportDnsHint $Entry
        if ($null -ne $hint) { $item = $item + ' (' + $hint + ')' }
    }
    return $item
}

# One clause of the Import status, in the words and order the Python scripts
# use (see the Import handler): ' <Lead>, because <Reason>: <items>.' with at
# most $script:IMPORT_MAX_ITEMS items, in file order, then ' and N more'; ''
# when there is nothing to name. The cap keeps a file naming a thousand keys
# from burying every other clause, and only the items shown are formatted
# (Format-ImportEntry): the rest are only counted.
$script:IMPORT_MAX_ITEMS = 5
function Get-ImportClause([string]$Lead, [string]$Reason, $Items, [string]$Kind) {
    if ($null -eq $Items) { return '' }
    $all = @($Items)
    if ($all.Count -eq 0) { return '' }
    $shown = [math]::Min($all.Count, $script:IMPORT_MAX_ITEMS)
    $parts = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $shown; $i++) { $parts.Add((Format-ImportEntry $Kind $all[$i])) }
    $text = ' ' + $Lead + ', because ' + $Reason + ': ' + ($parts -join ', ')
    if ($all.Count -gt $shown) { $text += ' and ' + ($all.Count - $shown) + ' more' }
    return $text + '.'
}

$F = @{
    Bg=[System.Drawing.Color]::FromArgb(32,32,32);      Rail=[System.Drawing.Color]::FromArgb(27,27,27)
    Row=[System.Drawing.Color]::FromArgb(45,45,45);     RowHot=[System.Drawing.Color]::FromArgb(51,51,51)
    RowEdge=[System.Drawing.Color]::FromArgb(56,56,56); RowTopHi=[System.Drawing.Color]::FromArgb(64,64,64)
    Text=[System.Drawing.Color]::FromArgb(255,255,255); TextSub=[System.Drawing.Color]::FromArgb(160,160,160)
    Accent=[System.Drawing.Color]::FromArgb(76,194,255);AccentDim=[System.Drawing.Color]::FromArgb(40,76,194,255)
    ThumbOn=[System.Drawing.Color]::FromArgb(27,27,27); ThumbOff=[System.Drawing.Color]::FromArgb(206,206,206)
    OutlineOff=[System.Drawing.Color]::FromArgb(154,154,154)
    NavHot=[System.Drawing.Color]::FromArgb(41,41,41);  NavSel=[System.Drawing.Color]::FromArgb(48,48,48)
    Bar=[System.Drawing.Color]::FromArgb(39,39,39)
}


# Segoe MDL2 Assets glyphs, one per nav page
$script:navGlyphs = @([char]0xE9D9, [char]0xE72E, [char]0xE71D, [char]0xE8D7,
                      [char]0xE734, [char]0xE83D, [char]0xE9D2)

# StringFormat that renders "&" literally instead of eating it as a mnemonic
$script:SF = New-Object System.Drawing.StringFormat
$script:SF.HotkeyPrefix = [System.Drawing.Text.HotkeyPrefix]::None
$script:SFw = New-Object System.Drawing.StringFormat
$script:SFw.HotkeyPrefix = [System.Drawing.Text.HotkeyPrefix]::None
$script:SFw.Trimming = [System.Drawing.StringTrimming]::Word

function Add-RoundedPath([System.Drawing.Drawing2D.GraphicsPath]$path,[System.Drawing.RectangleF]$r,[float]$rad){
    $d=$rad*2
    $path.AddArc($r.X,$r.Y,$d,$d,180,90); $path.AddArc($r.Right-$d,$r.Y,$d,$d,270,90)
    $path.AddArc($r.Right-$d,$r.Bottom-$d,$d,$d,0,90); $path.AddArc($r.X,$r.Bottom-$d,$d,$d,90,90)
    $path.CloseFigure()
}
function Enable-DoubleBuffer($c){
    $c.GetType().GetProperty("DoubleBuffered",[System.Reflection.BindingFlags]"Instance,NonPublic").SetValue($c,$true)
}
function Fill-Round([System.Drawing.Graphics]$g,[System.Drawing.RectangleF]$r,[float]$rad,[System.Drawing.Color]$c){
    $p=New-Object System.Drawing.Drawing2D.GraphicsPath; Add-RoundedPath $p $r $rad
    $b=New-Object System.Drawing.SolidBrush $c; $g.FillPath($b,$p); $b.Dispose(); $p.Dispose()
}
function Stroke-Round([System.Drawing.Graphics]$g,[System.Drawing.RectangleF]$r,[float]$rad,[System.Drawing.Color]$c){
    $p=New-Object System.Drawing.Drawing2D.GraphicsPath; Add-RoundedPath $p $r $rad
    $pen=New-Object System.Drawing.Pen $c; $g.DrawPath($pen,$p); $pen.Dispose(); $p.Dispose()
}

Add-Type -TypeDefinition @"
using System.Drawing;
using System.Windows.Forms;
public class DarkMenuColors : ProfessionalColorTable {
    public override Color ToolStripDropDownBackground { get { return Color.FromArgb(51,51,51); } }
    public override Color MenuBorder { get { return Color.FromArgb(70,70,70); } }
    public override Color MenuItemBorder { get { return Color.FromArgb(76,194,255); } }
    public override Color MenuItemSelected { get { return Color.FromArgb(62,62,62); } }
    public override Color MenuItemSelectedGradientBegin { get { return Color.FromArgb(62,62,62); } }
    public override Color MenuItemSelectedGradientEnd { get { return Color.FromArgb(62,62,62); } }
    public override Color ImageMarginGradientBegin { get { return Color.FromArgb(51,51,51); } }
    public override Color ImageMarginGradientMiddle { get { return Color.FromArgb(51,51,51); } }
    public override Color ImageMarginGradientEnd { get { return Color.FromArgb(51,51,51); } }
}
"@ -ReferencedAssemblies System.Drawing, System.Windows.Forms

# An exception that escapes a window handler would otherwise raise .NET's
# "Unhandled exception" dialog, whose Quit button ends the process with every
# staged change in it. Seen once, in a real elevated session, from the DoH
# template box's Leave handler ("Test-DohTemplate is not recognized") - not
# reproduced since, in the harness or in the real dialog loop. Handler errors
# normally print to the console and the window carries on; this makes the
# escaped kind do the same. Pure .NET on purpose: it has to work even when the
# script's own functions are out of reach, which is what that error said.
[System.Windows.Forms.Application]::add_ThreadException([System.Threading.ThreadExceptionEventHandler]{
    param($sender,$e)
    [Console]::Error.WriteLine("SlimBrave Neo: error in a window handler, ignored - " + $e.Exception.Message)
})

$form = New-Object System.Windows.Forms.Form
$form.Text = "SlimBrave Neo（中文版）"
# Design size is 1180x760 at 96 DPI; scaled it is 1770x1140 at 150%, taller
# than a 1080p work area, so the HEIGHT yields to the screen (the page is
# AutoScroll and absorbs it; the bar keeps the bottom edge). Width cannot
# yield - the columns do not reflow - so it is S'd and may overhang.
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
$form.MaximizeBox = $false
# The palette is dark but .NET Framework never asks DWM for a dark title bar,
# so the window opened under Windows' light frame - the P/Invoke for this has
# been declared since the DPI block and never called. Attribute 20 is
# DWMWA_USE_IMMERSIVE_DARK_MODE on Windows 10 20H1+ and 11; builds 1809-1903
# used 19. Best effort: any failure just leaves the light frame.
$form.Add_HandleCreated({
    try {
        $on=1
        if([SlimBrave.DpiHelper]::DwmSetWindowAttribute($this.Handle,20,[ref]$on,4) -ne 0){
            [void][SlimBrave.DpiHelper]::DwmSetWindowAttribute($this.Handle,19,[ref]$on,4)
        }
    } catch {}
})
# Non-client height of THIS window style, from the same AdjustWindowRectEx
# WinForms sizes the window with. SystemInformation.CaptionHeight +
# 2*FixedFrameBorderSize.Height says 29 on Windows 11 where the frame is 39.
$chromeH=$form.Height-$form.ClientSize.Height
# Primary screen on purpose: $script:DPI is the system DPI, i.e. the primary
# monitor's, and the window is placed there below, so size, factor and
# position come from one monitor. Never grows past the design; never
# shrinks below ~4 rows (then it overhangs rather than the page vanishing).
$wa=[System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
# Width has no fallback - the columns do not reflow - so on a screen too
# narrow for S(1180) the FACTOR yields instead: it is clamped to what fits,
# and the fonts, built from the same factor below, shrink with the grid.
# 1920-wide at 175%+ and 1366-wide at 125% are the real cases. Floor 0.75:
# below that the text is unreadable and overhanging is the lesser evil.
# This must run before the first S() call, which is the line after it.
$chromeW=$form.Width-$form.ClientSize.Width
$fitDpi=[double]($wa.Width-$chromeW)/1180.0
if($fitDpi -lt $script:DPI){ $script:DPI=[math]::Max(0.75,$fitDpi) }
$clientH=[math]::Max((S 300),[math]::Min((S 760),($wa.Height-$chromeH)))
$form.ClientSize = New-Object System.Drawing.Size (S 1180), $clientH
# Windows' default placement keeps a window inside the MONITOR, not the work
# area: a work-area-tall window lands with its bottom on the screen edge and
# the action bar under the taskbar (measured: y=48 on 1080p / Windows 11).
# Place it ourselves, centred in the work area the height was clamped to;
# a clamped window gets y = $wa.Y, a shorter one is centred.
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
$form.Location = New-Object System.Drawing.Point ($wa.X+[math]::Max(0,[int](($wa.Width-$form.Width)/2))),($wa.Y+[math]::Max(0,[int](($wa.Height-$form.Height)/2)))
$form.BackColor = $F.Bg
Enable-DoubleBuffer $form

# Fonts are authored in points but built in PIXELS at pt*96/72*$script:DPI -
# exactly what a point font renders as at the system DPI, so at any normal
# scale nothing changes - except that the size follows $script:DPI. That only
# matters when the factor was clamped below the display's own DPI to keep the
# window inside the screen width (form block above): grid and glyphs then
# shrink together instead of the text outgrowing its rows.
$script:zhUiFontFamily = $null
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
}
$script:titleFont=New-UiFont "Segoe UI Semibold" 16
$script:crumbFont=New-UiFont "Segoe UI" 9
$script:navFont  =New-UiFont "Segoe UI" 10
$script:rowFont  =New-UiFont "Segoe UI" 10
$script:capFont  =New-UiFont "Segoe UI" 8.5
$script:btnFont  =New-UiFont "Segoe UI" 9.5
$script:pTitle   =New-UiFont "Segoe UI Semibold" 11
try { $script:iconFont = New-UiFont "Segoe MDL2 Assets" 11 }
catch { $script:iconFont = New-UiFont "Segoe UI" 10 }

# --------------------------------------------------------------- nav rail
$rail=New-Object System.Windows.Forms.Panel
$rail.Location=New-Object System.Drawing.Point 0,0
$rail.Size=New-Object System.Drawing.Size (S 250),$form.ClientSize.Height
# Anchored: WinForms caps Form.Height at MaxWindowTrackSize in the setter while
# ClientSize still reports the request, so the derived sizes must follow the
# client the OS actually grants, not the one asked for.
$rail.Anchor=[System.Windows.Forms.AnchorStyles]"Top,Bottom,Left"
$rail.BackColor=$F.Rail; Enable-DoubleBuffer $rail; $form.Controls.Add($rail); $rail.TabIndex=0

$script:railTitleFont=New-UiFont "Segoe UI Semibold" 15
$script:railSubFont=New-UiFont "Segoe UI" 9

$railHead=New-Object System.Windows.Forms.Panel
$railHead.Location=New-Object System.Drawing.Point 0,(S 14)
$railHead.Size=New-Object System.Drawing.Size (S 250),(S 60)
$railHead.BackColor=$F.Rail
Enable-DoubleBuffer $railHead
$railHead.Add_Paint({
    param($s,$e); $g=$e.Graphics
    $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint=[System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
    $g.Clear($script:F.Rail)
    # accent-tinted app tile with the shield glyph, the same language the nav
    # items use, so the header reads as part of the list rather than a banner
    $tile=New-Object System.Drawing.RectangleF (S 16),(S 8),(S 32),(S 32)
    Fill-Round $g $tile (S 8) $script:F.AccentDim
    $ib=New-Object System.Drawing.SolidBrush $script:F.Accent
    $glyphFont=New-UiFont $script:iconFont.FontFamily 14
    $gl=[char]0xE72E
    $sz=$g.MeasureString($gl,$glyphFont,1000,$script:SF)
    $g.DrawString($gl,$glyphFont,$ib,($tile.X+($tile.Width-$sz.Width)/2),($tile.Y+($tile.Height-$sz.Height)/2),$script:SF)
    $glyphFont.Dispose(); $ib.Dispose()
    $tb=New-Object System.Drawing.SolidBrush $script:F.Text
    $g.DrawString("SlimBrave Neo",$script:railTitleFont,$tb,(S 58),(S 6),$script:SF); $tb.Dispose()
    $sb=New-Object System.Drawing.SolidBrush $script:F.TextSub
    $g.DrawString("策略管理器",$script:railSubFont,$sb,(S 60),(S 31),$script:SF); $sb.Dispose()
})
$rail.Controls.Add($railHead)

# page 0 = Presets, 1..7 = categories, 8 = DNS
$script:pages=@("快捷预设","全部选项")
foreach($c in $script:cats){ $script:pages+=$c.name }
$script:pages+="DNS over HTTPS"
$script:navItems=@(); $script:sel=0

# ---------------------------------------------------------------------------
# Keyboard access
#
# Every interactive control here is an owner-drawn Panel, and a Panel is not
# selectable by default - so nothing but the two TextBoxes could take focus and
# the window was unusable without a mouse. The previous GUI, built from real
# CheckBoxes and Buttons, never had this problem. ControlStyles.Selectable is
# set through the protected SetStyle by reflection; a probe confirmed Paint and
# MouseDown are unaffected by it, so no compiled Panel subclass is needed.
#
# Activation goes through the SAME handler the mouse uses, raised at the centre
# of the control's own hit zone. Click, hover and keyboard then share one code
# path - the way Zone-Of already unified the first two. A separate keyboard
# branch is how the two drift apart.
# ---------------------------------------------------------------------------
$script:miSetStyle    = [System.Windows.Forms.Control].GetMethod('SetStyle',    [Reflection.BindingFlags]'Instance,NonPublic')
$script:miOnMouseDown = [System.Windows.Forms.Control].GetMethod('OnMouseDown', [Reflection.BindingFlags]'Instance,NonPublic')
$script:miOnClick     = [System.Windows.Forms.Control].GetMethod('OnClick',     [Reflection.BindingFlags]'Instance,NonPublic')

function Enable-Focusable($c,[switch]$Arrows){
    # [void]: Invoke on a void method returns $null, and PowerShell EMITS that -
    # without the cast every factory returned @($null, $panel) and the bar's
    # packing loop died setting .Left on an array. Text-level tests cannot see
    # this class of bug; the render harness can.
    [void]$script:miSetStyle.Invoke($c, @([System.Windows.Forms.ControlStyles]::Selectable, $true))
    $c.TabStop = $true
    $c.Add_GotFocus({ $this.Invalidate() })
    # Armed is the activation latch (Add-KeyActivation). A KeyUp swallowed by
    # a dialog must not leave it set for the next press.
    $c.Add_LostFocus({ $this.Tag.Armed=$false; $this.Invalidate() })
    # Return is a dialog key - the form would eat it as navigation before
    # KeyDown ever saw it. Left and Right are too, but only rows use them; on
    # the rail and the bar they fall through to WinForms' own arrow movement.
    $c.Add_PreviewKeyDown({
        param($s,$e)
        if($e.KeyCode -eq [System.Windows.Forms.Keys]::Return){ $e.IsInputKey = $true }
    })
    if($Arrows){
        $c.Add_PreviewKeyDown({
            param($s,$e)
            if($e.KeyCode -eq [System.Windows.Forms.Keys]::Left -or
               $e.KeyCode -eq [System.Windows.Forms.Keys]::Right){ $e.IsInputKey = $true }
        })
    }
}

function Invoke-MouseAt($c, [int]$x, [int]$y){
    # ::new(), not New-Object: New-Object hands back a PSObject wrapper, and
    # reflection's Invoke will not convert that to MouseEventArgs.
    $mea = [System.Windows.Forms.MouseEventArgs]::new([System.Windows.Forms.MouseButtons]::Left, 1, $x, $y, 0)
    [void]$script:miOnMouseDown.Invoke($c, [object[]]@($mea))
}

function Invoke-ClickOn($c){
    [void]$script:miOnClick.Invoke($c, @([System.EventArgs]::Empty))
}

function Test-ActivateKey($ev){
    return ($ev.KeyCode -eq [System.Windows.Forms.Keys]::Space -or
            $ev.KeyCode -eq [System.Windows.Forms.Keys]::Return)
}

function Add-KeyActivation($c,[scriptblock]$fire){
    # Arm on KeyDown, fire on KeyUp - a real Win32 button's own pattern.
    # KeyDown auto-repeats while a key is held and KeyUp never does, so a held
    # Space flips a toggle once instead of every repeat tick, and a held Enter
    # on Reset cannot answer its own confirm box: the Enter that dismisses a
    # dialog delivers its KeyUp to the button underneath, and the latch,
    # cleared before firing, ignores it.
    $c.Tag.Fire=$fire
    $c.Add_KeyDown({
        param($s,$ev)
        if(Test-ActivateKey $ev){ $s.Tag.Armed=$true; $ev.Handled=$true; $ev.SuppressKeyPress=$true }
    })
    $c.Add_KeyUp({
        param($s,$ev)
        if((Test-ActivateKey $ev) -and $s.Tag.Armed){
            $s.Tag.Armed=$false
            & $s.Tag.Fire $s
            $ev.Handled=$true
        }
    })
}

function Draw-FocusRing($g, $w, $h, $col=$null){
    # Distinct from hover: hover fills, focus outlines. A keyboard user must be
    # able to tell where they are on a row the mouse is also sitting on.
    # Anti-aliasing turns a 1px dotted line on integer coordinates into a solid
    # half-strength one, so it is off for the ring alone.
    if($null -eq $col){ $col=$script:F.Accent }
    $sm=$g.SmoothingMode
    $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::None
    $p = New-Object System.Drawing.Pen $col, 1
    $p.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dot
    $g.DrawRectangle($p, 1, 1, ($w - 3), ($h - 3))
    $p.Dispose()
    $g.SmoothingMode=$sm
}

function New-NavItem([int]$idx,[string]$name,[int]$y){
    $it=New-Object System.Windows.Forms.Panel
    $it.Location=New-Object System.Drawing.Point (S 8),$y
    $it.Size=New-Object System.Drawing.Size (S 234),(S 36)
    $it.BackColor=$F.Rail; $it.Tag=@{Idx=$idx;Name=$name;Hot=$false}
    Enable-DoubleBuffer $it
    $it.Add_Paint({
        param($s,$e); $g=$e.Graphics
    $g.TextRenderingHint=[System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
        $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $st=$s.Tag; $g.Clear($script:F.Rail)
        $isSel=($st.Idx -eq $script:sel)
        if($isSel -or $st.Hot){
            $c=$script:F.NavHot; if($isSel){$c=$script:F.NavSel}
            Fill-Round $g (New-Object System.Drawing.RectangleF 0,0,($s.Width-1),($s.Height-1)) (S 5) $c
        }
        if($isSel){ $b=New-Object System.Drawing.SolidBrush $script:F.Accent
                    $g.FillRectangle($b,0,(S 10),(S 3),(S 16)); $b.Dispose() }
        $glyph=[char]0xE713
        if($st.Idx -eq 0){ $glyph=[char]0xE7BE }
        elseif($st.Idx -eq 1){ $glyph=[char]0xE8FD }
        elseif(($st.Idx-2) -lt $script:navGlyphs.Count){ $glyph=$script:navGlyphs[$st.Idx-2] }
        else { $glyph=[char]0xE968 }
        $ib=New-Object System.Drawing.SolidBrush $script:F.Accent
        $g.DrawString($glyph,$script:iconFont,$ib,(S 14),(S 8),$script:SF); $ib.Dispose()
        $ink=$script:F.TextSub; if($isSel){$ink=$script:F.Text}
        $nb=New-Object System.Drawing.SolidBrush $ink
        $g.DrawString($st.Name,$script:navFont,$nb,(S 44),(S 9),$script:SF); $nb.Dispose()
        if($s.Focused){ Draw-FocusRing $g $s.Width $s.Height }
    })
    $it.Add_MouseEnter({$this.Tag.Hot=$true;$this.Invalidate()})
    $it.Add_MouseLeave({$this.Tag.Hot=$false;$this.Invalidate()})
    $it.Add_Click({
        if($script:searchBox -and $script:searchBox.Text){ $script:searchBox.Text="" }
        Select-Page $this.Tag.Idx
    })
    Add-KeyActivation $it { param($s) Invoke-ClickOn $s }
    Enable-Focusable $it
    $it.AccessibleName=$name; $it.AccessibleRole=[System.Windows.Forms.AccessibleRole]::ListItem
    $it.Cursor=[System.Windows.Forms.Cursors]::Hand
    $rail.Controls.Add($it); return $it
}
$yy=S 88
for($i=0;$i -lt $script:pages.Count;$i++){
    $script:navItems+=(New-NavItem $i $script:pages[$i] $yy); $yy+=S 40
}

# --------------------------------------------------------------- header
$crumb=New-Object System.Windows.Forms.Label
$crumb.Font=$script:crumbFont; $crumb.ForeColor=$F.TextSub; $crumb.BackColor=$F.Bg
$crumb.Location=New-Object System.Drawing.Point (S 282),(S 18); $crumb.AutoSize=$true
$crumb.UseMnemonic=$false; $form.Controls.Add($crumb)

$pageTitle=New-Object System.Windows.Forms.Label
$pageTitle.Font=$script:titleFont; $pageTitle.ForeColor=$F.Text; $pageTitle.BackColor=$F.Bg
$pageTitle.Location=New-Object System.Drawing.Point (S 280),(S 38); $pageTitle.AutoSize=$true
$pageTitle.UseMnemonic=$false; $form.Controls.Add($pageTitle)

# Search box. Sits in the header so it is reachable from any page, not just
# All Options - a policy you cannot name is exactly the one you need to find.
$searchHost=New-Object System.Windows.Forms.Panel
$searchHost.Location=New-Object System.Drawing.Point (S 880),(S 34)
$searchHost.Size=New-Object System.Drawing.Size (S 272),(S 32)
$searchHost.BackColor=$F.Bg
Enable-DoubleBuffer $searchHost
$searchHost.Add_Paint({
    param($s,$e); $g=$e.Graphics
    $g.TextRenderingHint=[System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
    $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear($script:F.Bg)
    $r=New-Object System.Drawing.RectangleF 0,0,($s.Width-1),($s.Height-1)
    Fill-Round $g $r (S 4) $script:F.Row
    $edge=$script:F.RowEdge
    if($script:searchBox -and $script:searchBox.Focused){ $edge=$script:F.Accent }
    Stroke-Round $g $r (S 4) $edge
    $ib=New-Object System.Drawing.SolidBrush $script:F.TextSub
    $gl=[char]0xE721
    $g.DrawString($gl,$script:iconFont,$ib,(S 9),(S 7),$script:SF); $ib.Dispose()
    if(-not $script:searchBox -or [string]::IsNullOrEmpty($script:searchBox.Text)){
        $pb=New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(110,110,110))
        $g.DrawString("搜索策略名称、说明或 Key...",$script:capFont,$pb,(S 34),(S 9),$script:SF)
        $pb.Dispose()
    }
})
$form.Controls.Add($searchHost); $searchHost.TabIndex=1

$script:searchBox=New-Object System.Windows.Forms.TextBox
$script:searchBox.BorderStyle=[System.Windows.Forms.BorderStyle]::None
$script:searchBox.Font=$script:rowFont
$script:searchBox.BackColor=$F.Row
$script:searchBox.ForeColor=$F.Text
$script:searchBox.Location=New-Object System.Drawing.Point (S 34),(S 8)
$script:searchBox.Size=New-Object System.Drawing.Size (S 228),(S 20)
$searchHost.Controls.Add($script:searchBox)
$script:searchBox.Add_GotFocus({ $searchHost.Invalidate() })
$script:searchBox.Add_LostFocus({ $searchHost.Invalidate() })
$script:searchBox.AccessibleName="搜索策略名称、说明或 Key..."

$page=New-Object System.Windows.Forms.Panel
$page.Location=New-Object System.Drawing.Point (S 270),(S 80)
$page.Size=New-Object System.Drawing.Size (S 900),($form.ClientSize.Height-(S 152))   # 80 above, 68 bar, 4 gap
$page.Anchor=[System.Windows.Forms.AnchorStyles]"Top,Bottom,Left"
$page.BackColor=$F.Bg; $page.AutoScroll=$true
Enable-DoubleBuffer $page; $form.Controls.Add($page); $page.TabIndex=2

# --------------------------------------------------------------- action bar
$bar=New-Object System.Windows.Forms.Panel
$bar.Location=New-Object System.Drawing.Point (S 250),($form.ClientSize.Height-(S 68))
$bar.Size=New-Object System.Drawing.Size (S 930),(S 68)
$bar.Anchor=[System.Windows.Forms.AnchorStyles]"Bottom,Left"
$bar.BackColor=$F.Bar; Enable-DoubleBuffer $bar; $form.Controls.Add($bar); $bar.TabIndex=3
$script:statusText="就绪"
$script:BAR_PAD=S 20   # status text left margin, button row right margin
$script:BAR_GAP=S 8    # between buttons
$script:barButtonsLeft=$bar.Width   # x of the leftmost button, set once the row is built
$script:barTip=New-Object System.Windows.Forms.ToolTip
# The tooltip carries the full status when the bar had to cut it. The 5 s
# default hid a 161-character repair note before it could be read; 30 s is
# just under the control's cap.
$script:barTip.AutoPopDelay=30000; $script:barTip.InitialDelay=300; $script:barTip.ReshowDelay=100
$bar.Add_Paint({
    param($s,$e); $g=$e.Graphics
    $g.TextRenderingHint=[System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
    $p=New-Object System.Drawing.Pen $script:F.RowEdge
    $g.DrawLine($p,0,0,$s.Width,0); $p.Dispose()
    # The buttons are child panels, so status text drawn past the leftmost
    # one lands on the bar behind them and shows through the gaps between
    # them (issue #20). Draw it into the room before that button instead.
    # Set-Status has already grown the bar to fit the message, so this draws
    # into whatever height that produced and only ellipsises past the cap.
    $room=$script:barButtonsLeft-(2*$script:BAR_PAD)
    $lineH=$g.MeasureString("Ag",$script:capFont,10000,$script:SF).Height
    # As many lines as the bar's CURRENT height holds - Set-Status has already
    # grown the bar to fit the message, so this is normally all of it. The
    # ellipsis and tooltip below are a last resort past the four-line cap,
    # not the channel for anything a user has to act on.
    $lines=[math]::Max(1,[math]::Min($script:BAR_MAX_LINES,[math]::Floor(($s.Height-(S 12))/$lineH)))
    $boxH=[int][math]::Ceiling($lineH*$lines)
    $rect=New-Object System.Drawing.RectangleF $script:BAR_PAD,(($s.Height/2)-($boxH/2)),([math]::Max($room,0)),$boxH
    $fmt=New-Object System.Drawing.StringFormat $script:SF
    $fmt.Trimming=[System.Drawing.StringTrimming]::EllipsisWord
    $fmt.FormatFlags=[System.Drawing.StringFormatFlags]::LineLimit
    $fmt.LineAlignment=[System.Drawing.StringAlignment]::Center
    # A zero-width rect makes MeasureString report everything as fitted,
    # hence the explicit $room guard.
    $fit=0; $nl=0
    [void]$g.MeasureString($script:statusText,$script:capFont,$rect.Size,$fmt,[ref]$fit,[ref]$nl)
    $tip=""
    if($room -le 0 -or $fit -lt $script:statusText.Length){
        # A WinForms ToolTip never wraps on its own - it sends no
        # TTM_SETMAXTIPWIDTH and exposes no max width - so a 350-character
        # Apply status rendered as one ~1800 px line. Break it on words; the
        # control does honour embedded newlines.
        $ln=@(); $cur=""; $curW=0
        foreach($ch in $script:statusText.ToCharArray()){
            $cw=$(if([int]$ch -ge 0x2E80){2}else{1})
            if($curW + $cw -gt 84 -and $cur.Length -gt 0){ $ln+=$cur; $cur=""; $curW=0 }
            $cur+=$ch; $curW+=$cw
        }
        if($cur){ $ln+=$cur }
        $tip=($ln -join "`r`n")
    }
    if($script:barTip.GetToolTip($s) -ne $tip){ $script:barTip.SetToolTip($s,$tip) }
    $b=New-Object System.Drawing.SolidBrush $script:F.TextSub
    if($room -gt 0){ $g.DrawString($script:statusText,$script:capFont,$b,$rect,$fmt) }
    $b.Dispose(); $fmt.Dispose()
})
$script:BAR_MAX_LINES=4
function Set-Status([string]$t){
    # The bar grows to fit its message rather than hiding the tail behind a
    # hover: after Apply, the part that says "close Brave and run this again"
    # is exactly the part that used to end up as "...". Up to four lines; the
    # page above gives up the room (it is AutoScroll, nothing is lost) and the
    # buttons stay centred. At two lines or fewer the bar is its usual S 68,
    # so ordinary messages change nothing.
    $script:statusText=$t
    $room=$script:barButtonsLeft-(2*$script:BAR_PAD)
    $need=S 68
    if($room -gt 0){
        $g=$bar.CreateGraphics()
        $fmt=New-Object System.Drawing.StringFormat $script:SF
        $lineH=$g.MeasureString("Ag",$script:capFont,10000,$script:SF).Height
        $fit=0; $nl=0
        [void]$g.MeasureString($t,$script:capFont,(New-Object System.Drawing.SizeF $room,10000),$fmt,[ref]$fit,[ref]$nl)
        $fmt.Dispose(); $g.Dispose()
        $nl=[math]::Max(1,[math]::Min($script:BAR_MAX_LINES,$nl))
        $need=[math]::Max((S 68),([int][math]::Ceiling($nl*$lineH)+(S 24)))
    }
    if($bar.Height -ne $need){
        $bar.Top=$form.ClientSize.Height-$need
        $bar.Height=$need
        foreach($c in $bar.Controls){ $c.Top=[int](($need-$c.Height)/2) }
        if($null -ne $page){ $page.Height=$bar.Top-$page.Top-(S 4) }
    }
    $bar.Invalidate()
}

function New-BarButton([string]$label,[bool]$accent){
    $disp = Get-ZhButton $label
    $b=New-Object System.Windows.Forms.Panel
    $w=[int]([System.Windows.Forms.TextRenderer]::MeasureText($disp,$script:btnFont).Width+(S 34))
    $b.Location=New-Object System.Drawing.Point 0,(S 18)   # x is placed by the caller once the width is known
    $b.Size=New-Object System.Drawing.Size $w,(S 32)
    $b.BackColor=$F.Bar; $b.Tag=@{Id=$label;L=$disp;A=$accent;Hot=$false}
    Enable-DoubleBuffer $b
    $b.Add_Paint({
        param($s,$e); $g=$e.Graphics
    $g.TextRenderingHint=[System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
        $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.Clear($script:F.Bar)
        $r=New-Object System.Drawing.RectangleF 0,0,($s.Width-1),($s.Height-1)
        if($s.Tag.A){
            $c=$script:F.Accent; if($s.Tag.Hot){$c=[System.Drawing.Color]::FromArgb(96,205,255)}
            Fill-Round $g $r (S 4) $c; $ink=[System.Drawing.Color]::FromArgb(27,27,27)
        } else {
            $c=$script:F.Row; if($s.Tag.Hot){$c=$script:F.RowHot}
            Fill-Round $g $r (S 4) $c; Stroke-Round $g $r (S 4) $script:F.RowEdge; $ink=$script:F.Text
        }
        $tb=New-Object System.Drawing.SolidBrush $ink
        $sz=$g.MeasureString($s.Tag.L,$script:btnFont,1000,$script:SF)
        $g.DrawString($s.Tag.L,$script:btnFont,$tb,(($s.Width-$sz.Width)/2),(($s.Height-$sz.Height)/2),$script:SF)
        $tb.Dispose()
        # accent pen on the accent fill is invisible: the ring takes the ink
        if($s.Focused){ Draw-FocusRing $g $s.Width $s.Height $(if($s.Tag.A){$ink}else{$script:F.Accent}) }
    })
    $b.Add_MouseEnter({$this.Tag.Hot=$true;$this.Invalidate()})
    $b.Add_MouseLeave({$this.Tag.Hot=$false;$this.Invalidate()})
    $b.Add_Click({
        switch($this.Tag.Id){
            "Apply Settings" { if(Invoke-ApplyPolicy){ $script:applied=Get-StateSnapshot; Refresh-View } }
            "Reset" {
                $ans=[System.Windows.Forms.MessageBox]::Show(
                    "确定移除 SlimBrave Neo 管理的所有策略？由组策略或其他工具设置的策略将保持不变。",
                    "确认重置",[System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Warning)
                if($ans -eq "Yes"){ if(Invoke-ResetPolicy){ $script:applied=Get-StateSnapshot; Refresh-View } }
            }
            "Re-sync" { Sync-FromRegistry; $script:applied=Get-StateSnapshot; Refresh-View }
            "Export" {
                $dlg=New-Object System.Windows.Forms.SaveFileDialog
                $dlg.Filter="JSON 配置文件 (*.json)|*.json"
                $dlg.InitialDirectory=Get-InvokerDocs
                $dlg.FileName="SlimBraveNeoSettings.json"
                if($dlg.ShowDialog() -eq "OK"){
                    $feat=@{}
                    foreach($row in Get-AllRows){
                        $v=Get-RowPolicyValue $row
                        if($null -ne $v){ $feat[$row.key]=$v }
                    }
                    $out=@{Features=$feat}
                    $m=$script:dnsModes[$script:dnsState.Mode]
                    if($m -ne "unmanaged"){
                        $out.DnsMode=$m
                        # Only the modes that actually write it. off/automatic
                        # with a template is a combination Apply drops; the
                        # Linux CLI rejects only off with --doh-templates.
                        if($script:dnsState.Tmpl -and ($m -eq "custom" -or $m -eq "secure")){ $out.DnsTemplates=$script:dnsState.Tmpl }
                    }
                    # Set-Content failure is NON-terminating, so without this
                    # the success status ran even when nothing was written -
                    # a locked, read-only or full target reported "Exported".
                    # Only the write sits inside the try. A handler that runs
                    # while a try block is active anywhere up the chain turns
                    # its own errors into the .NET crash dialog instead of
                    # console text, and Set-Status repaints the bar.
                    $err=$null
                    try{
                        [System.IO.File]::WriteAllText($dlg.FileName,
                            ($out | ConvertTo-Json -Depth 5),
                            (New-Object System.Text.UTF8Encoding $false))
                    } catch { $err=$_.Exception.Message }
                    if($null -eq $err){ Set-Status ([string]::Format($script:zhData.ui.status.exported_fmt, $feat.Count)) }
                    else { Set-Status ([string]::Format($script:zhData.ui.status.export_failed_fmt, $err)) }
                }
            }
            "Import" {
                $dlg=New-Object System.Windows.Forms.OpenFileDialog
                $dlg.Filter="JSON 配置文件 (*.json)|*.json"
                $dlg.InitialDirectory=Get-InvokerDocs
                if($dlg.ShowDialog() -eq "OK"){
                    $ok=$false
                    # Import-PresetIntoState clears every row before it reads the
                    # file, so anything that throws part-way would leave the
                    # selections wiped behind 'Import failed'. The catch puts this
                    # copy back: 'Import failed' always means nothing changed.
                    $snap=@{}
                    foreach($id in @($script:state.Keys)){ $snap[$id]=@{On=$script:state[$id].On; Sel=$script:state[$id].Sel} }
                    $dnsSnap=@{Mode=$script:dnsState.Mode; Tmpl=$script:dnsState.Tmpl}
                    # What the top level carries besides the three fields, for the
                    # status (Read-ImportFields fills it; Case holds pairs), and
                    # why an import failed when that is more than 'not a SlimBrave
                    # config': a case-only duplicate ($dupWhy) or another reason
                    # the file is refused ($failWhy).
                    $top=@{Case=[System.Collections.Generic.List[object]]::new(); Other=[System.Collections.Generic.List[string]]::new(); Found=""}
                    $dupWhy=$null
                    $failWhy=$null
                    try{
                        # ReadAllText reads UTF-8 by default and honours a UTF-8,
                        # UTF-16 or UTF-32 BOM, so the BOM-less UTF-8 Export writes
                        # and older UTF-16 exports both read back unchanged.
                        $cfg=[System.IO.File]::ReadAllText($dlg.FileName) | ConvertFrom-Json
                        # Features, DnsMode and DnsTemplates count only in their
                        # exact letter case, as in the Python scripts.
                        $field=Read-ImportFields $cfg $top
                        # ConvertFrom-Json only throws on malformed JSON. Any other
                        # .json - a bookmarks dump, "[]", a bare string - parses fine,
                        # and Import-PresetIntoState clears every staged row BEFORE it
                        # looks for Features, so without this guard a wrong file wiped
                        # the selections and still reported "Imported". Features must
                        # be an object or a legacy array; a scalar is refused too. The
                        # full type name, never [pscustomobject], which matches almost
                        # anything. The throw lands in the catch below, which is the
                        # honest message.
                        if(-not ($cfg -is [System.Management.Automation.PSCustomObject]) -or
                           -not $field.ContainsKey('Features') -or
                           $null -eq $cfg.Features -or
                           -not (($cfg.Features -is [System.Management.Automation.PSCustomObject]) -or ($cfg.Features -is [array]))){ throw "no Features block" }
                        # A DnsTemplates the Python scripts refuse is refused here
                        # too, with their reason, before any row is touched
                        # (Read-ImportTemplate).
                        $template=Read-ImportTemplate $field['DnsTemplates']
                        if($null -ne $template.Why){ $failWhy=$template.Why; throw $failWhy }
                        Import-PresetIntoState @{features=$cfg.Features;dns=$field['DnsMode'];tmpl=$template.Text}
                        $ok=$true
                    } catch {
                        # Windows PowerShell keeps a JSON object as a PSObject, whose
                        # property names ignore letter case, so ConvertFrom-Json
                        # refuses a file naming "a" and "A" in one object, at any
                        # depth. The error id is the same in every language; the
                        # message, which names both keys, is in the user's.
                        if([string]$_.FullyQualifiedErrorId -like 'DuplicateKeysInJsonString,*'){ $dupWhy=[string]$_.Exception.Message }
                        # Nor can a PSObject have a property named "", at any depth:
                        # 5.1's ConvertFrom-Json looks each key up in Properties[...]
                        # (PopulateFromDictionary in the non-CoreCLR JsonObject.cs),
                        # whose indexer throws PSArgumentException for its parameter
                        # 'name', error id Argument. On that path only an empty name
                        # throws it (the reserved names fail as ReservedMemberName or
                        # as a duplicate); PowerShell 7 says EmptyKeyInJsonString.
                        if(([string]$_.FullyQualifiedErrorId -like 'Argument,*.ConvertFromJsonCommand') -and
                           ($_.Exception -is [System.Management.Automation.PSArgumentException]) -and
                           [string]::Equals([string]$_.Exception.ParamName, 'name', [System.StringComparison]::Ordinal)){ $failWhy="a key is empty" }
                        foreach($id in @($snap.Keys)){ $script:state[$id].On=$snap[$id].On; $script:state[$id].Sel=$snap[$id].Sel }
                        $script:dnsState.Mode=$dnsSnap.Mode; $script:dnsState.Tmpl=$dnsSnap.Tmpl
                        $ok=$false
                    }
                    # The rebuild and the status run OUTSIDE the try: a handler
                    # that fires while a try block is active anywhere up the
                    # chain turns its own errors into the .NET crash dialog.
                    if($ok){
                        Refresh-View
                        # The file's name is escaped as the Python scripts escape it.
                        $lead=[string]::Format($script:zhData.ui.status.imported_from_fmt, (Format-ImportFileName ([System.IO.Path]::GetFileName($dlg.FileName))))
                        $tail=''
                        # Everything the file carries that nothing took, in the
                        # Python scripts' reasons and fixed order, each clause in
                        # file order (Get-ImportClause), its kind saying how its
                        # list is shown (Format-ImportEntry). Features items come
                        # first, then the DnsMode note, then the other top-level
                        # fields: a name in the wrong case inside Features comes
                        # before one at the top level, and an unknown DnsMode
                        # after the Features values.
                        $tail+=Get-ImportClause 'Left unmanaged' 'names are case-sensitive' (@($script:importMiscased)+@($top.Case)) 'Case'
                        $tail+=Get-ImportClause 'Left unmanaged' 'the value is not one this policy accepts' $script:importNotes 'Item'
                        $tail+=Get-ImportClause 'Left unmanaged' 'no row sets that value' $script:importUnwritten 'Item'
                        $tail+=Get-ImportClause 'Left unmanaged' 'SlimBrave Neo no longer offers it' $script:importRetired 'Name'
                        $tail+=Get-ImportClause 'Left unmanaged' 'SlimBrave Neo does not offer it' $script:importUnknown 'Unknown'
                        $tail+=Get-ImportClause 'Ignored' 'it is not a SlimBrave Neo setting' $top.Other 'Name'
                        # Unique: two rows can share a key and name it twice.
                        # Sorted and not capped, as before: a group drops a key
                        # only where its rows carry two keys (spellcheck and
                        # shields today).
                        if($script:importConflicts.Count -gt 0){
                            $tail+=" Left unmanaged, because it is mutually exclusive with another imported row: "+(($script:importConflicts | Sort-Object -Unique) -join ", ")+"."
                        }
                        # A full stop ends the lead when a clause follows, so the bar reads as
                        # sentences; the Python scripts join their clauses with '; ' instead.
                        if($tail){ $msg=$lead+'.'+$tail } else { $msg=$lead }
                        Set-Status $msg
                    } else {
                        # A case-only duplicate is said as such, with the error's
                        # own text made safe; so is an empty key and a DnsTemplates
                        # refused; a Features in the wrong case is named.
                        $why="not a SlimBrave config"
                        if($null -ne $dupWhy){
                            $why="keys differ only in letter case"
                            if($dupWhy){ $why+=": "+(Format-ImportText $dupWhy 300) }
                        } elseif($failWhy){
                            $why=$failWhy
                        } elseif($top.Found){ $why+=" (found "+(Format-ImportName $top.Found)+"; names are case-sensitive)" }
                        Set-Status ([string]::Format($script:zhData.ui.status.import_failed_fmt, $why))
                    }
                }
            }
        }
    })
    Add-KeyActivation $b { param($s) Invoke-ClickOn $s }
    Enable-Focusable $b
    $b.AccessibleName=$disp; $b.AccessibleRole=[System.Windows.Forms.AccessibleRole]::PushButton
    $b.Cursor=[System.Windows.Forms.Cursors]::Hand
    $bar.Controls.Add($b); return $b
}
# Packed from the bar's right edge leftward. Button widths come from the
# rendered label, so the row's width follows the text - laid out left-to-right
# from a fixed x it ran off the form above 100% (issue #20). Anchored right it
# grows into the free middle instead, and the status text takes what is left.
$specs=@(@("Export",$false),@("Import",$false),@("Re-sync",$false),@("Reset",$false),@("Apply Settings",$true))
$bx=$bar.Width-$script:BAR_PAD
for($i=$specs.Count-1;$i -ge 0;$i--){
    $btn=New-BarButton $specs[$i][0] $specs[$i][1]
    $btn.TabIndex=$i   # Tab walks the bar in visual order, Export first
    $bx-=$btn.Width; $btn.Left=$bx; $bx-=$script:BAR_GAP
}
$script:barButtonsLeft=$bx+$script:BAR_GAP

# --------------------------------------------------------------- rows
$script:rowPanels=@()
$script:COLLAPSED=S 64
$script:EXP_X=S 690        # chevron column on toggle rows
$script:EXP_X_CHOICE=S 596 # chevron column on dropdown rows
$script:DD_X=S 640         # dropdown control left edge
$script:DD_W=S 180         # dropdown control width
$script:TG_X=S 768         # toggle pill left edge
$script:TG_Y=S 22          # toggle pill top
$script:TG_W=S 44
$script:TG_H=S 20
$script:TG_PAD=S 10        # generous hit padding around the pill

function Get-CapWidth($isChoice){
    # room a caption has before it reaches that row type's chevron column.
    # Choice rows lose ~100px to the dropdown, so a fixed character count
    # cannot serve both - it either wastes space on toggles or overruns
    # into the dropdown on permissions rows.
    if($isChoice){ return ($script:EXP_X_CHOICE-(S 34)) }
    return ($script:EXP_X-(S 34))
}

function Fit-Text([System.Drawing.Graphics]$g,[string]$text,[System.Drawing.Font]$font,[int]$w){
    if($g.MeasureString($text,$font,10000,$script:SF).Width -le $w){ return $text }
    $lo=0; $hi=$text.Length
    while($lo -lt $hi){
        $mid=[int](($lo+$hi+1)/2)
        $try=$text.Substring(0,$mid)+"..."
        if($g.MeasureString($try,$font,10000,$script:SF).Width -le $w){ $lo=$mid } else { $hi=$mid-1 }
    }
    return $text.Substring(0,$lo)+"..."
}

function Zone-Of($panel,[int]$x,[int]$y){
    $st=$panel.Tag
    $ecol=$script:EXP_X; if($st.IsChoice){ $ecol=$script:EXP_X_CHOICE }
    # Whether a row has a chevron is fixed once the GUI is built - the text,
    # the font and the cap width never change - but this measured it on every
    # MouseMove, taking an HDC each time. Cache it on the panel's own Tag.
    if($null -eq $st.HasExp){
        $g2=$panel.CreateGraphics()
        $st.HasExp = [bool]($st.Row.full -and ($st.Row.full -ne $st.Row.short -or
            $g2.MeasureString($st.Row.short,$script:capFont,10000,$script:SF).Width -gt (Get-CapWidth $st.IsChoice)))
        $g2.Dispose()
    }
    $hasExp = $st.HasExp
    if($hasExp -and $x -ge $ecol -and $x -le ($ecol+(S 26)) -and $y -ge (S 14) -and $y -le (S 50)){ return "exp" }
    if($st.IsChoice){
        # bounded exactly like the toggle: clicking a label or empty space
        # must do nothing on BOTH row types. Only the control is live.
        $dl=$script:DD_X-$script:TG_PAD; $dr2=$script:DD_X+$script:DD_W+$script:TG_PAD
        if($x -ge $dl -and $x -le $dr2 -and $y -ge ((S 17)-$script:TG_PAD) -and $y -le ((S 47)+$script:TG_PAD)){ return "ctl" }
        return ""
    }
    $l=$script:TG_X-$script:TG_PAD; $r=$script:TG_X+$script:TG_W+$script:TG_PAD
    $tp=$script:TG_Y-$script:TG_PAD;  $b=$script:TG_Y+$script:TG_H+$script:TG_PAD
    if($x -ge $l -and $x -le $r -and $y -ge $tp -and $y -le $b){ return "ctl" }
    return ""
}

function New-FluentRow($row,[int]$y){
    $p=New-Object System.Windows.Forms.Panel
    $p.Location=New-Object System.Drawing.Point (S 2),$y
    $p.Size=New-Object System.Drawing.Size (S 840),$script:COLLAPSED
    $p.BackColor=$F.Bg
    $isChoice=($null -ne $row.PSObject.Properties['choices'])
    $p.Tag=@{Row=$row;Hot=$false;IsChoice=$isChoice;Open=$false;Zone=''}
    $p.AccessibleName=$row.name; $p.AccessibleDescription=$row.full
    $p.AccessibleRole=$(if($isChoice){[System.Windows.Forms.AccessibleRole]::ComboBox}else{[System.Windows.Forms.AccessibleRole]::CheckButton})
    Enable-DoubleBuffer $p
    $p.Add_Paint({
        param($s,$e); $g=$e.Graphics
        $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint=[System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
        $st=$s.Tag; $g.Clear($script:F.Bg)
        $r=New-Object System.Drawing.RectangleF 0,0,($s.Width-1),($s.Height-2)
        $c=$script:F.Row; if($st.Hot){$c=$script:F.RowHot}
        Fill-Round $g $r (S 6) $c; Stroke-Round $g $r (S 6) $script:F.RowEdge
        $hi=New-Object System.Drawing.Pen $script:F.RowTopHi
        $g.DrawLine($hi,(S 7),1,($s.Width-(S 8)),1); $hi.Dispose()
        $tb=New-Object System.Drawing.SolidBrush $script:F.Text
        $g.DrawString($st.Row.name,$script:rowFont,$tb,(S 18),(S 11),$script:SF); $tb.Dispose()
        $cb=New-Object System.Drawing.SolidBrush $script:F.TextSub
        if($st.Open){
            $wcol=$script:EXP_X; if($st.IsChoice){ $wcol=$script:EXP_X_CHOICE }
            $rect=New-Object System.Drawing.RectangleF (S 18),(S 33),($wcol-(S 30)),($s.Height-(S 42))
            $g.DrawString($st.Row.full,$script:capFont,$cb,$rect,$script:SFw)
        } else {
            $avail=Get-CapWidth $st.IsChoice
            $short=Fit-Text $g $st.Row.short $script:capFont $avail
            $g.DrawString($short,$script:capFont,$cb,(S 18),(S 34),$script:SF)
        }
        $cb.Dispose()
        # expander chevron, only when there is more to show
        $avail2=Get-CapWidth $st.IsChoice
        $truncated=($g.MeasureString($st.Row.short,$script:capFont,10000,$script:SF).Width -gt $avail2)
        if($st.Row.full -and ($st.Row.full -ne $st.Row.short -or $truncated)){
            $ecol=$script:EXP_X; if($st.IsChoice){ $ecol=$script:EXP_X_CHOICE }
            $ex=New-Object System.Drawing.RectangleF $ecol,(S 18),(S 26),(S 26)
            if($st.Zone -eq "exp"){ Fill-Round $g $ex (S 4) $script:F.RowTopHi }
            $cp=New-Object System.Drawing.Pen $script:F.TextSub,([float](1.7*$script:DPI))
            $cx=($ecol+(S 6)); $cy=S 29; $d2=S 2; $d4=S 4; $d7=S 7; $d14=S 14
            if($st.Open){
                $g.DrawLines($cp,[System.Drawing.PointF[]]@(
                    [System.Drawing.PointF]::new($cx,($cy+$d4)),
                    [System.Drawing.PointF]::new(($cx+$d7),($cy-$d2)),
                    [System.Drawing.PointF]::new(($cx+$d14),($cy+$d4))))
            } else {
                $g.DrawLines($cp,[System.Drawing.PointF[]]@(
                    [System.Drawing.PointF]::new($cx,($cy-$d2)),
                    [System.Drawing.PointF]::new(($cx+$d7),($cy+$d4)),
                    [System.Drawing.PointF]::new(($cx+$d14),($cy-$d2))))
            }
            $cp.Dispose()
        }
        if($st.IsChoice){
            # owner-drawn dropdown: a stock ComboBox paints a light arrow
            # button that no dark theme can reach, so draw the whole control
            # and open a themed menu on click.
            $dr=New-Object System.Drawing.RectangleF $script:DD_X,(S 17),$script:DD_W,(S 30)
            $managed=($script:state[$st.Row.Id].Sel -gt 0)
            $bg=$script:F.RowHot; if($managed){ $bg=$script:F.AccentDim }
            if($st.Zone -eq "ctl"){ $bg=$script:F.RowTopHi; if($managed){ $bg=[System.Drawing.Color]::FromArgb(70,76,194,255) } }
            Fill-Round $g $dr (S 4) $bg
            $edge=$script:F.RowEdge; if($managed){ $edge=$script:F.Accent }
            Stroke-Round $g $dr (S 4) $edge
            $ink=$script:F.Text; if($managed){ $ink=$script:F.Accent }
            $vb=New-Object System.Drawing.SolidBrush $ink
            $g.DrawString($st.Row.choices[$script:state[$st.Row.Id].Sel][0],$script:rowFont,$vb,($dr.X+(S 12)),($dr.Y+(S 6)),$script:SF)
            $vb.Dispose()
            $ch=New-Object System.Drawing.Pen $ink,([float](1.6*$script:DPI))
            $cx2=$dr.Right-(S 24); $cy2=$dr.Y+(S 13)
            $g.DrawLines($ch,[System.Drawing.PointF[]]@(
                [System.Drawing.PointF]::new($cx2,$cy2),
                [System.Drawing.PointF]::new(($cx2+(S 5)),($cy2+(S 5))),
                [System.Drawing.PointF]::new(($cx2+(S 10)),$cy2)))
            $ch.Dispose()
        } else {
            $word="关"; if($script:state[$st.Row.Id].On){$word="开"}
            $wb=New-Object System.Drawing.SolidBrush $script:F.TextSub
            $g.DrawString($word,$script:rowFont,$wb,(S 726),(S 21),$script:SF); $wb.Dispose()
            $tx=$script:TG_X;$ty=$script:TG_Y
            if($st.Zone -eq "ctl"){
                $halo=New-Object System.Drawing.RectangleF ($tx-(S 6)),($ty-(S 6)),($script:TG_W+(S 12)),($script:TG_H+(S 12))
                Fill-Round $g $halo (S 15) $script:F.RowTopHi
            }
            $track=New-Object System.Drawing.RectangleF $tx,$ty,$script:TG_W,$script:TG_H
            if($script:state[$st.Row.Id].On){
                Fill-Round $g $track (S 10) $script:F.Accent
                $th=New-Object System.Drawing.SolidBrush $script:F.ThumbOn
                $g.FillEllipse($th,($tx+(S 26)),($ty+(S 3)),(S 14),(S 14)); $th.Dispose()
            } else {
                Stroke-Round $g $track (S 10) $script:F.OutlineOff
                $th=New-Object System.Drawing.SolidBrush $script:F.ThumbOff
                $g.FillEllipse($th,($tx+(S 4)),($ty+(S 3)),(S 14),(S 14)); $th.Dispose()
            }
        }
        if($s.Focused){ Draw-FocusRing $g $s.Width $s.Height }
    })
    $p.Add_MouseDown({
        param($s,$ev)
        $st=$s.Tag
        $ecol=$script:EXP_X; if($st.IsChoice){ $ecol=$script:EXP_X_CHOICE }
        # One hit-test for click, hover and highlight. The bare rectangle that
        # used to sit here ignored whether the row HAS a chevron, so a click in
        # empty row space flipped the expander on rows with no expander - and
        # from 125% scaling visibly grew them. Zone-Of is what MouseMove uses.
        $zone=Zone-Of $s $ev.X $ev.Y
        if($zone -eq "exp"){
            $st.Open=-not $st.Open
            if($st.Open){
                $g=$s.CreateGraphics()
                $wc=$script:EXP_X; if($st.IsChoice){ $wc=$script:EXP_X_CHOICE }
                $sz=$g.MeasureString($st.Row.full,$script:capFont,($wc-(S 30)),$script:SFw)
                $g.Dispose()
                $s.Height=[Math]::Max($script:COLLAPSED,[int]($sz.Height+(S 46)))
            } else { $s.Height=$script:COLLAPSED }
            Reflow-Page
            $s.Invalidate(); return
        }
        if($st.IsChoice){
            if($zone -eq "ctl"){
                # Only one dropdown can be open at a time, so one slot covers
                # both call sites. NOT Add_Closed: the strip closes BEFORE the
                # item's Click handler runs, so disposing there tears it down
                # under the handler that is still reading $this.Tag.
                if($script:ddMenu -and -not $script:ddMenu.IsDisposed){ $script:ddMenu.Dispose() }
                $menu=New-Object System.Windows.Forms.ContextMenuStrip
                $menu.BackColor=$script:F.RowHot
                $menu.ForeColor=$script:F.Text
                $menu.Font=$script:rowFont
                $menu.ShowImageMargin=$false
                $menu.Renderer=New-Object System.Windows.Forms.ToolStripProfessionalRenderer(
                    (New-Object DarkMenuColors))
                $i=0
                foreach($c in $st.Row.choices){
                    $mi=$menu.Items.Add($c[0])
                    $mi.Tag=@{Row=$s;Idx=$i}
                    if($i -eq $script:state[$st.Row.Id].Sel){ $mi.ForeColor=$script:F.Accent }
                    $mi.Add_Click({
                        $d=$this.Tag
                        $script:state[$d.Row.Tag.Row.Id].Sel=$d.Idx
                        $d.Row.Invalidate()
                    })
                    $i++
                }
                $menu.Show($s,(New-Object System.Drawing.Point $script:DD_X,(S 47)))
                # a keyboard user lands on the current value; hover moves it as before
                $menu.Items[$script:state[$st.Row.Id].Sel].Select()
                $script:ddMenu=$menu
            }
            return
        }
        else {
            # toggles fire ONLY inside the pill (plus padding). Clicking a
            # label should never silently flip a machine-wide policy.
            if($zone -ne "ctl"){ return }
            $script:state[$st.Row.Id].On = -not $script:state[$st.Row.Id].On
            if($script:state[$st.Row.Id].On -and $st.Row.group){
                # exclusivity applies to the MODEL, so it holds for group
                # members that are not currently rendered on this page
                foreach($other in Get-AllRows){
                    if($other.Id -ne $st.Row.Id -and $other.group -eq $st.Row.group){
                        $script:state[$other.Id].On=$false
                    }
                }
                foreach($o in $script:rowPanels){ $o.Invalidate() }
            }
        }
        $s.Invalidate()
    })
    $p.Add_MouseEnter({$this.Tag.Hot=$true;$this.Invalidate()})
    $p.Add_MouseLeave({
        $this.Tag.Hot=$false; $this.Tag.Zone=""
        $this.Cursor=[System.Windows.Forms.Cursors]::Default
        $this.Invalidate()
    })
    Add-KeyActivation $p { param($s)
        $st=$s.Tag
        # the centre of the live control, so this is the mouse's own path
        if($st.IsChoice){ Invoke-MouseAt $s ($script:DD_X+[int]($script:DD_W/2)) (S 32) }
        else            { Invoke-MouseAt $s ($script:TG_X+[int]($script:TG_W/2)) ($script:TG_Y+[int]($script:TG_H/2)) }
    }
    $p.Add_KeyDown({
        param($s,$ev)
        $st=$s.Tag
        # Right opens the description, Left closes it - the tree-view idiom.
        # Zone-Of says "" for a row with no chevron, so those ignore both.
        if($ev.KeyCode -eq [System.Windows.Forms.Keys]::Right -or
           $ev.KeyCode -eq [System.Windows.Forms.Keys]::Left){
            $want=($ev.KeyCode -eq [System.Windows.Forms.Keys]::Right)
            $ecol=$script:EXP_X; if($st.IsChoice){ $ecol=$script:EXP_X_CHOICE }
            $cx=$ecol+(S 13); $cy=S 32
            if(($st.Open -ne $want) -and ((Zone-Of $s $cx $cy) -eq "exp")){
                Invoke-MouseAt $s $cx $cy
                # keyboard only: a description opened below the fold is
                # otherwise unreachable, the mouse is already where it clicked
                if($st.Open){ $page.ScrollControlIntoView($s) }
            }
            $ev.Handled=$true; $ev.SuppressKeyPress=$true; return
        }
        # Home, End, PageUp and PageDown walk the list the way a ListView does.
        $k=$ev.KeyCode
        if($k -eq [System.Windows.Forms.Keys]::Home){ [void]$form.SelectNextControl($page,$true,$true,$true,$false); $ev.Handled=$true }
        elseif($k -eq [System.Windows.Forms.Keys]::End){ [void]$form.SelectNextControl($bar,$false,$true,$true,$true); $ev.Handled=$true }
        elseif($k -eq [System.Windows.Forms.Keys]::PageDown -or $k -eq [System.Windows.Forms.Keys]::PageUp){
            $fwd=($k -eq [System.Windows.Forms.Keys]::PageDown)
            $n=[math]::Max(1,[int]($page.ClientSize.Height/($script:COLLAPSED+(S 4))))
            for($i=0;$i -lt $n;$i++){ if(-not $page.SelectNextControl($form.ActiveControl,$fwd,$true,$false,$false)){ break } }
            $ev.Handled=$true
        }
    })
    Enable-Focusable $p -Arrows
    $p.Add_MouseMove({
        param($s,$ev)
        $z=Zone-Of $s $ev.X $ev.Y
        if($z -ne $s.Tag.Zone){
            $s.Tag.Zone=$z
            if($z -eq ""){ $s.Cursor=[System.Windows.Forms.Cursors]::Default }
            else { $s.Cursor=[System.Windows.Forms.Cursors]::Hand }
            $s.Invalidate()
        }
    })

    return $p
}

function Reflow-Page {
    # AutoScroll makes child Location live in SCROLLED coordinates: a child at
    # absolute y sits at y + AutoScrollPosition.Y, and that offset is negative
    # when scrolled down. Lay every row out at its absolute y PLUS the current
    # offset and leave the scroll alone. This used to park the scroll at zero
    # and restore it afterwards - correct in the end, but each
    # AutoScrollPosition write scrolls synchronously by blitting the old
    # pixels, so the user saw the page jump and an after-image of the rows
    # until the repaint caught up.
    $off=$page.AutoScrollPosition.Y
    $page.SuspendLayout()
    # Same strides as Select-Page and Show-SearchResults lay the page out
    # with: header S 38 + S 4, row S 64 + S 4, and on All Options an S 10 gap
    # before each category after the first. This used to add S 6 under every
    # header instead, so the first expand or collapse shifted every row on a
    # page with section headers.
    $inSearch=($script:searchBox -and -not [string]::IsNullOrWhiteSpace($script:searchBox.Text))
    $y=S 4; $first=$true
    foreach($p in $script:rowPanels){
        if(($null -ne $p.Tag.T) -and -not $first -and -not $inSearch){ $y+=S 10 }
        $p.Location=New-Object System.Drawing.Point (S 2),($y+$off)
        $y+=$p.Height+(S 4)
        $first=$false
    }
    $page.ResumeLayout()
    # Moving children invalidates only their new bounds; the region they
    # vacated keeps its old pixels. One repaint of the whole page, children
    # included, and Update() so it happens now rather than after the click.
    $page.Invalidate($true)
    $page.Update()
}

function New-SectionHeader([string]$text,[int]$y,[int]$count){
    $h=New-Object System.Windows.Forms.Panel
    $h.Location=New-Object System.Drawing.Point (S 2),$y
    $h.Size=New-Object System.Drawing.Size (S 840),(S 38)
    $h.BackColor=$F.Bg; $h.Tag=@{T=$text;N=$count}
    Enable-DoubleBuffer $h
    $h.Add_Paint({
        param($s,$e); $g=$e.Graphics
    $g.TextRenderingHint=[System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
        $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.Clear($script:F.Bg)
        $tb=New-Object System.Drawing.SolidBrush $script:F.Text
        $g.DrawString($s.Tag.T,$script:pTitle,$tb,(S 4),(S 12),$script:SF); $tb.Dispose()
        $w=[int]($g.MeasureString($s.Tag.T,$script:pTitle,1000,$script:SF).Width)
        $cb=New-Object System.Drawing.SolidBrush $script:F.TextSub
        if($s.Tag.N -gt 0){ $g.DrawString("$($s.Tag.N)",$script:capFont,$cb,($w+(S 12)),(S 16),$script:SF) }
        $cb.Dispose()
        $p=New-Object System.Drawing.Pen $script:F.RowEdge
        $g.DrawLine($p,($w+(S 34)),(S 24),(S 835),(S 24)); $p.Dispose()
    })
    return $h
}

# --------------------------------------------------------------- preset cards
function New-PresetCard($preset,[int]$y){
    $p=New-Object System.Windows.Forms.Panel
    $p.Location=New-Object System.Drawing.Point (S 2),$y
    $p.Size=New-Object System.Drawing.Size (S 840),(S 78)
    $p.BackColor=$F.Bg; $p.Tag=@{P=$preset;Hot=$false}
    Enable-DoubleBuffer $p
    $p.Add_Paint({
        param($s,$e); $g=$e.Graphics
    $g.TextRenderingHint=[System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
        $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $st=$s.Tag; $g.Clear($script:F.Bg)
        $r=New-Object System.Drawing.RectangleF 0,0,($s.Width-1),($s.Height-2)
        $c=$script:F.Row; if($st.Hot){$c=$script:F.RowHot}
        Fill-Round $g $r (S 6) $c; Stroke-Round $g $r (S 6) $script:F.RowEdge
        $hi=New-Object System.Drawing.Pen $script:F.RowTopHi
        $g.DrawLine($hi,(S 7),1,($s.Width-(S 8)),1); $hi.Dispose()
        $tb=New-Object System.Drawing.SolidBrush $script:F.Text
        $g.DrawString($st.P.name,$script:pTitle,$tb,(S 18),(S 14),$script:SF); $tb.Dispose()
        $cb=New-Object System.Drawing.SolidBrush $script:F.TextSub
        $g.DrawString($st.P.blurb,$script:capFont,$cb,(S 18),(S 40),$script:SF)
        $g.DrawString("$($st.P.count) 条策略",$script:capFont,$cb,(S 18),(S 56),$script:SF); $cb.Dispose()
        $bw=$script:PC_BW
        $br=New-Object System.Drawing.RectangleF $script:PC_BX,$script:PC_BY,$bw,$script:PC_BH
        $bg=$script:F.RowHot; if($st.Hot){$bg=$script:F.Accent}
        Fill-Round $g $br (S 4) $bg
        if(-not $st.Hot){ Stroke-Round $g $br (S 4) $script:F.RowEdge }
        $ink=$script:F.Text; if($st.Hot){$ink=[System.Drawing.Color]::FromArgb(27,27,27)}
        $lb=New-Object System.Drawing.SolidBrush $ink
        $sz=$g.MeasureString("加载",$script:btnFont,1000,$script:SF)
        $g.DrawString("加载",$script:btnFont,$lb,($br.X+($bw-$sz.Width)/2),($br.Y+(S 7)),$script:SF); $lb.Dispose()
        if($s.Focused){ Draw-FocusRing $g $s.Width $s.Height }
    })
    # Same zone discipline as the setting rows: loading a preset DISCARDS every
    # staged selection, so a stray click on the blurb the user is reading must
    # not do it. Only the drawn Load button responds, and only it lights up.
    $p.Add_MouseMove({
        param($s,$ev)
        $over=(Test-InPresetButton $ev.X $ev.Y)
        if($s.Tag.Hot -ne $over){ $s.Tag.Hot=$over; $s.Invalidate() }
        if($over){ $s.Cursor=[System.Windows.Forms.Cursors]::Hand }
        else     { $s.Cursor=[System.Windows.Forms.Cursors]::Default }
    })
    $p.Add_MouseLeave({$this.Tag.Hot=$false;$this.Invalidate()})
    Add-KeyActivation $p { param($s)
        Invoke-MouseAt $s ($script:PC_BX+[int]($script:PC_BW/2)) ($script:PC_BY+[int]($script:PC_BH/2))
    }
    Enable-Focusable $p
    $p.AccessibleName="Load $($preset.name) preset"; $p.AccessibleDescription=$preset.blurb
    $p.AccessibleRole=[System.Windows.Forms.AccessibleRole]::PushButton
    $p.Add_MouseDown({
        param($s,$ev)
        if(-not (Test-InPresetButton $ev.X $ev.Y)){ return }
        Import-PresetIntoState $s.Tag.P
        Refresh-View
        Set-Status ([string]::Format($script:zhData.ui.preset_loaded_status, $s.Tag.P.name, $s.Tag.P.count))
    })
    return $p
}

# Shared by New-PresetCard's Paint and its hit-testing. Kept as constants for
# the same reason the row control columns are: when the drawn rect and the
# clickable rect were computed separately, they drifted apart.
$script:PC_BX = S 705
$script:PC_BY = S 24
$script:PC_BW = S 110
$script:PC_BH = S 32
function Test-InPresetButton($x, $y) {
    return ($x -ge $script:PC_BX -and $x -le ($script:PC_BX + $script:PC_BW) -and
            $y -ge $script:PC_BY -and $y -le ($script:PC_BY + $script:PC_BH))
}

# --------------------------------------------------------------- DNS page
# Script scope on purpose: the Leave handler fires long after Build-DnsPage
# has returned, and a nested function is out of scope by then - every blur of
# the template box threw CommandNotFoundException.
$script:tmplHint = "https://dns.example/dns-query"
function Sync-TmplHint($box){
    if($box.Focused){ return }
    if([string]::IsNullOrEmpty($box.Tag)){
        $box.ForeColor=[System.Drawing.Color]::FromArgb(96,96,96)
        $box.Text=$script:tmplHint
    }
}

function Test-DnsControlHit([int]$x,[int]$y){
    # the DNS card's one live zone, the mode dropdown, with the toggle padding
    $dl=$script:DD_X-$script:TG_PAD; $dr2=$script:DD_X+$script:DD_W+$script:TG_PAD
    return ($x -ge $dl -and $x -le $dr2 -and $y -ge (S 6) -and $y -le (S 56))
}

function Build-DnsPage {
    $card=New-Object System.Windows.Forms.Panel
    $card.Location=New-Object System.Drawing.Point (S 2),(S 4)
    $card.Size=New-Object System.Drawing.Size (S 840),(S 150)
    $card.BackColor=$F.Bg
    $card.Tag=@{Zone=""}
    Enable-DoubleBuffer $card
    $card.Add_Paint({
        param($s,$e); $g=$e.Graphics
        $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint=[System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
        $st=$s.Tag
        $g.Clear($script:F.Bg)
        $r=New-Object System.Drawing.RectangleF 0,0,($s.Width-1),($s.Height-2)
        Fill-Round $g $r (S 6) $script:F.Row; Stroke-Round $g $r (S 6) $script:F.RowEdge
        $hi=New-Object System.Drawing.Pen $script:F.RowTopHi
        $g.DrawLine($hi,(S 7),1,($s.Width-(S 8)),1); $hi.Dispose()
        $tb=New-Object System.Drawing.SolidBrush $script:F.Text
        $g.DrawString("DNS over HTTPS 模式",$script:rowFont,$tb,(S 18),(S 18),$script:SF)
        $g.DrawString("自定义 DoH 模板 URL",$script:rowFont,$tb,(S 18),(S 92),$script:SF); $tb.Dispose()
        $cb=New-Object System.Drawing.SolidBrush $script:F.TextSub
        $g.DrawString("选择`“不管理`”将不写入任何 DNS 策略，完全保留 Brave 原有设置",$script:capFont,$cb,(S 18),(S 40),$script:SF)
        $needs=($script:dnsModes[$script:dnsState.Mode] -eq "custom" -or $script:dnsModes[$script:dnsState.Mode] -eq "secure")
        $note="仅在 custom（自定义）和 secure（安全）模式下使用"
        if($needs){ $note="必填 - 未设置模板时，安全 DNS 将无法解析任何域名" }
        $g.DrawString($note,$script:capFont,$cb,(S 18),(S 114),$script:SF); $cb.Dispose()

        # mode dropdown, same column and bounds rule as every other row
        $dr=New-Object System.Drawing.RectangleF $script:DD_X,(S 16),$script:DD_W,(S 30)
        $managed=($script:dnsState.Mode -gt 0)
        $bg=$script:F.RowHot; if($managed){ $bg=$script:F.AccentDim }
        if($st.Zone -eq "ctl"){ $bg=$script:F.RowTopHi; if($managed){ $bg=[System.Drawing.Color]::FromArgb(70,76,194,255) } }
        Fill-Round $g $dr (S 4) $bg
        $edge=$script:F.RowEdge; if($managed){ $edge=$script:F.Accent }
        Stroke-Round $g $dr (S 4) $edge
        $ink=$script:F.Text; if($managed){ $ink=$script:F.Accent }
        $vb=New-Object System.Drawing.SolidBrush $ink
        $g.DrawString((Get-ZhDnsMode $script:dnsModes[$script:dnsState.Mode]),$script:rowFont,$vb,($dr.X+(S 12)),($dr.Y+(S 6)),$script:SF); $vb.Dispose()
        $ch=New-Object System.Drawing.Pen $ink,([float](1.6*$script:DPI))
        $cx=$dr.Right-(S 24); $cy=$dr.Y+(S 13)
        $g.DrawLines($ch,[System.Drawing.PointF[]]@(
            [System.Drawing.PointF]::new($cx,$cy),
            [System.Drawing.PointF]::new(($cx+(S 5)),($cy+(S 5))),
            [System.Drawing.PointF]::new(($cx+(S 10)),$cy)))
        $ch.Dispose()

        # the template field is a real TextBox child; just draw its frame
        $well=New-Object System.Drawing.RectangleF ($script:DD_X-1),(S 89),($script:DD_W+2),(S 28)
        $wedge=$script:F.RowEdge; if($needs){ $wedge=$script:F.Accent }
        Stroke-Round $g $well (S 4) $wedge
        if($s.Focused){ Draw-FocusRing $g $s.Width $s.Height }
    })
    $tmpl=New-Object System.Windows.Forms.TextBox
    $tmpl.BorderStyle=[System.Windows.Forms.BorderStyle]::None
    $tmpl.Font=$script:rowFont
    $tmpl.BackColor=[System.Drawing.Color]::FromArgb(38,38,38)
    $tmpl.ForeColor=$F.Text
    $tmpl.Location=New-Object System.Drawing.Point ($script:DD_X+(S 8)),(S 96)
    $tmpl.Size=New-Object System.Drawing.Size ($script:DD_W-(S 16)),(S 20)
    $tmpl.Text=""
    $card.Controls.Add($tmpl)
    $card.Tag.Tmpl=$tmpl
    $tmpl.AccessibleName="Custom template URL"

    # .NET Framework has no PlaceholderText, so fake one: grey hint while the
    # box is empty and unfocused, cleared the moment the user types.
    $tmpl.Tag=""
    $tmpl.Add_Enter({
        if([string]::IsNullOrEmpty($this.Tag)){ $this.Text="" }
        $this.ForeColor=$script:F.Text
    })
    Sync-TmplHint $tmpl

    $card.Add_MouseMove({
        param($s,$ev)
        $z=""
        if(Test-DnsControlHit $ev.X $ev.Y){ $z="ctl" }
        if($z -ne $s.Tag.Zone){
            $s.Tag.Zone=$z
            if($z -eq ""){ $s.Cursor=[System.Windows.Forms.Cursors]::Default }
            else { $s.Cursor=[System.Windows.Forms.Cursors]::Hand }
            $s.Invalidate()
        }
    })
    $card.Add_MouseLeave({
        $this.Tag.Zone=""; $this.Cursor=[System.Windows.Forms.Cursors]::Default; $this.Invalidate()
    })
    $card.Add_MouseDown({
        param($s,$ev)
        # bounded exactly like every other control: label clicks do nothing.
        # Hit-tested from the coordinates, not the hover zone, so the keyboard
        # path (Invoke-MouseAt at the control's centre) takes the same door.
        if(-not (Test-DnsControlHit $ev.X $ev.Y)){ return }
        if($script:ddMenu -and -not $script:ddMenu.IsDisposed){ $script:ddMenu.Dispose() }
        $menu=New-Object System.Windows.Forms.ContextMenuStrip
        $menu.BackColor=$script:F.RowHot
        $menu.ForeColor=$script:F.Text
        $menu.Font=$script:rowFont
        $menu.ShowImageMargin=$false
        $menu.Renderer=New-Object System.Windows.Forms.ToolStripProfessionalRenderer((New-Object DarkMenuColors))
        $i=0
        foreach($m in $script:dnsModes){
            $mi=$menu.Items.Add((Get-ZhDnsMode $m))
            $mi.Tag=@{Card=$s;Idx=$i}
            if($i -eq $script:dnsState.Mode){ $mi.ForeColor=$script:F.Accent }
            $mi.Add_Click({
                $d=$this.Tag
                $script:dnsState.Mode=$d.Idx
                $m=$script:dnsModes[$d.Idx]
                $box=$d.Card.Tag.Tmpl
                $box.Enabled=($m -eq "custom" -or $m -eq "secure")
                if(-not $box.Enabled){ $box.ForeColor=[System.Drawing.Color]::FromArgb(96,96,96) }
                elseif(-not [string]::IsNullOrEmpty($box.Tag)){ $box.ForeColor=$script:F.Text }
                Set-Status ([string]::Format($script:zhData.ui.dns.status_mode, (Get-ZhDnsMode $m)))
                $d.Card.Invalidate()
            })
            $i++
        }
        $menu.Show($s,(New-Object System.Drawing.Point $script:DD_X,(S 46)))
        $menu.Items[$script:dnsState.Mode].Select()
        $script:ddMenu=$menu
    })
    # The dropdown is the card itself: focusable, Space/Enter opens the menu
    # through the mouse's own MouseDown, and the template box, being its
    # child, follows it in Tab order.
    Add-KeyActivation $card { param($s) Invoke-MouseAt $s ($script:DD_X+[int]($script:DD_W/2)) (S 31) }
    Enable-Focusable $card
    $card.AccessibleName="DNS over HTTPS mode"; $card.AccessibleRole=[System.Windows.Forms.AccessibleRole]::ComboBox
    $m0=$script:dnsModes[$script:dnsState.Mode]
    $tmpl.Enabled=($m0 -eq "custom" -or $m0 -eq "secure")
    if($script:dnsState.Tmpl){ $tmpl.Tag=$script:dnsState.Tmpl; $tmpl.Text=$script:dnsState.Tmpl; $tmpl.ForeColor=$F.Text }
    # One TextChanged and one Leave. The prototype's hint-mirroring pair and
    # the engine's validating pair were both registered, so each event ran
    # twice in registration order - benign, but order-dependent.
    $tmpl.Add_TextChanged({ if($this.Focused){ $this.Tag=$this.Text; $script:dnsState.Tmpl=$this.Text } })
    $tmpl.Add_Leave({
        $this.Tag=$this.Text
        # normalise on the way out so the stored value is what Apply writes.
        # Guarded: this handler once raised "Test-DohTemplate is not recognized"
        # in a real session, and an exception out of Leave is the .NET crash
        # dialog. Apply validates the template again before writing anything,
        # so a failure here may cost the hint, never the window.
        try {
            if(-not [string]::IsNullOrWhiteSpace($this.Tag)){
                $chk=Test-DohTemplate $this.Tag
                if($chk.Ok){ $this.Tag=$chk.Value; $this.Text=$chk.Value; $script:dnsState.Tmpl=$chk.Value }
                else { Set-Status ([string]::Format($script:zhData.ui.dns.status_tmpl_err, $chk.Reason)) }
            }
            Sync-TmplHint $this
        } catch { [Console]::Error.WriteLine("SlimBrave Neo: DoH template check skipped - " + $_.Exception.Message) }
    })
    $page.Controls.Add($card)
}

# --------------------------------------------------------------- page switch
function Get-SearchStem([string]$w){
    # "passwords" -> "password", but "dns", "https" and "class" keep their s:
    # only a trailing s after at least three other letters, not doubled, is
    # treated as a plural.
    if($w.Length -ge 4 -and $w.EndsWith("s") -and -not $w.EndsWith("ss")){ return $w.Substring(0,$w.Length-1) }
    return $w
}
function Get-SearchWords([string]$text){
    # The words of a haystack, each present as itself and as its stem. Policy
    # keys are CamelCase, so they are split at case changes too - a user who
    # types "blocklist" should find ExtensionInstallBlocklist - and kept whole
    # as well, so a pasted key still matches by prefix.
    # A HashSet, not a hashtable. PowerShell resolves $table.Keys to the ENTRY
    # named "keys" when one exists - and "registry keys" appears in several
    # descriptions - so the key collection came back as $true and every prefix
    # test on those rows threw into the console. The unary comma keeps the set
    # from being unrolled into strings on return.
    $out=New-Object System.Collections.Generic.HashSet[string]
    $spaced=$text -creplace '([a-z0-9])([A-Z])','$1 $2'
    foreach($w in (("$text $spaced").ToLower() -split '[^a-z0-9]+')){
        if($w){ [void]$out.Add($w); [void]$out.Add((Get-SearchStem $w)) }
    }
    return ,$out
}
function Test-SearchHit($words,[string]$tok,[string]$stem){
    # A token hits when it IS a word (or a word's stem), or when it is the
    # start of one and long enough to mean something - three characters, so
    # "tel" finds telemetry but "is" cannot match every row that has an "i".
    if($words.Contains($tok) -or $words.Contains($stem)){ return $true }
    if($stem.Length -ge 3){
        foreach($w in $words){ if($w.StartsWith($stem)){ return $true } }
    }
    return $false
}
function Test-HasCjk([string]$s){
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

function Show-SearchResults([string]$query){
    $hits=Get-SearchMatches $query
    $pageTitle.Text="搜索结果"
    $n=@($hits).Count
    $word="matches"; if($n -eq 1){ $word="match" }
    $crumb.Text=[string]::Format($script:zhData.ui.search_crumb, $n, $query)
    foreach($n2 in $script:navItems){ $n2.Invalidate() }
    $page.SuspendLayout()
    $page.AutoScrollPosition=New-Object System.Drawing.Point 0,0
    $page.AutoScrollMinSize=New-Object System.Drawing.Size 0,0
    # Dispose, don't just detach: Controls.Clear() drops the reference but
    # leaves every child's window handle alive until a GC runs, and All Options
    # builds ~85 of them per visit. Dispose() removes itself from the parent
    # collection, so this terminates.
    # A rebuild disposes the focused control, and Win32 then hands focus to
    # the page itself, which nothing paints and no key reaches. Remember the
    # position and put focus back on whatever is built there.
    $keepIdx=-1
    if($page.ContainsFocus){ for($i=0;$i -lt $page.Controls.Count;$i++){ if($page.Controls[$i].ContainsFocus){ $keepIdx=$i; break } } }
    while($page.Controls.Count -gt 0){ $page.Controls[0].Dispose() }
    $script:rowPanels=@()
    $y=S 4
    if($n -eq 0){
        $empty=New-Object System.Windows.Forms.Label
        $empty.Text=[string]::Format($script:zhData.ui.search_empty, $query)
        $empty.Font=$script:rowFont; $empty.ForeColor=$F.TextSub
        $empty.BackColor=$F.Bg; $empty.AutoSize=$true
        $empty.Location=New-Object System.Drawing.Point (S 6),(S 12)
        $page.Controls.Add($empty)
    } else {
        $lastCat=""
        foreach($h in $hits){
            if($h.Cat -ne $lastCat){
                $hd=New-SectionHeader $h.Cat $y 0
                $page.Controls.Add($hd); $script:rowPanels+=$hd; $y+=$hd.Height+(S 4)
                $lastCat=$h.Cat
            }
            $rp=New-FluentRow $h.Row $y
            $page.Controls.Add($rp); $script:rowPanels+=$rp; $y+=$rp.Height+(S 4)
        }
    }
    $page.ResumeLayout()
    $page.AutoScrollPosition=New-Object System.Drawing.Point 0,0
    $page.Invalidate($true); $page.Update()
    if($keepIdx -ge 0){
        $back=$null
        if($keepIdx -lt $page.Controls.Count -and $page.Controls[$keepIdx].CanSelect){ $back=$page.Controls[$keepIdx] }
        if($back){ [void]$back.Focus() } else { [void]$page.SelectNextControl($null,$true,$true,$true,$false) }
    }
}

function Refresh-View {
    # Rebuild whatever the user is looking at. Apply, Reset, Re-sync, Import
    # and a preset Load used to call Select-Page directly, which replaced an
    # open search-results view with the page behind it while the box kept
    # its query.
    $q=""; if($script:searchBox){ $q=$script:searchBox.Text.Trim() }
    if([string]::IsNullOrWhiteSpace($q)){ Select-Page $script:sel } else { Show-SearchResults $q }
}

function Select-Page([int]$idx){
    $script:sel=$idx
    foreach($n in $script:navItems){$n.Invalidate()}
    $name=$script:pages[$idx]
    $crumb.Text="SlimBrave Neo  >  $name"
    $pageTitle.Text=$name
    $page.SuspendLayout()
    # Zero the scroll BEFORE clearing and refilling. Child Location is in
    # scrolled coordinates, so rows added while the previous page's offset is
    # still applied land that far down, and AutoScrollMinSize grows to cover
    # the emptiness above them - the "ghost scroll" you have to travel through
    # before reaching the content.
    $page.AutoScrollPosition=New-Object System.Drawing.Point 0,0
    $page.AutoScrollMinSize=New-Object System.Drawing.Size 0,0
    # Dispose, don't just detach: Controls.Clear() drops the reference but
    # leaves every child's window handle alive until a GC runs, and All Options
    # builds ~85 of them per visit. Dispose() removes itself from the parent
    # collection, so this terminates.
    # A rebuild disposes the focused control, and Win32 then hands focus to
    # the page itself, which nothing paints and no key reaches. Remember the
    # position and put focus back on whatever is built there.
    $keepIdx=-1
    if($page.ContainsFocus){ for($i=0;$i -lt $page.Controls.Count;$i++){ if($page.Controls[$i].ContainsFocus){ $keepIdx=$i; break } } }
    while($page.Controls.Count -gt 0){ $page.Controls[0].Dispose() }
    $script:rowPanels=@()
    if($idx -eq 0){
        $y=S 4
        foreach($pr in $script:presets){
            $c=New-PresetCard $pr $y; $page.Controls.Add($c); $y+=S 82
        }
    } elseif($idx -eq 1){
        # every row, every category, one scroll - no menuing
        $y=S 4; $total=0
        foreach($cat in $script:cats){
            $hd=New-SectionHeader $cat.name $y $cat.rows.Count
            $page.Controls.Add($hd); $script:rowPanels+=$hd; $y+=$hd.Height+(S 4)
            foreach($row in $cat.rows){
                $rp=New-FluentRow $row $y; $page.Controls.Add($rp)
                $script:rowPanels+=$rp; $y+=$rp.Height+(S 4); $total++
            }
            $y+=S 10
        }
        $pageTitle.Text="全部选项"
        $crumb.Text=[string]::Format($script:zhData.ui.all_crumb, $total)
    } elseif($idx -eq ($script:pages.Count-1)){
        Build-DnsPage
    } else {
        $cat=$script:cats[$idx-2]; $y=S 4
        foreach($row in $cat.rows){
            $rp=New-FluentRow $row $y; $page.Controls.Add($rp)
            $script:rowPanels+=$rp; $y+=$rp.Height+(S 4)
        }
    }
    $page.ResumeLayout()
    $page.AutoScrollPosition=New-Object System.Drawing.Point 0,0
    $page.Invalidate($true); $page.Update()
    if($keepIdx -ge 0){
        $back=$null
        if($keepIdx -lt $page.Controls.Count -and $page.Controls[$keepIdx].CanSelect){ $back=$page.Controls[$keepIdx] }
        if($back){ [void]$back.Focus() } else { [void]$page.SelectNextControl($null,$true,$true,$true,$false) }
    }
}

$script:searchBox.Add_TextChanged({
    $q=$this.Text.Trim()
    $searchHost.Invalidate()
    if([string]::IsNullOrWhiteSpace($q)){ Select-Page $script:sel } else { Show-SearchResults $q }
})
$script:searchBox.Add_KeyDown({
    param($s,$ev)
    if($ev.KeyCode -eq [System.Windows.Forms.Keys]::Escape){ $s.Text="" }
    # Search is live through TextChanged, so Return has nothing left to do.
    # Without suppressing both, the edit control beeps on every press.
    if($ev.KeyCode -eq [System.Windows.Forms.Keys]::Escape -or
       $ev.KeyCode -eq [System.Windows.Forms.Keys]::Return){ $ev.SuppressKeyPress=$true }
})

# Escape follows the TUI: clears an active search (the box handles that
# itself), otherwise closes the window. Wired here, with the rest of the GUI,
# rather than beside ShowDialog - the render harness slices the GUI off just
# below this point, and a handler past the cut is one it can never exercise.
$form.KeyPreview=$true
$form.Add_KeyDown({
    param($s,$ev)
    if($ev.KeyCode -ne [System.Windows.Forms.Keys]::Escape){ return }
    # A text box owns its Escape: the search box clears itself on the first
    # press and closes on the second, as the TUI does; the DoH template box
    # never closes the window.
    $ac=$s.ActiveControl
    if($ac -is [System.Windows.Forms.TextBox] -and ($ac -ne $script:searchBox -or $ac.Text)){ return }
    $ev.Handled=$true; $ev.SuppressKeyPress=$true
    $s.Close()
})
# Focus starts in the search box, as it did before the panels were focusable:
# typing at launch searches, and no focus ring shows until the keyboard moves
# it. Shown, not ActiveControl: under ShowDialog the latter is bookkeeping that
# Win32 focus catches up with late.
$form.Add_Shown({ [void]$script:searchBox.Focus() })
# Closing with staged changes - Escape, Alt+F4 or the X - asks first. The
# baseline is taken whenever the model is known to match the registry.
$script:applied=$null
function Get-StateSnapshot {
    $rows=foreach($kv in ($script:state.GetEnumerator() | Sort-Object Name)){ "$($kv.Name)=$($kv.Value.On)|$($kv.Value.Sel)" }
    return (($rows -join ";")+"#$($script:dnsState.Mode)|$($script:dnsState.Tmpl)")
}
$form.Add_FormClosing({
    param($s,$e)
    if($null -eq $script:applied -or (Get-StateSnapshot) -eq $script:applied){ return }
    $ans=[System.Windows.Forms.MessageBox]::Show(
        "当前有尚未应用的更改。确定关闭并放弃更改吗？",
        "SlimBrave Neo",[System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question)
    if($ans -ne "Yes"){ $e.Cancel=$true }
})

if(Test-Path $script:machineReg){ Sync-FromRegistry } else { Set-Status "本机尚未设置任何 Brave 托管策略" }
$script:applied=Get-StateSnapshot
Select-Page 0
[void] $form.ShowDialog()
# ShowDialog does not dispose. Do it here, while the script's own functions
# still exist for any handler the teardown fires.
$form.Dispose()
