#!/bin/sh
# AgentPay installer.
#
#   curl -fsSL https://wlfi.sh | sh
#   curl -fsSL https://wlfi.sh | sh -s -- --yes --verbose
#
# Downloads the release tarball for this OS and CPU, verifies its SHA-256 against the release's
# SHA256SUMS before extracting anything (fail closed), installs it into ~/.agentpay and puts
# `agentpay` on PATH. It never uses sudo: `agentpay setup` asks for it later, when it installs
# the system services.
#
# Options:
#   -y, --yes          answer yes to every question (a downgrade, moving an older install aside)
#   -v, --verbose      print every action
#   --no-modify-path   do not touch shell startup files
#   -h, --help         show this help
#
# Environment:
#   AGENTPAY_VERSION       release to install, e.g. 0.6.0 or v0.6.0 (default: latest)
#   AGENTPAY_INSTALL_DIR   install directory (default: ~/.agentpay)
#   AGENTPAY_RELEASES_URL  where releases are downloaded from, https:// or file://
#                          (default: https://github.com/worldliberty/agentpay-sdk/releases)
#   AGENTPAY_SHA256        optional extra pin: the tarball must also have this SHA-256
#
# Install layout:
#   <dir>/versions/<version>/   the extracted release (bin/, libexec/, client/, node/)
#   <dir>/current               symlink to the active version
#   <dir>/bin/agentpay          symlink to current/bin/agentpay (this directory goes on PATH)
#   <dir>/bin/agentpay-setup    symlink to current/bin/agentpay-setup
#   <dir>/installer.json        what was installed, from where, and which shell file was changed
#
# Everything runs inside main(), called on the last line, so a truncated download under
# `curl | sh` never runs half a script.

set -eu

DEFAULT_RELEASES_URL="https://github.com/worldliberty/agentpay-sdk/releases"
ISSUES_URL="https://github.com/worldliberty/agentpay-sdk/issues"
RC_BEGIN="# >>> agentpay >>>"
RC_END="# <<< agentpay <<<"
# Block written by the previous (TypeScript) installer. It exported AGENTPAY_HOME, which the
# current client treats as a development override, so it is replaced.
LEGACY_RC_BEGIN="# >>> agentpay-sdk >>>"
LEGACY_RC_END="# <<< agentpay-sdk <<<"
# Files the previous installer put into the install directory. They are moved aside, not deleted.
LEGACY_ITEMS="app one-click-install-manifest.json bin/agentpay-admin bin/agentpay-agent
bin/agentpay-daemon bin/agentpay-system-keychain bin/run-agentpay-daemon.sh
bin/install-user-daemon.sh bin/uninstall-user-daemon.sh bin/agentpay-daemon-password-helper.sh
bin/install-system-daemon.sh bin/uninstall-system-daemon.sh"

YES=0
VERBOSE=0
MODIFY_PATH=1
STEP_COUNT=0
STEPS=""
TMP_DIR=""
LOCK_DIR=""
STAGING_DIR=""

usage() {
  cat <<'EOF'
Install AgentPay into ~/.agentpay and put `agentpay` on PATH.

Usage: install.sh [--yes] [--verbose] [--no-modify-path]

Options:
  -y, --yes          answer yes to every question
  -v, --verbose      print every action
      --no-modify-path
                     do not change shell startup files
  -h, --help         show this help

Environment:
  AGENTPAY_VERSION       release to install, e.g. 0.6.0 (default: latest)
  AGENTPAY_INSTALL_DIR   install directory (default: ~/.agentpay)
  AGENTPAY_RELEASES_URL  release download base, https:// or file://
  AGENTPAY_SHA256        also require the tarball to have this SHA-256
EOF
}

# ---------------------------------------------------------------------------------------------
# Output

# Prints a verbose progress line to stderr.
log() {
  if [ "$VERBOSE" = 1 ]; then
    printf '  · %s\n' "$*" >&2
  fi
}

# Records a finished step for the summary.
step() {
  STEP_COUNT=$((STEP_COUNT + 1))
  line=$(printf '  %2d  ✓  %-22s %s' "$STEP_COUNT" "$1" "$2")
  STEPS="$STEPS$line
"
  log "$1: $2"
}

# Prints the steps so far, a failed step, and what to do next; then exits.
#   fail <title> <message> [next action]
fail() {
  next=${3:-"Fix the problem above and run the installer again."}
  {
    printf '\nAgentPay install\n\n'
    printf '%s' "$STEPS"
    printf '  %2d  ✗  %-22s %s\n' "$((STEP_COUNT + 1))" "$1" "$2"
    printf '\nNext: %s\n' "$next"
  } >&2
  exit 1
}

# Shows a path with $HOME abbreviated to ~.
pretty_path() {
  case $1 in
    "$HOME") printf '~' ;;
    "$HOME"/*) printf '%s/%s' "~" "${1#"$HOME"/}" ;;
    *) printf '%s' "$1" ;;
  esac
}

# ---------------------------------------------------------------------------------------------
# Small helpers

have() {
  command -v "$1" >/dev/null 2>&1
}

# Whether a controlling terminal can be opened for questions (also under `curl | sh`).
tty_available() {
  (: </dev/tty) 2>/dev/null
}

# Asks a yes/no question on the terminal. Without a terminal the default is used; --yes
# always answers yes. Never waits on a timer.
#   confirm <question> <y|n>
confirm() {
  if [ "$YES" = 1 ]; then
    return 0
  fi
  if ! tty_available; then
    [ "$2" = y ]
    return
  fi
  if [ "$2" = y ]; then hint='[Y/n]'; else hint='[y/N]'; fi
  printf '%s %s ' "$1" "$hint" >/dev/tty
  reply=""
  read -r reply </dev/tty || reply=""
  case $reply in
    [Yy] | [Yy][Ee][Ss]) return 0 ;;
    [Nn] | [Nn][Oo]) return 1 ;;
    *) [ "$2" = y ] ;;
  esac
}

cleanup() {
  if [ -n "$STAGING_DIR" ] && [ -d "$STAGING_DIR" ]; then
    rm -rf "$STAGING_DIR"
  fi
  if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
  if [ -n "$LOCK_DIR" ] && [ -d "$LOCK_DIR" ]; then
    rmdir "$LOCK_DIR" 2>/dev/null || true
  fi
}

sha256_of() {
  if have sha256sum; then
    sha256sum "$1" | awk '{ print $1 }'
  elif have shasum; then
    shasum -a 256 "$1" | awk '{ print $1 }'
  elif have openssl; then
    openssl dgst -sha256 "$1" | awk '{ print $NF }'
  else
    fail "Checksum" "no SHA-256 tool found (sha256sum, shasum or openssl)" \
      "Install coreutils (sha256sum) or openssl, then run the installer again."
  fi
}

is_sha256() {
  case $1 in
    *[!0-9a-f]*) return 1 ;;
  esac
  [ "${#1}" -eq 64 ]
}

lowercase() {
  printf '%s' "$1" | tr 'ABCDEF' 'abcdef'
}

# Runs a command, keeping its stderr for --verbose instead of printing it between steps.
quietly() {
  quietly_err=$("$@" 2>&1 >/dev/null) && return 0
  quietly_status=$?
  [ -n "$quietly_err" ] && log "$quietly_err"
  return "$quietly_status"
}

# Downloads <url> to <file>. Only https:// (redirects included) and file:// are accepted.
fetch() {
  log "download $1"
  case $1 in
    https://*)
      # Tool errors stay out of the step list; --verbose shows them.
      if have curl; then
        quietly curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent \
          --show-error --location --retry 3 --connect-timeout 20 --output "$2" "$1"
      elif have wget; then
        quietly wget --quiet --https-only --tries=3 --output-document="$2" "$1"
      else
        fail "Download" "neither curl nor wget is installed" "Install curl, then run the installer again."
      fi
      ;;
    file://*)
      if have curl; then
        quietly curl --proto '=file' --fail --silent --show-error --output "$2" "$1"
      else
        quietly cp "${1#file://}" "$2"
      fi
      ;;
    *)
      return 1
      ;;
  esac
}

# Prints the physical path of $1, resolving symlinks in its deepest existing ancestor.
physical_path() {
  target=${1%/}
  [ -n "$target" ] || target=/
  suffix=""
  while [ ! -d "$target" ]; do
    suffix="/$(basename "$target")$suffix"
    target=$(dirname "$target")
  done
  target=$(cd "$target" && pwd -P)
  if [ "$target" = / ]; then
    printf '%s\n' "${suffix:-/}"
  else
    printf '%s\n' "$target$suffix"
  fi
}

# Compares dotted release versions (pre-release suffixes ignored). Succeeds when $1 < $2.
version_lt() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    sub(/[-+].*/, "", a); sub(/[-+].*/, "", b)
    na = split(a, x, "."); nb = split(b, y, ".")
    n = na > nb ? na : nb
    for (i = 1; i <= n; i++) {
      if ((x[i] + 0) < (y[i] + 0)) exit 0
      if ((x[i] + 0) > (y[i] + 0)) exit 1
    }
    exit 1
  }'
}

# Reads a top-level string field from a small JSON file written by this installer or dist.
json_field() {
  sed -n "s/^ *\"$2\": *\"\\([^\"]*\\)\".*/\\1/p" "$1" | head -n 1
}

json_string() {
  printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"
}

# ---------------------------------------------------------------------------------------------
# Steps

parse_args() {
  while [ $# -gt 0 ]; do
    case $1 in
      -y | --yes) YES=1 ;;
      -v | --verbose) VERBOSE=1 ;;
      --no-modify-path) MODIFY_PATH=0 ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        printf 'install.sh: unknown option %s\n\n' "$1" >&2
        usage >&2
        exit 2
        ;;
    esac
    shift
  done
}

detect_platform() {
  kernel=$(uname -s)
  machine=$(uname -m)
  case $kernel in
    Darwin) OS=macos OS_NAME=macOS ;;
    Linux) OS=linux OS_NAME=Linux ;;
    *) fail "Platform" "$kernel is not supported" "AgentPay runs on macOS and Linux." ;;
  esac
  case $machine in
    arm64 | aarch64) ARCH=arm64 ;;
    x86_64 | amd64) ARCH=x86_64 ;;
    *) fail "Platform" "$machine CPUs are not supported" "AgentPay runs on arm64 and x86_64." ;;
  esac
  # An x86_64 shell under Rosetta on Apple silicon still gets the native build.
  if [ "$OS" = macos ] && [ "$ARCH" = x86_64 ] &&
    [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
    ARCH=arm64
  fi
  if [ "$OS" = linux ]; then
    for loader in /lib/ld-musl-*; do
      if [ -e "$loader" ]; then
        fail "Platform" "musl-based Linux is not supported" \
          "Install AgentPay on a glibc-based distribution (Debian, Ubuntu, Fedora, ...)."
      fi
    done
  fi
  step "Platform" "$OS_NAME $ARCH"
}

resolve_install_dir() {
  dir=${AGENTPAY_INSTALL_DIR:-"$HOME/.agentpay"}
  case $dir in
    "~") dir=$HOME ;;
    \~/*) dir="$HOME/${dir#??}" ;;
  esac
  case $dir in
    /*) ;;
    *) dir="$PWD/$dir" ;;
  esac
  # The path is written into a shell startup file, so keep it free of shell syntax.
  case $dir in
    *[\"\$\`\\]* | *"
"*)
      fail "Install directory" "$dir contains quotes, \$, backticks, backslashes or newlines" \
        "Set AGENTPAY_INSTALL_DIR to a plain path such as ~/.agentpay."
      ;;
  esac
  while [ "${dir%/}" != "$dir" ] && [ "$dir" != / ]; do dir=${dir%/}; done
  INSTALL_DIR=$dir
  # The protection check looks through symlinks; everything else keeps the path as given.
  physical=$(physical_path "$dir")
  protected=0
  [ "$physical" = "$(physical_path "$HOME")" ] && protected=1
  case $physical in
    / | /usr | /usr/* | /opt | /opt/agentpay | /opt/agentpay/* | /bin | /sbin | /etc | /var | /tmp | \
      /private | /private/etc | /private/var | /private/tmp | /System | /System/* | /Library | \
      /Library/AgentPay | /Library/AgentPay/* | /Applications | /Users | /home | /root)
      protected=1
      ;;
  esac
  if [ "$protected" = 1 ]; then
    fail "Install directory" "refusing to install into $INSTALL_DIR (\$HOME, / or a system directory)" \
      "Use a dedicated directory, e.g. AGENTPAY_INSTALL_DIR=~/.agentpay."
  fi
  if [ -e "$INSTALL_DIR" ] && [ ! -d "$INSTALL_DIR" ]; then
    fail "Install directory" "$INSTALL_DIR exists and is not a directory" \
      "Move it out of the way or choose another AGENTPAY_INSTALL_DIR."
  fi
  if [ -d "$INSTALL_DIR" ]; then
    if [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ] && ! install_dir_is_recognized "$INSTALL_DIR"; then
      fail "Install directory" "$INSTALL_DIR is not empty and is not an AgentPay directory" \
        "Choose an empty or dedicated directory with AGENTPAY_INSTALL_DIR."
    fi
    if [ -z "$(find "$INSTALL_DIR" -prune -user "$(id -u)")" ] || [ ! -w "$INSTALL_DIR" ]; then
      fail "Install directory" "$INSTALL_DIR is not owned by or writable for $(id -un)" \
        "Run: sudo chown -R $(id -un) $(pretty_path "$INSTALL_DIR")  then run the installer again."
    fi
  fi
}

# Whether a non-empty directory belongs to AgentPay: this installer, the previous installer, or
# the client's per-user state.
install_dir_is_recognized() {
  [ -f "$1/installer.json" ] || [ -d "$1/versions" ] || [ -L "$1/current" ] ||
    [ -f "$1/one-click-install-manifest.json" ] || [ -e "$1/bin/agentpay" ] ||
    [ -L "$1/bin/agentpay" ] || [ -x "$1/bin/agentpay-daemon" ] || [ -x "$1/bin/agentpay-admin" ] ||
    [ -f "$1/client.json" ] || [ -d "$1/agent-auth" ]
}

check_releases_url() {
  RELEASES_URL=${AGENTPAY_RELEASES_URL:-$DEFAULT_RELEASES_URL}
  RELEASES_URL=${RELEASES_URL%/}
  case $RELEASES_URL in
    https://* | file:///*) ;;
    *)
      fail "Release" "refusing to download from $RELEASES_URL" \
        "Use an https:// (or local file://) AGENTPAY_RELEASES_URL."
      ;;
  esac
}

# Downloads SHA256SUMS and works out the version, asset name and expected digest.
resolve_release() {
  requested=${AGENTPAY_VERSION:-latest}
  if [ "$requested" = latest ]; then
    sums_url="$RELEASES_URL/latest/download/SHA256SUMS"
  else
    requested=${requested#v}
    case $requested in
      "" | *[!0-9A-Za-z.+-]*)
        fail "Release" "AGENTPAY_VERSION=$AGENTPAY_VERSION is not a version" \
          "Set AGENTPAY_VERSION to a release such as 0.6.0, or unset it for the latest."
        ;;
    esac
    sums_url="$RELEASES_URL/download/v$requested/SHA256SUMS"
  fi
  SUMS_FILE="$TMP_DIR/SHA256SUMS"
  if ! fetch "$sums_url" "$SUMS_FILE"; then
    fail "Release" "could not download $sums_url" \
      "Check your network connection and that release ${requested} exists, then try again."
  fi

  suffix="-$OS-$ARCH.tar.gz"
  if [ "$requested" = latest ]; then
    # agentpay-<version><suffix>: only the version is checked against the version characters;
    # the suffix holds the arch, and x86_64 has an underscore.
    ASSET=$(awk -v suffix="$suffix" '{
      name = $2; sub(/^\*/, "", name)
      cut = length(name) - length(suffix)
      if (cut > 9 && substr(name, cut + 1) == suffix && substr(name, 1, 9) == "agentpay-" &&
          substr(name, 10, cut - 9) ~ /^[0-9A-Za-z.+-]+$/) print name
    }' "$SUMS_FILE")
    count=$(printf '%s\n' "$ASSET" | grep -c . || true)
    if [ "$count" != 1 ]; then
      fail "Release" "the latest release has no single build for $OS_NAME $ARCH" \
        "Check $RELEASES_URL for a build for this machine, or set AGENTPAY_VERSION."
    fi
    VERSION=${ASSET#agentpay-}
    VERSION=${VERSION%"$suffix"}
    release_label="$VERSION (latest)"
  else
    VERSION=$requested
    ASSET="agentpay-$VERSION$suffix"
    release_label=$VERSION
  fi

  EXPECTED_SHA256=$(awk -v name="$ASSET" '$2 == name || $2 == "*" name { print $1 }' "$SUMS_FILE")
  if [ "$(printf '%s\n' "$EXPECTED_SHA256" | grep -c . || true)" != 1 ] ||
    ! is_sha256 "$EXPECTED_SHA256"; then
    fail "Release" "SHA256SUMS of $VERSION has no valid entry for $ASSET" \
      "Check $RELEASES_URL for a build for $OS_NAME $ARCH."
  fi
  if [ -n "${AGENTPAY_SHA256:-}" ]; then
    pinned=$(lowercase "$AGENTPAY_SHA256")
    if ! is_sha256 "$pinned"; then
      fail "Release" "AGENTPAY_SHA256 is not a SHA-256 digest" "Set it to 64 hex characters, or unset it."
    fi
    if [ "$pinned" != "$EXPECTED_SHA256" ]; then
      fail "Release" "SHA256SUMS lists $EXPECTED_SHA256 for $ASSET, not the pinned AGENTPAY_SHA256" \
        "Nothing was installed. Check AGENTPAY_SHA256 and AGENTPAY_VERSION."
    fi
  fi
  TARBALL_URL="$RELEASES_URL/download/v$VERSION/$ASSET"
  step "Release" "$release_label"
}

download_and_verify() {
  TARBALL="$TMP_DIR/$ASSET"
  if ! fetch "$TARBALL_URL" "$TARBALL"; then
    fail "Download" "could not download $TARBALL_URL" \
      "Check your network connection, then run the installer again."
  fi
  bytes=$(wc -c <"$TARBALL" | tr -d ' ')
  step "Download" "$ASSET ($(awk -v b="$bytes" 'BEGIN { printf "%.1f MB", b / 1048576 }'))"

  # Verify before extracting: nothing from an unverified archive touches the disk.
  actual=$(sha256_of "$TARBALL")
  if [ "$actual" != "$EXPECTED_SHA256" ]; then
    fail "Checksum" "SHA-256 mismatch for $ASSET (expected $EXPECTED_SHA256, got $actual)" \
      "Nothing was installed. Run the installer again; if it keeps failing, report it at $ISSUES_URL."
  fi
  step "Checksum" "SHA-256 verified ($(printf '%s' "$actual" | cut -c1-12)…)"
}

extract_release() {
  mkdir "$TMP_DIR/extract"
  log "extract $ASSET"
  if ! tar -xzf "$TARBALL" -C "$TMP_DIR/extract"; then
    fail "Install" "could not extract $ASSET" "Run the installer again."
  fi
  RELEASE_ROOT="$TMP_DIR/extract/${ASSET%.tar.gz}"
  manifest="$RELEASE_ROOT/manifest.json"
  if [ ! -f "$manifest" ] || [ ! -x "$RELEASE_ROOT/bin/agentpay" ] ||
    [ "$(json_field "$manifest" version)" != "$VERSION" ] ||
    [ "$(json_field "$manifest" os)" != "$OS" ] ||
    [ "$(json_field "$manifest" arch)" != "$ARCH" ]; then
    fail "Install" "$ASSET is not an AgentPay $VERSION release for $OS_NAME $ARCH" \
      "Report it at $ISSUES_URL."
  fi
}

# Decides what happens to an existing install before anything is changed.
plan_existing_install() {
  LEGACY_FOUND=""
  for item in $LEGACY_ITEMS; do
    if [ -e "$INSTALL_DIR/$item" ] || [ -L "$INSTALL_DIR/$item" ]; then
      LEGACY_FOUND="$LEGACY_FOUND $item"
    fi
  done
  if [ -f "$INSTALL_DIR/bin/agentpay" ] && [ ! -L "$INSTALL_DIR/bin/agentpay" ]; then
    LEGACY_FOUND="$LEGACY_FOUND bin/agentpay"
  fi
  if [ -d "$INSTALL_DIR/current" ] && [ ! -L "$INSTALL_DIR/current" ]; then
    fail "Install" "$INSTALL_DIR/current is a directory, not a link to a version" \
      "Move $(pretty_path "$INSTALL_DIR/current") aside, then run the installer again."
  fi

  if [ -n "$LEGACY_FOUND" ]; then
    LEGACY_DIR="$INSTALL_DIR/legacy"
    if [ -e "$LEGACY_DIR" ]; then
      LEGACY_DIR="$INSTALL_DIR/legacy-$(date +%Y%m%d%H%M%S)"
    fi
    if ! confirm "Move the previous AgentPay install's files to $(pretty_path "$LEGACY_DIR")?" y; then
      fail "Previous install" "kept as is" "Nothing was installed. Rerun with --yes to replace it."
    fi
  fi

  PREVIOUS_VERSION=""
  if [ -f "$INSTALL_DIR/installer.json" ]; then
    PREVIOUS_VERSION=$(json_field "$INSTALL_DIR/installer.json" version)
  fi
  if [ -n "$PREVIOUS_VERSION" ] && version_lt "$VERSION" "$PREVIOUS_VERSION"; then
    if ! confirm "AgentPay $PREVIOUS_VERSION is installed. Downgrade to $VERSION?" n; then
      fail "Install" "AgentPay $PREVIOUS_VERSION is newer than $VERSION" \
        "Nothing was changed. Rerun with --yes to downgrade."
    fi
  fi
}

move_legacy_install() {
  [ -n "$LEGACY_FOUND" ] || return 0
  mkdir -p "$LEGACY_DIR/bin"
  for item in $LEGACY_FOUND; do
    log "move $item to $LEGACY_DIR"
    mv "$INSTALL_DIR/$item" "$LEGACY_DIR/$item"
  done
  step "Previous install" "moved to $(pretty_path "$LEGACY_DIR")"
}

install_release() {
  versions="$INSTALL_DIR/versions"
  mkdir -p "$versions"
  STAGING_DIR="$versions/.$VERSION.partial.$$"
  rm -rf "$STAGING_DIR"
  mv "$RELEASE_ROOT" "$STAGING_DIR"
  # agentpay-setup (run as root) only copies binaries that nobody else can modify.
  chmod -R go-w "$STAGING_DIR"
  if [ "$OS" = macos ] && have xattr; then
    xattr -dr com.apple.quarantine "$STAGING_DIR" 2>/dev/null || true
  fi
  log "check $STAGING_DIR/bin/agentpay --version"
  if ! "$STAGING_DIR/bin/agentpay" --version >/dev/null 2>"$TMP_DIR/version.err"; then
    fail "Install" "AgentPay $VERSION does not start on this machine: $(head -n 1 "$TMP_DIR/version.err")" \
      "Nothing was changed. Report it at $ISSUES_URL."
  fi

  if [ -n "$LEGACY_FOUND" ]; then
    move_legacy_install
  fi
  target="$versions/$VERSION"
  if [ -e "$target" ]; then
    mv "$target" "$versions/.$VERSION.old.$$"
  fi
  mv "$STAGING_DIR" "$target"
  STAGING_DIR=""
  ln -sfn "versions/$VERSION" "$INSTALL_DIR/current"

  # Only the active version is kept.
  for old in "$versions"/* "$versions"/.[!.]*; do
    if [ -e "$old" ] && [ "$old" != "$target" ]; then
      log "remove $old"
      rm -rf "$old"
    fi
  done

  if [ -z "$PREVIOUS_VERSION" ]; then
    detail=$(pretty_path "$target")
  elif [ "$PREVIOUS_VERSION" = "$VERSION" ]; then
    detail="$(pretty_path "$target") (reinstalled)"
  else
    detail="$(pretty_path "$target") (was $PREVIOUS_VERSION)"
  fi
  step "Install" "$detail"
}

link_commands() {
  BIN_DIR="$INSTALL_DIR/bin"
  mkdir -p "$BIN_DIR"
  for name in agentpay agentpay-setup; do
    link="$BIN_DIR/$name"
    if [ -e "$link" ] && [ ! -L "$link" ]; then
      fail "Command" "$link exists and is not a link" "Move $(pretty_path "$link") aside, then run the installer again."
    fi
    ln -sfn "../current/bin/$name" "$link"
  done
  step "Command" "$(pretty_path "$BIN_DIR/agentpay")"
}

# The shell startup file that should put $BIN_DIR on PATH, for the user's login shell.
rc_file() {
  case $(basename "${SHELL:-sh}") in
    zsh) printf '%s\n' "${ZDOTDIR:-$HOME}/.zshrc" ;;
    bash)
      if [ "$OS" = macos ]; then
        # Terminal windows run login shells, which read the first of these that exists.
        for candidate in "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.profile"; do
          if [ -f "$candidate" ]; then
            printf '%s\n' "$candidate"
            return
          fi
        done
        printf '%s\n' "$HOME/.bash_profile"
      else
        printf '%s\n' "$HOME/.bashrc"
      fi
      ;;
    fish) printf '%s\n' "${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/agentpay.fish" ;;
    *) printf '%s\n' "$HOME/.profile" ;;
  esac
}

write_rc_block() {
  case $BIN_DIR in
    "$HOME"/*) path_expr="\$HOME/${BIN_DIR#"$HOME"/}" ;;
    *) path_expr=$BIN_DIR ;;
  esac
  case $1 in
    *.fish)
      cat <<EOF
# Added by the AgentPay installer. Delete this file to undo.
contains -- "$path_expr" \$PATH; or set -gx PATH "$path_expr" \$PATH
EOF
      ;;
    *)
      cat <<EOF
$RC_BEGIN
# Added by the AgentPay installer. Remove this block to undo.
case ":\${PATH}:" in
  *":$path_expr:"*) ;;
  *) export PATH="$path_expr:\$PATH" ;;
esac
$RC_END
EOF
      ;;
  esac
}

# Rewrites <rc> with exactly one AgentPay block (replacing the old installer's block in place),
# into <out>. Fails when a block has no end marker, so user lines are never dropped.
merge_rc_block() {
  awk -v blockfile="$2" -v b1="$RC_BEGIN" -v e1="$RC_END" -v b2="$LEGACY_RC_BEGIN" -v e2="$LEGACY_RC_END" '
    function emit(line) {
      if (done) return
      while ((getline line < blockfile) > 0) print line
      close(blockfile)
      done = 1
    }
    $0 == b1 || $0 == b2 { if (skip) { bad = 1; exit 3 } emit(); skip = 1; next }
    $0 == e1 || $0 == e2 { if (!skip) { bad = 1; exit 3 } skip = 0; next }
    !skip { print; last = $0 }
    END {
      if (bad || skip) exit 3
      if (!done) {
        if (NR > 0 && last != "") print ""
        emit()
      }
    }
  ' "$1" >"$3"
}

setup_path() {
  if [ "$MODIFY_PATH" = 0 ]; then
    RC_PATH=""
    step "PATH" "not changed (--no-modify-path)"
    return
  fi
  RC_PATH=$(rc_file)
  block="$TMP_DIR/rc-block"
  write_rc_block "$RC_PATH" >"$block"
  mkdir -p "$(dirname "$RC_PATH")"
  [ -e "$RC_PATH" ] || : >"$RC_PATH"
  case $RC_PATH in
    *.fish) cp "$block" "$TMP_DIR/rc.new" ;;
    *)
      if ! merge_rc_block "$RC_PATH" "$block" "$TMP_DIR/rc.new"; then
        RC_PATH=""
        step "PATH" "not changed: $(pretty_path "$(rc_file)") has an unfinished AgentPay block"
        return
      fi
      ;;
  esac
  if cmp -s "$RC_PATH" "$TMP_DIR/rc.new"; then
    step "PATH" "already set in $(pretty_path "$RC_PATH")"
    return
  fi
  if [ ! -w "$RC_PATH" ]; then
    RC_PATH=""
    step "PATH" "not changed: $(pretty_path "$(rc_file)") is not writable"
    return
  fi
  # Write through the existing path so a symlinked rc file keeps its target, owner and mode.
  cat "$TMP_DIR/rc.new" >"$RC_PATH"
  step "PATH" "added to $(pretty_path "$RC_PATH")"
}

write_install_record() {
  record="$INSTALL_DIR/installer.json"
  if [ -n "$RC_PATH" ]; then rc_json=$(json_string "$RC_PATH"); else rc_json=null; fi
  (
    umask 077
    cat >"$record.tmp" <<EOF
{
  "installer": 1,
  "version": "$VERSION",
  "os": "$OS",
  "arch": "$ARCH",
  "asset": "$ASSET",
  "sha256": "$EXPECTED_SHA256",
  "source": $(json_string "$TARBALL_URL"),
  "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "path_rc": $rc_json
}
EOF
  )
  mv "$record.tmp" "$record"
}

print_summary() {
  printf '\nAgentPay %s is installed.\n\n' "$VERSION"
  printf '%s' "$STEPS"
  printf '\n'
  if [ -n "${AGENTPAY_HOME:-}" ] && [ "$AGENTPAY_HOME" != "$HOME/.agentpay" ]; then
    printf 'Note: AGENTPAY_HOME is set in this shell, so your AgentPay settings are kept in\n'
    printf '      %s. If the previous installer set it, open a new terminal first.\n\n' \
      "$(pretty_path "$AGENTPAY_HOME")"
  fi
  case ":$PATH:" in
    *":$BIN_DIR:"*) next="agentpay setup" ;;
    *) next="$(pretty_path "$BIN_DIR")/agentpay setup" ;;
  esac
  printf 'Next: %s\n' "$next"
  printf '      Installs the AgentPay services (asks for your password via sudo) and creates\n'
  printf '      your wallet.'
  if [ "$next" != "agentpay setup" ] && [ -n "$RC_PATH" ]; then
    printf ' New terminals have agentpay on PATH.'
  fi
  printf '\n'
}

main() {
  parse_args "$@"
  umask 022
  if [ "$(id -u)" = 0 ]; then
    fail "User" "the installer is running as root" \
      "Run it as your normal user; \`agentpay setup\` asks for sudo when it needs it."
  fi
  if [ -z "${HOME:-}" ] || [ ! -d "$HOME" ]; then
    fail "User" "HOME is not set to a directory" "Run the installer from a normal login shell."
  fi
  have tar || fail "Platform" "tar is not installed" "Install tar, then run the installer again."

  detect_platform
  check_releases_url
  resolve_install_dir
  TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/agentpay-install.XXXXXX")
  trap cleanup EXIT
  trap 'exit 1' HUP INT TERM

  resolve_release
  download_and_verify
  extract_release

  if [ ! -d "$INSTALL_DIR" ]; then
    (umask 077 && mkdir -p "$INSTALL_DIR")
  fi
  LOCK_DIR="$INSTALL_DIR/.install-lock"
  if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    LOCK_DIR=""
    fail "Install" "another AgentPay install is running in $(pretty_path "$INSTALL_DIR")" \
      "Wait for it to finish. If none is running, remove $(pretty_path "$INSTALL_DIR")/.install-lock."
  fi
  plan_existing_install
  install_release
  link_commands
  setup_path
  write_install_record
  print_summary
}

main "$@"
