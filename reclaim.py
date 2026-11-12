#!/usr/bin/env python3
# Copyright 2026 md2k
# SPDX-License-Identifier: Apache-2.0
"""disk-reclaim (`reclaim`): find disk space you can safely get back, then choose what to clean.

Standard library only, Python 3.9+. Built for macOS; the generic detectors also work on Linux.
Nothing is deleted without an explicit confirmation.
"""
from __future__ import annotations

import argparse
import errno
import json
import locale
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set, Tuple

try:
    import curses
except ImportError:  # e.g. Windows without windows-curses; --dry-run still works
    curses = None  # type: ignore[assignment]

__version__ = "0.1.0"

IS_MAC = sys.platform == "darwin"
DAY = 86400.0
MiB = 1024 ** 2
GiB = 1024 ** 3

# Tests swap these out.
_run = subprocess.run
_which = shutil.which


def _sudo_user() -> Optional[str]:
    """The real user when running under sudo, else None."""
    user = os.environ.get("SUDO_USER")
    if user and user != "root" and hasattr(os, "geteuid") and os.geteuid() == 0:
        return user
    return None


def _home() -> str:
    if SUDO_USER:  # under sudo, work on the invoking user's home, not root's
        try:
            import pwd
            return os.path.realpath(pwd.getpwnam(SUDO_USER).pw_dir)
        except (ImportError, KeyError):
            pass
    return os.path.realpath(os.path.expanduser("~"))


SUDO_USER = _sudo_user()
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
HOME = _home()

# Item status: decides the default selection and whether an item can be selected at all.
PRESELECT = "preselect"  # safe and stale: selected by default
OPTIONAL = "optional"    # safe, but recent or costly to get back: off by default
REVIEW = "review"        # may hold real data: off by default, check before selecting
PROTECTED = "protected"  # in use, active or not backed up: cannot be selected


# ---------------------------------------------------------------- model


@dataclass
class Item:
    label: str
    size: int                              # allocated bytes; -1 = unknown
    status: str
    note: str = ""
    last_used: Optional[float] = None
    path: Optional[str] = None             # removed with rm when set
    guard: Optional[str] = None            # path must stay strictly under this folder
    expect_name: Optional[str] = None      # path basename must still match at delete time
    command: Optional[List[str]] = None    # run instead of rm when set
    as_user: bool = False                  # under sudo, run the command as the invoking user
    selected: bool = False

    def __post_init__(self) -> None:
        self.selected = self.status == PRESELECT

    @property
    def selectable(self) -> bool:
        return self.status != PROTECTED

    def action(self) -> str:
        if self.command:
            return " ".join([os.path.basename(self.command[0])] + self.command[1:])
        if self.path:
            return f"delete {self.path}"
        return "nothing to do"


@dataclass
class Category:
    key: str
    title: str
    hint: str                              # how the space comes back, or what it costs
    items: List[Item] = field(default_factory=list)

    def total(self) -> int:
        return sum_size(self.items)

    def selected_size(self) -> int:
        return sum_size([i for i in self.items if i.selected])

    def size_known(self) -> bool:
        return any(i.size >= 0 for i in self.items)


def sum_size(items: List[Item]) -> int:
    return sum(i.size for i in items if i.size > 0)


def selected_items(cats: List[Category]) -> List[Item]:
    return [i for c in cats for i in c.items if i.selected and i.selectable]


@dataclass
class Config:
    roots: List[str]
    older_than: float = 7.0                # days; project leftovers unused longer are preselected
    big_file: int = GiB                    # files at least this big are listed; 0 = off
    min_size: int = MiB                    # smaller project leftovers are not listed


# ---------------------------------------------------------------- helpers


def human(n: float) -> str:
    if n < 0:
        return "?"
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024 or unit == "T":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return "?"


def age(ts: Optional[float], now: Optional[float] = None) -> str:
    if not ts:
        return "-"
    days = ((now or time.time()) - ts) / DAY
    return "today" if days < 1 else f"{int(days)}d"


def short(path: str) -> str:
    if path == HOME:
        return "~"
    if path.startswith(HOME + os.sep):
        return "~" + path[len(HOME):]
    return path


def norm(path: str) -> str:
    return os.path.realpath(os.path.expanduser(path))


def is_under(path: str, dirs: List[str]) -> bool:
    """True when path is one of dirs or inside one of them."""
    for d in dirs:
        d = d.rstrip(os.sep) or os.sep
        if path == d or path.startswith(d if d == os.sep else d + os.sep):
            return True
    return False


def _alloc(st: os.stat_result) -> int:
    blocks = getattr(st, "st_blocks", None)
    return blocks * 512 if blocks is not None else st.st_size


class Denied:
    """Folders the scan couldn't read, split by what would fix it."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.no_permission: List[str] = []   # EACCES: sudo helps
        self.privacy: List[str] = []         # EPERM: macOS privacy protection; sudo doesn't help

    def note(self, path: str, err: OSError) -> None:
        if err.errno == errno.EACCES:
            self.no_permission.append(path)
        elif err.errno == errno.EPERM:
            self.privacy.append(path)

    def warnings(self) -> List[str]:
        out = []
        if self.no_permission:
            msg = (f"{len(self.no_permission)} folder(s) couldn't be read (permission denied), "
                   f"e.g. {short(self.no_permission[0])}")
            out.append(msg if IS_ROOT else msg + "; run with sudo to include them")
        if self.privacy:
            out.append(f"{len(self.privacy)} folder(s) are blocked by macOS privacy protection, "
                       f"e.g. {short(self.privacy[0])}; sudo doesn't help there: give your terminal "
                       "Full Disk Access (System Settings > Privacy & Security)")
        return out


DENIED = Denied()


def dir_usage(path: str) -> Tuple[int, float]:
    """Allocated bytes under path (like du) and the latest time anything inside was used.

    "Used" means file access or modify time, or folder modify time. Folder access times
    are ignored because listing a folder (this scan included) can update them.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return 0, 0.0
    total, latest = _alloc(st), st.st_mtime
    seen: Set[Tuple[int, int]] = set()
    stack = [path]
    while stack:
        d = stack.pop()
        try:
            it = os.scandir(d)
        except OSError as err:
            DENIED.note(d, err)
            continue
        with it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                is_dir = stat.S_ISDIR(st.st_mode)
                if not is_dir and st.st_nlink > 1:
                    key = (st.st_dev, st.st_ino)
                    if key in seen:
                        continue
                    seen.add(key)
                total += _alloc(st)
                if is_dir:
                    stack.append(e.path)
                    latest = max(latest, st.st_mtime)
                else:
                    latest = max(latest, st.st_mtime, st.st_atime)
    return total, latest


def find_tool(name: str) -> Optional[str]:
    """Absolute path of a tool. Also looks in the usual install folders, which sudo drops from PATH."""
    extra = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/local/go/bin",
             os.path.join(HOME, "go", "bin"), os.path.join(HOME, "bin")]
    return _which(name, path=os.pathsep.join([os.environ.get("PATH", "")] + extra))


def as_user(cmd: List[str]) -> List[str]:
    """Under sudo, run cmd as the invoking user (Homebrew, Go and npm caches are theirs)."""
    return ["sudo", "-u", SUDO_USER, "-H", "--"] + cmd if SUDO_USER else cmd


def _cmd_out(cmd: List[str], timeout: float = 30, any_rc: bool = False, user: bool = False) -> Optional[str]:
    """stdout of a command, or None when the tool is missing or fails."""
    tool = find_tool(cmd[0])
    if not tool:
        return None
    full = [tool] + cmd[1:]
    try:
        r = _run(as_user(full) if user else full, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0 and not (any_rc and r.stdout):
        return None
    return r.stdout


class Progress:
    """One self-overwriting status line on stderr while scanning."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self.dirs = 0
        self._last = 0.0

    def tick(self, path: str) -> None:
        self.dirs += 1
        now = time.monotonic()
        if self.enabled and now - self._last >= 0.1:
            self._last = now
            self.show(f"scanning {self.dirs} folders  {short(path)}")

    def show(self, text: str) -> None:
        if not self.enabled:
            return
        w = max(20, shutil.get_terminal_size((80, 20)).columns - 1)
        sys.stderr.write("\r" + text[:w].ljust(w))
        sys.stderr.flush()

    def done(self) -> None:
        if self.enabled:
            w = max(20, shutil.get_terminal_size((80, 20)).columns - 1)
            sys.stderr.write("\r" + " " * w + "\r")
            sys.stderr.flush()


# ---------------------------------------------------------------- project leftovers


@dataclass(frozen=True)
class Rule:
    category: str
    rebuild: str
    markers: Tuple[str, ...] = ()          # one of these must sit next to the folder
    inside: str = ""                        # this must exist inside the folder
    status: Optional[str] = None            # fixed status instead of the age rule


PROJECT_MARKERS = (
    "package.json", "pyproject.toml", "setup.py", "go.mod", "Cargo.toml", "pom.xml",
    "build.gradle", "build.gradle.kts", "CMakeLists.txt", "Makefile",
)
_VENV = Rule("python venvs", "recreate the venv", inside="pyvenv.cfg")
_BUILD = Rule("build / dist (review)", "re-run the project build", markers=PROJECT_MARKERS, status=REVIEW)

RULES: Dict[str, Rule] = {
    ".terraform": Rule(".terraform", "terraform init (+ workspace select)"),
    ".terragrunt-cache": Rule(".terragrunt-cache", "terragrunt init"),
    "node_modules": Rule("node_modules", "npm / yarn / pnpm install", markers=("package.json",)),
    ".venv": _VENV,
    "venv": _VENV,
    "target": Rule("target (rust / maven)", "cargo build / mvn package", markers=("Cargo.toml", "pom.xml")),
    ".next": Rule(".next", "next build", markers=("package.json",)),
    ".nuxt": Rule(".nuxt", "nuxt build", markers=("package.json",)),
    "__pycache__": Rule("__pycache__", "recreated automatically"),
    "build": _BUILD,
    "dist": _BUILD,
}

# Never walked into, anywhere.
SKIP_NAMES = frozenset({".git", ".hg", ".svn", "node_modules", "site-packages"})
# App bundles and media libraries: their insides are not yours to clean.
PACKAGE_RE = re.compile(
    r"\.(app|photoslibrary|musiclibrary|tvlibrary|fcpbundle|imovielibrary|lrlibrary|bundle|framework|xcarchive)$",
    re.IGNORECASE,
)
# Skipped directly under the home folder; hidden folders there are skipped too
# (tool state like ~/.nvm or ~/.vscode, where node_modules are installed tools).
HOME_SKIP = frozenset({"Library", "Applications"})


def _rule_applies(rule: Rule, path: str, sibling_names: Set[str]) -> bool:
    if rule.markers and not any(m in sibling_names for m in rule.markers):
        return False
    if rule.inside and not os.path.exists(os.path.join(path, rule.inside)):
        return False
    return True


def tool_dirs() -> List[str]:
    """Package stores under the home folder that the walk must never clean from inside."""
    dirs = {os.path.join(HOME, "go", "pkg")}
    for var in ("GOMODCACHE", "GOPATH"):
        out = (_cmd_out(["go", "env", var], user=True) or "").strip()
        if out:
            dirs.add(out if var == "GOMODCACHE" else os.path.join(out.split(os.pathsep)[0], "pkg"))
    return sorted(norm(d) for d in dirs)


Found = Tuple[Rule, str, str]          # rule, path, root
BigFile = Tuple[str, int, float, str]  # path, allocated bytes, last used, root


def walk_roots(cfg: Config, progress: Optional[Progress] = None,
               skip: Optional[List[str]] = None) -> Tuple[List[Found], List[BigFile]]:
    """Find project leftovers (and big files) under the roots. Folders in skip are never entered."""
    skip = list(skip or [])
    found: List[Found] = []
    big: List[BigFile] = []
    seen: Set[str] = set()
    for root in cfg.roots:
        if not os.path.isdir(root) or os.path.islink(root):
            continue
        root_dev = os.lstat(root).st_dev
        stack = [root]
        while stack:
            d = stack.pop()
            if d in seen:
                continue
            seen.add(d)
            if progress:
                progress.tick(d)
            try:
                with os.scandir(d) as it:
                    entries = list(it)
            except OSError as err:
                DENIED.note(d, err)
                continue
            names = {e.name for e in entries}
            home_top = d == HOME
            for e in entries:
                try:
                    if e.is_dir(follow_symlinks=False):
                        p = e.path
                        if is_under(p, skip):
                            continue
                        if home_top and (e.name.startswith(".") or e.name in HOME_SKIP):
                            continue
                        rule = RULES.get(e.name)
                        if rule and _rule_applies(rule, p, names):
                            if p not in seen:
                                seen.add(p)
                                found.append((rule, p, root))
                            continue
                        if e.name in SKIP_NAMES or PACKAGE_RE.search(e.name):
                            continue
                        if e.stat(follow_symlinks=False).st_dev != root_dev:
                            continue  # another file system
                        stack.append(p)
                    elif cfg.big_file and e.is_file(follow_symlinks=False):
                        st = e.stat(follow_symlinks=False)
                        if st.st_size >= cfg.big_file:
                            big.append((e.path, _alloc(st), max(st.st_mtime, st.st_atime), root))
                except OSError:
                    continue
    return found, big


def detect_artifacts(cfg: Config, found: List[Found], now: float,
                     progress: Optional[Progress] = None) -> List[Category]:
    cats: Dict[str, Category] = {}
    for n, (rule, path, root) in enumerate(found, 1):
        if progress:
            progress.show(f"sizing {n}/{len(found)}  {short(path)}")
        size, last = dir_usage(path)
        if size < cfg.min_size:
            continue
        idle = (now - last) / DAY
        if rule.status:
            status, note = rule.status, "may hold real files"
        elif idle > cfg.older_than:
            status, note = PRESELECT, f"unused {int(idle)}d"
        else:
            status, note = OPTIONAL, "used recently"
        cat = cats.setdefault(rule.category, Category(
            key="artifact:" + rule.category, title=rule.category,
            hint=f"comes back with: {rule.rebuild}"))
        cat.items.append(Item(label=short(path), size=size, status=status, note=note,
                              last_used=last, path=path, guard=root,
                              expect_name=os.path.basename(path)))
    return list(cats.values())


def detect_big_files(big: List[BigFile]) -> Optional[Category]:
    if not big:
        return None
    cat = Category("big-files", "big files (review)", "only you know whether these still matter")
    for path, size, last, root in big:
        cat.items.append(Item(label=short(path), size=size, status=REVIEW, note="check before deleting",
                              last_used=last, path=path, guard=root,
                              expect_name=os.path.basename(path)))
    return cat


# ---------------------------------------------------------------- tool caches


def detect_caches() -> Category:
    cat = Category("caches", "tool caches", "downloaded or rebuilt again on next use")
    lib = os.path.join(HOME, "Library", "Caches") if IS_MAC else os.path.join(HOME, ".cache")

    def add(label: str, path: Optional[str], command: Optional[List[str]] = None, note: str = "") -> None:
        if not path:
            return
        path = norm(path)
        if not os.path.isdir(path):
            return
        size, last = dir_usage(path)
        if size < MiB:
            return
        where = short(path)
        cat.items.append(Item(
            label=label, size=size, status=OPTIONAL, note=f"{note}; {where}" if note else where,
            last_used=last, path=None if command else path,
            guard=None if command else os.path.dirname(path),
            expect_name=None if command else os.path.basename(path),
            command=command, as_user=bool(command)))

    def tool_cmd(name: str, *args: str) -> Optional[List[str]]:
        tool = find_tool(name)
        return [tool, *args] if tool else None

    gocache = (_cmd_out(["go", "env", "GOCACHE"], user=True) or "").strip() or os.path.join(lib, "go-build")
    add("go build cache", gocache, tool_cmd("go", "clean", "-cache"), "slower next build")
    gomod = (_cmd_out(["go", "env", "GOMODCACHE"], user=True) or "").strip() or os.path.join(HOME, "go", "pkg", "mod")
    add("go module cache", gomod, tool_cmd("go", "clean", "-modcache"), "modules download again")
    add("npm cache", os.path.join(HOME, ".npm", "_cacache"), tool_cmd("npm", "cache", "clean", "--force"))
    add("yarn cache", os.path.join(lib, "Yarn") if IS_MAC else os.path.join(lib, "yarn"))
    add("pip cache", os.path.join(lib, "pip"))
    brew = (_cmd_out(["brew", "--cache"], user=True) or "").strip()
    add("homebrew cache", brew or None, tool_cmd("brew", "cleanup", "-s"), "also removes old formula versions")
    add("playwright browsers", os.path.join(lib, "ms-playwright"), None, "npx playwright install brings them back")
    if IS_MAC:
        add("vs code updater leftovers", os.path.join(lib, "com.microsoft.VSCode.ShipIt"))
    return cat


TF_VERSION_KEEP_DAYS = 90


def detect_tf_versions(now: float, vdir: Optional[str] = None,
                       active_candidates: Optional[List[str]] = None) -> Optional[Category]:
    """Old terraform binaries downloaded by tfswitch. The one terraform points at is protected."""
    vdir = norm(vdir or os.path.join(HOME, ".terraform.versions"))
    if not os.path.isdir(vdir):
        return None
    if active_candidates is None:
        active_candidates = [c for c in (find_tool("terraform"), os.path.join(HOME, "bin", "terraform")) if c]
    active = {os.path.realpath(c) for c in active_candidates if os.path.lexists(c)}
    cat = Category("tf-versions", "terraform versions (tfswitch)",
                   "tfswitch downloads a version again when a project asks for it")
    with os.scandir(vdir) as it:
        for e in it:
            if not e.name.startswith("terraform_") or ".asc" in e.name or not e.is_file(follow_symlinks=False):
                continue
            st = e.stat(follow_symlinks=False)
            last = max(st.st_mtime, st.st_atime)
            idle = (now - last) / DAY
            if os.path.realpath(e.path) in active:
                status, note = PROTECTED, "active: terraform points here"
            elif idle > TF_VERSION_KEEP_DAYS:
                status, note = PRESELECT, f"unused {int(idle)}d"
            else:
                status, note = OPTIONAL, "used recently"
            cat.items.append(Item(label=e.name, size=_alloc(st), status=status, note=note, last_used=last,
                                  path=e.path, guard=vdir, expect_name=e.name))
    return cat


# ---------------------------------------------------------------- browser code-sign clones (macOS)


_CLONE_RE = re.compile(r"\.code_sign_clone/([^/\n]+)")


def parse_lsof_clones(out: str) -> Set[str]:
    """Clone folder names held open by any process, from `lsof -Fn` output."""
    return {m.group(1) for line in out.splitlines() if line.startswith("n") for m in _CLONE_RE.finditer(line)}


def user_tmpdir() -> str:
    """The invoking user's per-user temp folder (…/T/)."""
    if not SUDO_USER and os.environ.get("TMPDIR"):
        return os.environ["TMPDIR"]
    return (_cmd_out(["getconf", "DARWIN_USER_TEMP_DIR"], user=True) or "").strip()


def detect_browser_clones(tmpdir: Optional[str] = None) -> Optional[Category]:
    """Chrome-family browsers clone their app bundle at launch and should delete it on exit.

    A crash, force-quit or restart with the browser open leaves the clone behind.
    """
    tmpdir = tmpdir if tmpdir is not None else user_tmpdir()
    if not tmpdir:
        return None
    base = os.path.join(os.path.dirname(norm(tmpdir).rstrip(os.sep)), "X")
    try:
        with os.scandir(base) as it:
            parents = sorted(e.path for e in it
                             if e.name.endswith(".code_sign_clone") and e.is_dir(follow_symlinks=False))
    except OSError:
        return None
    if not parents:
        return None
    out = _cmd_out(["lsof", "-nP", "-Fn"], timeout=120, any_rc=True)
    in_use = parse_lsof_clones(out) if out is not None else None
    cat = Category("browser-clones", "browser code-sign clones",
                   "the running browser keeps its own; the rest are leftovers from launches that didn't quit cleanly")
    for parent in parents:
        app = os.path.basename(parent)[: -len(".code_sign_clone")]
        with os.scandir(parent) as it:
            for e in it:
                if not e.is_dir(follow_symlinks=False):
                    continue
                size, _ = dir_usage(e.path)
                mtime = e.stat(follow_symlinks=False).st_mtime
                if in_use is None:
                    status, note = REVIEW, "couldn't check whether it's in use (lsof failed)"
                elif e.name in in_use:
                    status, note = PROTECTED, "in use"
                else:
                    status, note = PRESELECT, "orphaned"
                cat.items.append(Item(label=f"{app}/{e.name}", size=size, status=status, note=note,
                                      last_used=mtime, path=e.path, guard=parent, expect_name=e.name))
    return cat


# ---------------------------------------------------------------- docker


_DOCKER_UNITS = {"B": 1, "kB": 1e3, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12, "PB": 1e15}


def parse_docker_size(text: str) -> int:
    m = re.match(r"\s*([\d.]+)\s*([kKMGTP]?B)\b", text or "")
    return int(float(m.group(1)) * _DOCKER_UNITS[m.group(2)]) if m else 0


def parse_docker_df(out: str) -> Dict[str, Tuple[int, int]]:
    """{type: (size, reclaimable)} from `docker system df --format '{{json .}}'`."""
    res: Dict[str, Tuple[int, int]] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        res[str(row.get("Type", ""))] = (parse_docker_size(str(row.get("Size", ""))),
                                         parse_docker_size(str(row.get("Reclaimable", ""))))
    return res


def detect_docker() -> Optional[Category]:
    docker = find_tool("docker")
    if not docker:
        return None
    out = _cmd_out(["docker", "system", "df", "--format", "{{json .}}"], timeout=20, user=True)
    if out is None:
        return None  # the daemon isn't running
    df = parse_docker_df(out)
    cat = Category("docker", "docker", "Docker Desktop can take a while to shrink its disk image after a prune")

    def add(label: str, size: int, status: str, note: str, *args: str) -> None:
        cat.items.append(Item(label, size, status, note, command=[docker, *args] if args else None,
                              as_user=bool(args)))

    _, bc = df.get("Build Cache", (0, 0))
    if bc:
        add("build cache", bc, OPTIONAL, "rebuilt on the next docker build", "builder", "prune", "-f")
    _, cont = df.get("Containers", (0, 0))
    if cont:
        add("stopped containers", cont, OPTIONAL, "removes stopped containers", "container", "prune", "-f")
    img_size, img = df.get("Images", (0, 0))
    if img_size:
        add("dangling images", -1, OPTIONAL, "untagged layers only", "image", "prune", "-f")
    if img:
        add("unused images", img, REVIEW, "every image no container uses; you pull them again",
            "image", "prune", "-a", "-f")
    vol, _ = df.get("Local Volumes", (0, 0))
    if vol:
        add("volumes", vol, PROTECTED, "never touched: volumes hold data")
    return cat


# ---------------------------------------------------------------- time machine local snapshots (macOS)


_SNAP_FMT = "%Y-%m-%d-%H%M%S"


def _snap_ts(name: str) -> Optional[float]:
    try:
        return datetime.strptime(name, _SNAP_FMT).timestamp()
    except ValueError:
        return None


def parse_snapshots(out: str) -> List[str]:
    return sorted({m.group(1) for m in re.finditer(r"com\.apple\.TimeMachine\.(\d{4}-\d{2}-\d{2}-\d{6})", out)})


def parse_latest_backup(out: str) -> Optional[float]:
    found = re.findall(r"(\d{4}-\d{2}-\d{2}-\d{6})", out or "")
    return _snap_ts(found[-1]) if found else None


def detect_tm_snapshots() -> Optional[Category]:
    tmutil = find_tool("tmutil")
    if not tmutil:
        return None
    names = parse_snapshots(_cmd_out(["tmutil", "listlocalsnapshots", "/"]) or "")
    if not names:
        return None
    latest = parse_latest_backup(_cmd_out(["tmutil", "latestbackup"]) or "")
    running = bool(re.search(r"Running\s*=\s*1", _cmd_out(["tmutil", "status"]) or ""))
    when = datetime.fromtimestamp(latest).strftime("%m-%d %H:%M") if latest else ""
    cat = Category("tm-snapshots", "time machine local snapshots",
                   "they hold files deleted since they were taken; macOS also drops them after 24h "
                   "or when space runs low")
    for n in names:
        t = _snap_ts(n)
        if running and n == names[-1]:
            status, note = PROTECTED, "a backup is running"
        elif latest is None:
            status, note = REVIEW, "no completed backup found to compare with"
        elif t is not None and t <= latest:
            status, note = OPTIONAL, f"covered by backup {when}"
        else:
            status, note = PROTECTED, f"newer than the last completed backup ({when})"
        cat.items.append(Item(label=f"snapshot {n}", size=-1, status=status, note=note, last_used=t,
                              command=[tmutil, "deletelocalsnapshots", n]))
    return cat


# ---------------------------------------------------------------- scan


def scan(cfg: Config, progress: Optional[Progress] = None) -> Tuple[List[Category], List[str]]:
    now = time.time()
    cats: List[Category] = []
    warnings: List[str] = []
    DENIED.reset()

    def safe(name: str, fn: Callable[[], object]) -> object:
        try:
            return fn()
        except Exception as e:  # one broken detector must not end the whole scan
            warnings.append(f"{name}: {e}")
            return None

    def keep(result: object) -> None:
        for c in result if isinstance(result, list) else [result]:
            if isinstance(c, Category) and c.items:
                cats.append(c)

    walked = safe("walk", lambda: walk_roots(cfg, progress, skip=tool_dirs()))
    found, big = walked if isinstance(walked, tuple) else ([], [])
    keep(safe("project leftovers", lambda: detect_artifacts(cfg, found, now, progress)))
    keep(safe("big files", lambda: detect_big_files(big)))
    if progress:
        progress.show("checking tool caches")
    keep(safe("tool caches", detect_caches))
    keep(safe("terraform versions", lambda: detect_tf_versions(now)))
    if IS_MAC:
        if progress:
            progress.show("checking browser leftovers")
        keep(safe("browser clones", detect_browser_clones))
        keep(safe("time machine", detect_tm_snapshots))
    if progress:
        progress.show("checking docker")
    keep(safe("docker", detect_docker))
    cats.sort(key=lambda c: c.total(), reverse=True)
    return cats, warnings + DENIED.warnings()


# ---------------------------------------------------------------- delete


class Refused(Exception):
    pass


FORBIDDEN = frozenset({os.sep, HOME, "/Users", "/home", "/private", "/var", "/System", "/Library",
                       "/Applications", "/usr", "/opt", "/etc"})


def check_path(item: Item, cfg: Config) -> str:
    """Re-check an rm target right before deleting it. Returns the path or raises Refused."""
    p = item.path
    if not p or not os.path.isabs(p):
        raise Refused("not an absolute path")
    if not os.path.lexists(p):
        raise Refused("no longer exists")
    if os.path.islink(p):
        raise Refused("is a symlink now")
    if os.path.realpath(p) != p:
        raise Refused("path now goes through a symlink")
    if p in FORBIDDEN or p in cfg.roots or p.count(os.sep) < 3:
        raise Refused("too close to the top of the disk")
    if item.guard and not p.startswith(item.guard.rstrip(os.sep) + os.sep):
        raise Refused("outside the folder it was found in")
    if item.expect_name and os.path.basename(p) != item.expect_name:
        raise Refused("name changed")
    return p


def _rm(path: str) -> None:
    if not os.path.isdir(path) or os.path.islink(path):
        os.remove(path)
        return

    def retry(func: Callable[[str], object], p: str) -> None:
        # Read-only folders (e.g. a Go module cache): make writable, try once more.
        os.chmod(os.path.dirname(p), stat.S_IRWXU)
        if os.path.isdir(p) and not os.path.islink(p):
            os.chmod(p, stat.S_IRWXU)
        func(p)

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=lambda f, p, e: retry(f, p))
    else:
        shutil.rmtree(path, onerror=lambda f, p, e: retry(f, p))


@dataclass
class Result:
    item: Item
    ok: bool
    message: str


def execute(items: List[Item], cfg: Config,
            on_progress: Optional[Callable[[int, int, Item], None]] = None) -> List[Result]:
    results: List[Result] = []
    for n, it in enumerate(items, 1):
        if on_progress:
            on_progress(n, len(items), it)
        if not it.selectable:
            results.append(Result(it, False, "protected"))
            continue
        try:
            if it.command:
                cmd = as_user(it.command) if it.as_user else it.command
                r = _run(cmd, capture_output=True, text=True, timeout=1800)
                if r.returncode == 0:
                    results.append(Result(it, True, "done"))
                else:
                    lines = (r.stderr or r.stdout or "").strip().splitlines()
                    results.append(Result(it, False, lines[-1] if lines else f"exit {r.returncode}"))
            elif it.path:
                _rm(check_path(it, cfg))
                results.append(Result(it, True, "deleted"))
            else:
                results.append(Result(it, False, "nothing to do"))
        except Refused as e:
            results.append(Result(it, False, f"refused: {e}"))
        except Exception as e:
            results.append(Result(it, False, str(e)))
    return results


# ---------------------------------------------------------------- report


def headline() -> str:
    du = shutil.disk_usage(HOME)
    who = f"   (as root for {SUDO_USER})" if SUDO_USER else ""
    return f"disk-reclaim {__version__}   {human(du.free)} free of {human(du.total)}{who}"


def print_report(cats: List[Category], limit: int, out=None) -> None:
    out = out or sys.stdout
    now = time.time()
    print(headline() + "\n", file=out)
    if not cats:
        print("nothing found to reclaim", file=out)
        return
    for c in cats:
        total = human(c.total()) if c.size_known() else "?"
        print(f"{c.title}   {total} in {len(c.items)} item(s), selected by default {human(c.selected_size())}",
              file=out)
        print(f"  {c.hint}", file=out)
        items = sorted(c.items, key=lambda i: i.size, reverse=True)
        shown = items if limit == 0 else items[:limit]
        for i in shown:
            mark = "x" if i.selected else ("-" if i.status == PROTECTED else " ")
            print(f"  [{mark}] {human(i.size):>8} {age(i.last_used, now):>6}  {i.status:<9}  {i.label}"
                  + (f"  ({i.note})" if i.note else ""), file=out)
        if len(items) > len(shown):
            print(f"  ... {len(items) - len(shown)} more", file=out)
        print(file=out)
    sel = selected_items(cats)
    print(f"selected by default: {human(sum_size(sel))} in {len(sel)} item(s). "
          "Run reclaim without --dry-run to choose and clean.", file=out)


def report_json(cats: List[Category], warnings: List[str]) -> dict:
    du = shutil.disk_usage(HOME)
    return {
        "version": __version__,
        "disk": {"total": du.total, "free": du.free},
        "categories": [{
            "key": c.key, "title": c.title, "hint": c.hint, "total": c.total(),
            "items": [{
                "label": i.label, "size": i.size, "status": i.status, "note": i.note,
                "last_used": i.last_used, "path": i.path, "command": i.command, "selected": i.selected,
            } for i in c.items],
        } for c in cats],
        "warnings": warnings,
    }


# ---------------------------------------------------------------- picker (curses)


KEYS_MAIN = "↑↓ move  space toggle  a all  → open  c clean  q quit"
KEYS_CAT = "↑↓ move  space toggle  a all  s sort  ← back  c clean  q quit"
SORTS = ("size", "age", "name")


def toggle_items(items: List[Item], include_review: bool) -> None:
    """Select every candidate, or clear all items if every candidate is already selected.

    Candidates are selectable items; review items count only when include_review is set.
    """
    cands = [i for i in items if i.selectable and (include_review or i.status != REVIEW)]
    if cands and not all(i.selected for i in cands):
        for i in cands:
            i.selected = True
    else:
        for i in items:
            i.selected = False


def toggle_category(c: Category) -> str:
    """Space on a category: toggles its safe items. Returns a message when there is nothing to toggle."""
    if not any(i.selectable and i.status != REVIEW for i in c.items):
        if any(i.status == REVIEW for i in c.items):
            return "review items: open the category and pick them one by one"
        return "nothing selectable here"
    toggle_items(c.items, include_review=False)
    return ""


def fit(text: str, width: int) -> str:
    """Shorten text to width, keeping the end (paths are most telling at the end)."""
    if width <= 1:
        return ""
    return text if len(text) <= width else "…" + text[-(width - 1):]


class Tui:
    def __init__(self, scr, cats: List[Category], cfg: Config) -> None:
        self.scr, self.cats, self.cfg = scr, cats, cfg
        self.cat: Optional[Category] = None
        self.main_pos = self.item_pos = self.top = 0
        self.sort = "size"
        self.msg = ""
        self.log: List[Result] = []
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        scr.keypad(True)
        self.a_sel, self.a_review, self.a_prot = curses.A_BOLD, curses.A_NORMAL, curses.A_DIM
        if curses.has_colors():
            curses.start_color()
            bg = -1
            try:
                curses.use_default_colors()
            except curses.error:
                bg = curses.COLOR_BLACK
            curses.init_pair(1, curses.COLOR_GREEN, bg)
            curses.init_pair(2, curses.COLOR_YELLOW, bg)
            curses.init_pair(3, curses.COLOR_RED, bg)
            self.a_sel = curses.color_pair(1) | curses.A_BOLD
            self.a_review = curses.color_pair(2)
            self.a_prot = curses.color_pair(3)

    # -- state

    def rows(self) -> list:
        return self.cat.items if self.cat else self.cats

    def get_pos(self) -> int:
        return self.item_pos if self.cat else self.main_pos

    def set_pos(self, v: int) -> None:
        n = len(self.rows())
        v = max(0, min(v, n - 1)) if n else 0
        if self.cat:
            self.item_pos = v
        else:
            self.main_pos = v

    def list_height(self) -> int:
        return max(1, self.scr.getmaxyx()[0] - 6)

    # -- drawing

    def put(self, y: int, x: int, text: str, attr: int = 0) -> None:
        h, w = self.scr.getmaxyx()
        if 0 <= y < h and 0 <= x < w:
            try:
                self.scr.addnstr(y, x, text, w - x - (1 if y == h - 1 else 0), attr)
            except curses.error:
                pass

    def cat_line(self, c: Category) -> Tuple[str, int]:
        sel = [i for i in c.items if i.selected]
        selectable = [i for i in c.items if i.selectable]
        box = "[x]" if sel and len(sel) == len(selectable) else "[-]" if sel else "[ ]"
        n_prot = len(c.items) - len(selectable)
        n_rev = sum(1 for i in c.items if i.status == REVIEW)
        flags = ", ".join(f for f in (f"{n_prot} protected" if n_prot else "",
                                      f"{n_rev} to review" if n_rev else "") if f)
        total = human(c.total()) if c.size_known() else "?"
        text = (f" {box} {c.title:<30.30} {len(c.items):>5}  {total:>8}"
                f"   sel {human(c.selected_size()):>8}   {flags}")
        attr = self.a_sel if sel else (self.a_review if n_rev and n_rev == len(c.items) else 0)
        return text, attr

    def item_line(self, i: Item, w: int, now: float) -> Tuple[str, int]:
        box = "[x]" if i.selected else "[ ]"
        head = f" {box} {human(i.size):>8} {age(i.last_used, now):>6}  {i.note[:24]:<24}  "
        text = head + fit(i.label, max(1, w - len(head) - 1))
        if i.selected:
            attr = self.a_sel
        elif i.status == REVIEW:
            attr = self.a_review
        elif i.status == PROTECTED:
            attr = self.a_prot
        else:
            attr = 0
        return text, attr

    def detail(self) -> str:
        rows = self.rows()
        if not rows:
            return ""
        row = rows[self.get_pos()]
        if self.cat:
            return f"{row.status}: {row.note}  ·  {row.action()}" if row.note else f"{row.status}: {row.action()}"
        return row.hint

    def draw(self) -> None:
        scr = self.scr
        scr.erase()
        h, w = scr.getmaxyx()
        if h < 10 or w < 60:
            self.put(0, 0, "terminal too small (need 60x10)")
            scr.refresh()
            return
        sel = selected_items(self.cats)
        self.put(0, 0, f" {headline()}   selected {human(sum_size(sel))} in {len(sel)} item(s)".ljust(w),
                 curses.A_REVERSE | curses.A_BOLD)
        if self.cat:
            self.put(1, 1, f"{self.cat.title}   sorted by {self.sort}", curses.A_BOLD)
            self.put(2, 1, fit(self.cat.hint, w - 2), curses.A_DIM)
        else:
            self.put(1, 1, "what can go", curses.A_BOLD)
            self.put(2, 1, fit("space on a category selects its safe items; review items are picked inside it",
                               w - 2), curses.A_DIM)
        rows, lh, pos = self.rows(), self.list_height(), self.get_pos()
        if pos < self.top:
            self.top = pos
        elif pos >= self.top + lh:
            self.top = pos - lh + 1
        self.top = max(0, min(self.top, max(0, len(rows) - lh)))
        if len(rows) > lh:
            span = f"{self.top + 1}-{min(len(rows), self.top + lh)} of {len(rows)}"
            self.put(1, max(1, w - len(span) - 2), span, curses.A_DIM)
        if not rows:
            self.put(3, 2, "nothing left here", curses.A_DIM)
        now = time.time()
        for n, row in enumerate(rows[self.top:self.top + lh]):
            text, attr = self.item_line(row, w, now) if self.cat else self.cat_line(row)
            if self.top + n == pos:
                attr |= curses.A_REVERSE
            self.put(3 + n, 0, text.ljust(w), attr)
        self.put(h - 3, 0, "─" * w, curses.A_DIM)
        self.put(h - 2, 1, fit(self.msg or self.detail(), w - 2), curses.A_BOLD if self.msg else 0)
        self.put(h - 1, 1, KEYS_CAT if self.cat else KEYS_MAIN, curses.A_DIM)
        scr.refresh()

    def dialog(self, title: str, lines: List[str], prompt: str) -> int:
        h, w = self.scr.getmaxyx()
        bw = max(10, min(w - 2, max([len(title) + 6, len(prompt) + 4] + [len(x) + 4 for x in lines])))
        body = max(1, min(len(lines), h - 7))
        bh = body + 5
        win = curses.newwin(bh, bw, max(0, (h - bh) // 2), max(0, (w - bw) // 2))
        win.keypad(True)
        shown = lines if len(lines) <= body else lines[:body - 1] + [f"… {len(lines) - body + 1} more"]
        try:
            win.box()
            win.addnstr(0, 2, f" {title} ", bw - 4, curses.A_BOLD)
            for n, line in enumerate(shown):
                win.addnstr(2 + n, 2, line, bw - 4)
            win.addnstr(bh - 2, 2, prompt, bw - 4, curses.A_BOLD)
        except curses.error:
            pass
        win.refresh()
        key = win.getch()
        del win
        self.scr.touchwin()
        return key

    def progress(self, n: int, total: int, item: Item) -> None:
        h, w = self.scr.getmaxyx()
        self.put(h - 2, 0, " " * (w - 1))
        self.put(h - 2, 1, fit(f"cleaning {n}/{total}: {item.label}", w - 2), curses.A_BOLD)
        self.scr.refresh()

    # -- actions

    def toggle(self) -> None:
        rows = self.rows()
        if not rows:
            return
        row = rows[self.get_pos()]
        if not self.cat:
            self.toggle_category(row)
            return
        if not row.selectable:
            self.msg = f"protected: {row.note}"
            return
        row.selected = not row.selected
        self.set_pos(self.get_pos() + 1)

    def toggle_category(self, c: Category) -> None:
        self.msg = toggle_category(c)

    def toggle_all(self) -> None:
        if self.cat:
            toggle_items(self.cat.items, include_review=True)
        else:
            toggle_items([i for c in self.cats for i in c.items], include_review=False)

    def apply_sort(self) -> None:
        if not self.cat:
            return
        if self.sort == "size":
            self.cat.items.sort(key=lambda i: i.size, reverse=True)
        elif self.sort == "age":
            self.cat.items.sort(key=lambda i: i.last_used or float("inf"))
        else:
            self.cat.items.sort(key=lambda i: i.label.lower())

    def cycle_sort(self) -> None:
        rows = self.rows()
        cur = rows[self.get_pos()] if rows else None
        self.sort = SORTS[(SORTS.index(self.sort) + 1) % len(SORTS)]
        self.apply_sort()
        if cur is not None and self.cat:
            self.set_pos(next(n for n, i in enumerate(self.cat.items) if i is cur))

    def open(self) -> None:
        if self.cat or not self.cats:
            return
        self.cat = self.cats[self.main_pos]
        self.item_pos = self.top = 0
        self.apply_sort()

    def back(self) -> None:
        if not self.cat:
            return
        prev, self.cat, self.top = self.cat, None, 0
        self.set_pos(next((n for n, c in enumerate(self.cats) if c is prev), self.main_pos))

    def clean(self) -> None:
        sel = selected_items(self.cats)
        if not sel:
            self.msg = "nothing selected"
            return
        lines = []
        for c in self.cats:
            s = [i for i in c.items if i.selected and i.selectable]
            if s:
                lines.append(f"{c.title}: {len(s)} item(s), {human(sum_size(s))}")
        cmds = sorted({i.action() for i in sel if i.command})
        if cmds:
            lines += ["", "runs:"] + [f"  {x}" for x in cmds[:8]]
            if len(cmds) > 8:
                lines.append(f"  … {len(cmds) - 8} more")
        n_rm = sum(1 for i in sel if not i.command)
        if n_rm:
            lines += ["", f"deletes {n_rm} folder(s)/file(s) for good (not to the Trash)"]
        key = self.dialog("clean up", lines,
                          f"clean {len(sel)} item(s), {human(sum_size(sel))}?  y = yes, any other key = no")
        if key not in (ord("y"), ord("Y")):
            self.msg = "cancelled, nothing deleted"
            return
        before = shutil.disk_usage(HOME).free
        results = execute(sel, self.cfg, self.progress)
        after = shutil.disk_usage(HOME).free
        self.log += results
        done = {id(x.item) for x in results if x.ok}
        for c in self.cats:
            c.items = [i for i in c.items if id(i) not in done]
        self.cats = [c for c in self.cats if c.items]
        if self.cat is not None and not any(c is self.cat for c in self.cats):
            self.cat = None
        self.set_pos(self.get_pos())
        ok = [x for x in results if x.ok]
        bad = [x for x in results if not x.ok]
        est = sum_size([x.item for x in ok])
        self.msg = f"cleaned {len(ok)}/{len(results)} (~{human(est)}); free space {human(before)} → {human(after)}"
        if est and after - before < est // 2 and any(c.key == "tm-snapshots" for c in self.cats):
            self.msg += "; local snapshots still hold the rest"
        if bad:
            lines = [f"{x.item.label}: {x.message}" for x in bad]
            self.dialog(f"{len(bad)} item(s) not cleaned", lines, "any key to continue")

    def loop(self) -> None:
        while True:
            self.draw()
            k = self.scr.getch()
            self.msg = ""
            lh = self.list_height()
            if k in (ord("q"), ord("Q")):
                return
            elif k in (curses.KEY_UP, ord("k")):
                self.set_pos(self.get_pos() - 1)
            elif k in (curses.KEY_DOWN, ord("j")):
                self.set_pos(self.get_pos() + 1)
            elif k == curses.KEY_PPAGE:
                self.set_pos(self.get_pos() - lh)
            elif k == curses.KEY_NPAGE:
                self.set_pos(self.get_pos() + lh)
            elif k in (curses.KEY_HOME, ord("g")):
                self.set_pos(0)
            elif k in (curses.KEY_END, ord("G")):
                self.set_pos(len(self.rows()) - 1)
            elif k == ord(" "):
                self.toggle()
            elif k == ord("a"):
                self.toggle_all()
            elif k in (curses.KEY_RIGHT, curses.KEY_ENTER, 10, 13, ord("l")):
                self.open()
            elif k in (curses.KEY_LEFT, curses.KEY_BACKSPACE, 127, 27, ord("h")):
                self.back()
            elif k == ord("s") and self.cat:
                self.cycle_sort()
            elif k == ord("c"):
                self.clean()


def run_tui(cats: List[Category], cfg: Config) -> List[Result]:
    os.environ.setdefault("ESCDELAY", "25")  # Esc goes back without a 1 s pause
    locale.setlocale(locale.LC_ALL, "")
    log: List[Result] = []

    def body(scr) -> None:
        tui = Tui(scr, cats, cfg)
        try:
            tui.loop()
        finally:
            log.extend(tui.log)

    curses.wrapper(body)
    return log


def print_log(log: List[Result], out=None) -> None:
    out = out or sys.stdout
    ok = [x for x in log if x.ok]
    print(f"cleaned {len(ok)} of {len(log)} item(s), about {human(sum_size([x.item for x in ok]))}", file=out)
    for x in ok[:50]:
        print(f"  ok   {x.item.action()}", file=out)
    if len(ok) > 50:
        print(f"  ... {len(ok) - 50} more", file=out)
    for x in log:
        if not x.ok:
            print(f"  FAIL {x.item.label}: {x.message}", file=out)


def ask(question: str) -> bool:
    try:
        return input(question).strip().lower() in ("y", "yes")
    except EOFError:
        return False


# ---------------------------------------------------------------- cli


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="reclaim",
        description="Find disk space you can safely get back, then choose what to clean.")
    p.add_argument("--root", action="append", metavar="DIR",
                   help="where to look for project leftovers and big files (repeatable; default: home folder)")
    p.add_argument("--older-than", type=float, default=7, metavar="DAYS",
                   help="preselect project leftovers unused for longer than this (default 7)")
    p.add_argument("--big-file-gb", type=float, default=1, metavar="GB",
                   help="list files at least this big for review (default 1)")
    p.add_argument("--no-big-files", action="store_true", help="skip the big-file listing")
    p.add_argument("--dry-run", action="store_true", help="scan and print a report; never deletes")
    p.add_argument("--json", action="store_true", help="with --dry-run: print the report as JSON")
    p.add_argument("--limit", type=int, default=10, metavar="N",
                   help="with --dry-run: items shown per category (0 = all, default 10)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)
    if args.json and not args.dry_run:
        p.error("--json needs --dry-run")
    if args.limit < 0:
        p.error("--limit must be >= 0")
    if args.older_than < 0:
        p.error("--older-than must be >= 0")
    if args.big_file_gb <= 0:
        p.error("--big-file-gb must be > 0")
    return args


def make_config(args: argparse.Namespace) -> Config:
    return Config(
        roots=[norm(r) for r in (args.root or [HOME])],
        older_than=float(args.older_than),
        big_file=0 if args.no_big_files else int(args.big_file_gb * GiB),
    )


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    cfg = make_config(args)
    if not args.dry_run and (curses is None or not sys.stdin.isatty() or not sys.stdout.isatty()):
        print("reclaim: the picker needs a terminal; use --dry-run for a report", file=sys.stderr)
        return 2
    progress = Progress(enabled=sys.stderr.isatty() and not args.json)
    try:
        cats, warnings = scan(cfg, progress)
    except KeyboardInterrupt:
        progress.done()
        return 130
    progress.done()

    if args.json:
        json.dump(report_json(cats, warnings), sys.stdout, indent=2)
        print()
        return 0
    if args.dry_run:
        print_report(cats, args.limit)
        for w in warnings:
            print(f"warning: {w}", file=sys.stderr)
        return 0

    if DENIED.no_permission and not IS_ROOT:
        for w in warnings:
            print(f"warning: {w}", file=sys.stderr)
        if ask("Re-run with sudo to include them? [y/N] "):
            rest = sys.argv[1:] if argv is None else list(argv)
            os.execvp("sudo", ["sudo", sys.executable, os.path.realpath(__file__)] + rest)
    if not cats:
        print("nothing found to reclaim")
        return 0
    try:
        log = run_tui(cats, cfg)
    except KeyboardInterrupt:
        return 130
    if log:
        print_log(log)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
