# Copyright 2026 md2k
# SPDX-License-Identifier: Apache-2.0
"""Unit tests. Fixtures live under build/test-tmp in the repo; no real tool is ever run."""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import reclaim as r  # noqa: E402

TMP_BASE = os.path.join(REPO, "build", "test-tmp")
DAY = 86400


def mkfile(path, size=0):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(b"x" * size)
    return path


def age_tree(top, days, atime_days=None):
    """Backdate every file and folder under top (bottom-up, so parents keep the old time)."""
    m = time.time() - days * DAY
    a = time.time() - (days if atime_days is None else atime_days) * DAY
    for dp, _, files in os.walk(top, topdown=False):
        for f in files:
            os.utime(os.path.join(dp, f), (a, m))
        os.utime(dp, (m, m))


def fake_run(outputs):
    """A stand-in for subprocess.run: outputs maps a command's args (after the tool) to (rc, stdout)."""
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        key = " ".join(cmd[1:])
        rc, out = outputs.get(key, (1, ""))
        return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr="" if rc == 0 else "boom\nlast line")

    run.calls = calls
    return run


class Base(unittest.TestCase):
    def setUp(self):
        os.makedirs(TMP_BASE, exist_ok=True)
        self.root = os.path.realpath(tempfile.mkdtemp(dir=TMP_BASE))
        r.DENIED.reset()

    def tearDown(self):
        for dp, dirs, _ in os.walk(self.root):
            for d in dirs:
                try:
                    os.chmod(os.path.join(dp, d), 0o755)
                except OSError:
                    pass
        shutil.rmtree(self.root, ignore_errors=True)

    def p(self, *parts):
        return os.path.join(self.root, *parts)

    def cfg(self, **kw):
        kw.setdefault("min_size", 0)
        kw.setdefault("big_file", 0)
        return r.Config(roots=[self.root], **kw)

    def found_paths(self, cfg=None, skip=None):
        found, _ = r.walk_roots(cfg or self.cfg(), skip=skip)
        return sorted(os.path.relpath(p, self.root) for _, p, _ in found)


class WalkTests(Base):
    def test_rules_need_their_markers(self):
        mkfile(self.p("a", ".terraform", "providers", "p"), 10)
        mkfile(self.p("b", "node_modules", "x", "index.js"))            # no package.json: not a project
        mkfile(self.p("c", "package.json"))
        mkfile(self.p("c", "node_modules", "x", "index.js"))
        mkfile(self.p("d", ".venv", "pyvenv.cfg"))
        mkfile(self.p("e", "venv", "notes.txt"))                        # no pyvenv.cfg: someone's folder
        mkfile(self.p("f", "Makefile"))
        mkfile(self.p("f", "build", "out.o"))
        mkfile(self.p("g", "build", "photo.jpg"))                       # no project marker
        self.assertEqual(self.found_paths(),
                         ["a/.terraform", "c/node_modules", "d/.venv", "f/build"])

    def test_nested_node_modules_found_once(self):
        mkfile(self.p("app", "package.json"))
        mkfile(self.p("app", "node_modules", "pkg", "package.json"))
        mkfile(self.p("app", "node_modules", "pkg", "node_modules", "dep", "f.js"))
        self.assertEqual(self.found_paths(), ["app/node_modules"])

    def test_skip_dirs_are_never_entered(self):
        mkfile(self.p("skipme", "proj", ".terraform", "f"))
        mkfile(self.p("keep", ".terraform", "f"))
        seen = []
        real_scandir = os.scandir

        def recording(path="."):
            seen.append(str(path))
            return real_scandir(path)

        with mock.patch.object(r.os, "scandir", recording):
            found = self.found_paths(skip=[self.p("skipme")])
        self.assertEqual(found, ["keep/.terraform"])
        self.assertFalse([s for s in seen if s.startswith(self.p("skipme"))])

    def test_git_and_bundles_are_not_walked(self):
        mkfile(self.p("repo", ".git", "x", ".terraform", "f"))
        mkfile(self.p("Tool.app", "Contents", "package.json"))
        mkfile(self.p("Tool.app", "Contents", "node_modules", "f"))
        self.assertEqual(self.found_paths(), [])

    def test_big_files_listed_for_review(self):
        mkfile(self.p("dl", "image.iso"), 2 * r.MiB)
        mkfile(self.p("dl", "small.txt"), 10)
        _, big = r.walk_roots(self.cfg(big_file=r.MiB))
        cat = r.detect_big_files(big)
        self.assertEqual([i.label.endswith("image.iso") for i in cat.items], [True])
        self.assertEqual(cat.items[0].status, r.REVIEW)
        self.assertFalse(cat.items[0].selected)

    @unittest.skipIf(os.geteuid() == 0, "root can read everything")
    def test_unreadable_folders_are_reported(self):
        locked = self.p("locked")
        os.makedirs(locked)
        os.chmod(locked, 0)
        r.walk_roots(self.cfg())
        self.assertEqual(r.DENIED.no_permission, [locked])
        with mock.patch.object(r, "IS_ROOT", False):
            self.assertIn("run with sudo", r.DENIED.warnings()[0])


class StatusTests(Base):
    def artifacts(self, cfg=None):
        found, _ = r.walk_roots(cfg or self.cfg())
        cats = r.detect_artifacts(cfg or self.cfg(), found, time.time())
        return {os.path.relpath(i.path, self.root): i for c in cats for i in c.items}

    def test_stale_preselected_recent_optional(self):
        mkfile(self.p("old", ".terraform", "f"), 10)
        mkfile(self.p("new", ".terraform", "f"), 10)
        age_tree(self.p("old", ".terraform"), 30)
        items = self.artifacts(self.cfg(older_than=7))
        self.assertEqual(items["old/.terraform"].status, r.PRESELECT)
        self.assertTrue(items["old/.terraform"].selected)
        self.assertEqual(items["new/.terraform"].status, r.OPTIONAL)
        self.assertFalse(items["new/.terraform"].selected)

    def test_recent_file_access_counts_as_use(self):
        mkfile(self.p("p", ".terraform", "providers", "bin"), 10)
        age_tree(self.p("p", ".terraform"), 60, atime_days=1)  # init long ago, plan ran yesterday
        self.assertEqual(self.artifacts()["p/.terraform"].status, r.OPTIONAL)

    def test_min_size_hides_tiny_leftovers(self):
        mkfile(self.p("p", "__pycache__", "m.pyc"), 10)
        self.assertEqual(self.artifacts(self.cfg(min_size=r.MiB)), {})

    def test_hardlinks_counted_once(self):
        a = mkfile(self.p("one", "f"), 256 * 1024)
        os.makedirs(self.p("two"))
        mkfile(self.p("two", "f"), 256 * 1024)
        os.link(a, self.p("one", "g"))
        linked, _ = r.dir_usage(self.p("one"))
        plain, _ = r.dir_usage(self.p("two"))
        self.assertLess(abs(linked - plain), 64 * 1024)


class ToolDetectorTests(Base):
    def tool(self, name):
        return "/fake/" + name

    def test_tf_versions_protects_active(self):
        vdir = self.p("versions")
        for v in ("1.0.0", "1.1.0", "1.2.0"):
            mkfile(os.path.join(vdir, "terraform_" + v), 10)
        mkfile(os.path.join(vdir, "terraform_72D7468F.asc"))
        old = time.time() - 200 * DAY
        for v in ("1.0.0", "1.2.0"):
            os.utime(os.path.join(vdir, "terraform_" + v), (old, old))
        link = self.p("bin", "terraform")
        os.makedirs(os.path.dirname(link))
        os.symlink(os.path.join(vdir, "terraform_1.2.0"), link)
        cat = r.detect_tf_versions(time.time(), vdir=vdir, active_candidates=[link])
        got = {i.label: i.status for i in cat.items}
        self.assertEqual(got, {"terraform_1.0.0": r.PRESELECT, "terraform_1.1.0": r.OPTIONAL,
                               "terraform_1.2.0": r.PROTECTED})

    def test_browser_clones_in_use_protected(self):
        parent = self.p("X", "com.google.Chrome.code_sign_clone")
        mkfile(os.path.join(parent, "code_sign_clone.AAA", "Chrome.app", "bin"), 10)
        mkfile(os.path.join(parent, "code_sign_clone.BBB", "Chrome.app", "bin"), 10)
        lsof = f"p123\nn{parent}/code_sign_clone.AAA/Chrome.app/bin\n"
        with mock.patch.object(r, "find_tool", self.tool), \
                mock.patch.object(r, "_run", fake_run({"-nP -Fn": (1, lsof)})):
            cat = r.detect_browser_clones(tmpdir=self.p("T") + "/")
        got = {i.label.split("/")[-1]: i.status for i in cat.items}
        self.assertEqual(got, {"code_sign_clone.AAA": r.PROTECTED, "code_sign_clone.BBB": r.PRESELECT})

    def test_browser_clones_review_when_lsof_missing(self):
        mkfile(self.p("X", "com.google.Chrome.code_sign_clone", "code_sign_clone.AAA", "f"))
        with mock.patch.object(r, "find_tool", lambda n: None):
            cat = r.detect_browser_clones(tmpdir=self.p("T"))
        self.assertEqual([i.status for i in cat.items], [r.REVIEW])

    def snapshots(self, latest, running="0"):
        out = {
            "listlocalsnapshots /": (0, "Snapshots for disk /:\n"
                                        "com.apple.TimeMachine.2026-11-12-102906.local\n"
                                        "com.apple.TimeMachine.2026-11-12-133613.local\n"
                                        "com.apple.TimeMachine.2026-11-12-143621.local\n"),
            "status": (0, f"{{\n    Running = {running};\n}}\n"),
        }
        if latest:
            out["latestbackup"] = (0, f"/Volumes/.timemachine/X/{latest}.backup/{latest}.backup\n")
        with mock.patch.object(r, "find_tool", self.tool), mock.patch.object(r, "_run", fake_run(out)):
            return [(i.label[-17:], i.status) for i in r.detect_tm_snapshots().items]

    def test_snapshots_covered_by_backup_are_deletable(self):
        self.assertEqual(self.snapshots("2026-11-12-135120"), [
            ("2026-11-12-102906", r.OPTIONAL),
            ("2026-11-12-133613", r.OPTIONAL),
            ("2026-11-12-143621", r.PROTECTED),
        ])

    def test_snapshot_in_use_by_running_backup(self):
        self.assertEqual(self.snapshots("2026-11-12-150000", running="1")[-1],
                         ("2026-11-12-143621", r.PROTECTED))

    def test_snapshots_need_review_without_backup(self):
        self.assertEqual({s for _, s in self.snapshots(None)}, {r.REVIEW})

    def test_docker(self):
        self.assertEqual(r.parse_docker_size("11.58GB (45%)"), 11_580_000_000)
        self.assertEqual(r.parse_docker_size("856.1kB"), 856_100)
        self.assertEqual(r.parse_docker_size("0B"), 0)
        df = "\n".join(json.dumps(x) for x in [
            {"Type": "Images", "Size": "25.34GB", "Reclaimable": "11.58GB (45%)"},
            {"Type": "Containers", "Size": "15.76MB", "Reclaimable": "856.1kB (5%)"},
            {"Type": "Local Volumes", "Size": "1.672GB", "Reclaimable": "0B (0%)"},
            {"Type": "Build Cache", "Size": "1.277GB", "Reclaimable": "327.8MB"},
        ])
        with mock.patch.object(r, "find_tool", self.tool), \
                mock.patch.object(r, "_run", fake_run({"system df --format {{json .}}": (0, df)})):
            cat = r.detect_docker()
        got = {i.label: i.status for i in cat.items}
        self.assertEqual(got, {"build cache": r.OPTIONAL, "stopped containers": r.OPTIONAL,
                               "dangling images": r.OPTIONAL, "unused images": r.REVIEW,
                               "volumes": r.PROTECTED})
        vol = [i for i in cat.items if i.label == "volumes"][0]
        self.assertIsNone(vol.command)

    def test_lsof_parser(self):
        out = "p1\nn/x/com.google.Chrome.code_sign_clone/code_sign_clone.Q1/A\nn/other\nfcwd\n"
        self.assertEqual(r.parse_lsof_clones(out), {"code_sign_clone.Q1"})


class DeleteTests(Base):
    def item(self, path, guard=None, name=None):
        return r.Item("x", 1, r.PRESELECT, path=path, guard=guard or self.root,
                      expect_name=name or os.path.basename(path))

    def refused(self, item, cfg=None):
        with self.assertRaises(r.Refused) as cm:
            r.check_path(item, cfg or self.cfg())
        return str(cm.exception)

    def test_check_path_accepts_normal_target(self):
        target = os.path.dirname(mkfile(self.p("proj", ".terraform", "f")))
        self.assertEqual(r.check_path(self.item(target), self.cfg()), target)

    def test_check_path_refusals(self):
        target = os.path.dirname(mkfile(self.p("proj", ".terraform", "f")))
        os.symlink(target, self.p("link"))
        os.symlink(self.p("proj"), self.p("proj-link"))
        self.assertIn("symlink", self.refused(self.item(self.p("link"))))
        self.assertIn("through a symlink", self.refused(self.item(self.p("proj-link", ".terraform"))))
        self.assertIn("no longer exists", self.refused(self.item(self.p("gone"))))
        self.assertIn("outside", self.refused(self.item(target, guard=self.p("elsewhere"))))
        self.assertIn("name changed", self.refused(self.item(target, name=".venv")))
        self.assertIn("top of the disk", self.refused(self.item(self.root, guard=os.path.dirname(self.root))))

    def test_rm_handles_read_only_trees(self):
        mkfile(self.p("ro", "sub", "f"), 10)
        os.chmod(self.p("ro", "sub"), 0o555)
        os.chmod(self.p("ro"), 0o555)
        r._rm(self.p("ro"))
        self.assertFalse(os.path.exists(self.p("ro")))

    def test_execute_rm_command_and_protected(self):
        target = os.path.dirname(mkfile(self.p("proj", ".terraform", "f")))
        ok = self.item(target)
        cmd = r.Item("cache", 5, r.OPTIONAL, command=["/fake/go", "clean", "-cache"], as_user=True)
        prot = r.Item("vol", 5, r.PROTECTED, command=["/fake/docker", "volume", "rm"])
        run = fake_run({})  # every command fails
        with mock.patch.object(r, "_run", run), mock.patch.object(r, "SUDO_USER", "alice"):
            res = r.execute([ok, cmd, prot], self.cfg())
        self.assertEqual([(x.ok, x.message) for x in res],
                         [(True, "deleted"), (False, "last line"), (False, "protected")])
        self.assertFalse(os.path.exists(target))
        self.assertEqual(run.calls, [["sudo", "-u", "alice", "-H", "--", "/fake/go", "clean", "-cache"]])


class CliTests(Base):
    def test_arg_validation(self):
        for argv in (["--json"], ["--dry-run", "--limit", "-1"], ["--big-file-gb", "0"]):
            with self.assertRaises(SystemExit), mock.patch("sys.stderr", io.StringIO()):
                r.parse_args(argv)

    def test_report_and_json(self):
        cat = r.Category("c", "things", "hint")
        cat.items = [r.Item("a", 3 * r.GiB, r.PRESELECT, note="unused 9d"),
                     r.Item("b", -1, r.PROTECTED, note="in use")]
        out = io.StringIO()
        r.print_report([cat], limit=10, out=out)
        text = out.getvalue()
        self.assertIn("things   3.0G in 2 item(s), selected by default 3.0G", text)
        self.assertIn("[-]        ?", text)
        json.dumps(r.report_json([cat], ["w"]))

    def test_privacy_warning_points_at_full_disk_access(self):
        import errno
        r.DENIED.note("/x", OSError(errno.EPERM, "nope"))
        self.assertIn("Full Disk Access", r.DENIED.warnings()[0])


if __name__ == "__main__":
    unittest.main()
