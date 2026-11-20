"""Tests for session groups (proxy --session-group): the store the proxies of one client share, how a proxy
finds its client run, and how the firewall, the proxy, wrap and doctor use them.

The attack: one server delivers untrusted text, another private data, a third sends it out. Each proxy used to
be a session of its own, so a flow rule never saw the three together.
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from support import ROOT
from agent_sentinel import Firewall, Policy, client_run, mcp_proxy, session
from agent_sentinel.cli_doctor import Line, ServerReport, session_group_lines
from agent_sentinel.filelock import locked
from agent_sentinel.session import (
    JOINED, MAX_GROUP_MEMBERS, NEW_RUN, REPLACED, UNUSABLE, GroupSessionStore, MemorySessionStore,
    SessionStateError,
)
from agent_sentinel.wrapping import ProxySettings, proxy_command_of, wrap_entry

FLOWS = {
    "tools": {
        "fetch_page": {"action": "allow", "labels": ["untrusted"]},
        "read_file": {"action": "allow", "labels": ["private"]},
        "send_email": {"action": "allow", "labels": ["sink"]},
        "search_notes": "allow",
    },
    "flows": [{"after": ["untrusted", "private"], "then": "sink", "action": "block"}],
    "classify_by_annotations": False,
}


class GroupStoreTest(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp()).resolve() / "sessions"
        self.addCleanup(shutil.rmtree, self.folder.parent, True)

    def store(self, member="files", run="100@1", group="claude-desktop", **options):
        return GroupSessionStore(self.folder, group, run, member, **options)

    def document(self):
        return json.loads((self.folder / "claude-desktop.json").read_text(encoding="ascii"))


class TheLifecycle(GroupStoreTest):
    def test_the_first_proxy_begins_a_run_and_the_others_join_it(self):
        first = self.store("files")
        self.assertEqual(first.join().status, NEW_RUN)
        second = self.store("mail")
        joined = second.join()
        self.assertEqual((joined.status, joined.members), (JOINED, ("files", "mail")))
        self.assertEqual(self.document()["members"], ["files", "mail"])
        self.assertEqual(self.document()["run"], "100@1")

    def test_marks_one_member_sets_refuse_a_sink_of_another_and_name_where_they_came_from(self):
        files, web, mail = self.store("files"), self.store("web"), self.store("mail")
        for store in (files, web, mail):
            store.join()
        Firewall(Policy.from_dict(FLOWS), session_store=web).mark_delivered("fetch_page")
        Firewall(Policy.from_dict(FLOWS), session_store=files).mark_delivered("read_file")
        decision = Firewall(Policy.from_dict(FLOWS), session_store=mail).check_call("send_email", {"to": "x"})
        self.assertEqual((decision.allowed, decision.rule), (False, "flows[0]"))
        self.assertIn("from 'files/read_file'", decision.reason)
        self.assertIn("from 'web/fetch_page'", decision.reason)
        self.assertEqual(mail.read().marks["private"].server, "files")

    def test_a_member_the_client_restarts_joins_and_never_resets(self):
        files = self.store("files")
        files.join()
        files.add(["private"], "read_file")
        restarted = self.store("files")
        self.assertEqual(restarted.join().status, JOINED)
        self.assertEqual(restarted.read().labels, {"private"})
        self.assertEqual(self.document()["members"], ["files"])  # listed once

    def test_a_file_of_another_client_run_is_replaced(self):
        old = self.store("files", run="100@1")
        old.join()
        old.add(["private", "untrusted"], "read_file")
        new = self.store("mail", run="200@2")
        joined = new.join()
        self.assertEqual((joined.status, joined.replaced), (REPLACED, ("files",)))
        self.assertEqual(new.read().labels, frozenset())
        # The member of the old run now sees a file that is not its run's: every mark counts as set.
        marks = old.read()
        self.assertTrue(marks.everything)
        self.assertIn("another client run", marks.why)

    def test_proxies_starting_at_the_same_moment_make_one_run(self):
        script = (
            "import sys, time; sys.path.insert(0, sys.argv[1]);"
            "from agent_sentinel.session import GroupSessionStore;"
            "time.sleep(max(0, float(sys.argv[4]) - time.time()));"
            "print(GroupSessionStore(sys.argv[2], 'g', 'run-1', sys.argv[3]).join().status)"
        )
        start = time.time() + 1.5
        processes = [subprocess.Popen([sys.executable, "-c", script, str(ROOT), str(self.folder), f"m{index}",
                                       str(start)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                     for index in range(5)]
        statuses = sorted(process.communicate(timeout=60)[0].decode().strip() for process in processes)
        self.assertEqual(statuses, [JOINED] * 4 + [NEW_RUN])
        members = json.loads((self.folder / "g.json").read_text(encoding="ascii"))["members"]
        self.assertEqual(sorted(members), [f"m{index}" for index in range(5)])

    def test_the_list_of_members_is_bounded(self):
        for index in range(MAX_GROUP_MEMBERS + 5):
            self.store(f"m{index}").join()
        self.assertEqual(len(self.document()["members"]), MAX_GROUP_MEMBERS)
        last = self.store("late")
        self.assertEqual(last.join().status, JOINED)  # it still shares the marks
        last.add(["private"], "read_file")
        first = self.store("m0")
        first.join()
        self.assertEqual(first.read().labels, {"private"})

    def test_names_that_could_leave_the_folder_are_refused(self):
        for group in ("../x", "a/b", "", "a" * 65, "c:", "x y"):
            with self.subTest(group=group), self.assertRaises(ValueError):
                self.store(group=group)
        with self.assertRaises(ValueError):
            self.store(member="a/b")
        with self.assertRaises(ValueError):
            self.store(run="x\n")


class FailingClosed(GroupStoreTest):
    def test_until_it_has_joined_every_mark_counts(self):
        store = self.store()
        self.assertTrue(store.read().everything)
        self.assertTrue(store.add(["private"], "read_file").everything)

    def test_a_file_that_disappears_counts_as_every_mark(self):
        store = self.store()
        store.join()
        store.path.unlink()
        self.assertIn("disappeared", store.read().why)

    def test_a_file_begun_again_after_joining_counts_as_every_mark(self):
        store = self.store("files")
        store.join()
        store.path.unlink()
        self.assertEqual(self.store("web").join().status, NEW_RUN)  # same run id, a new beginning
        marks = store.read()
        self.assertTrue(marks.everything)
        self.assertIn("begun again", marks.why)

    def test_marks_that_disappear_count_as_every_mark(self):
        store = self.store()
        store.join()
        store.add(["private"], "read_file")
        document = self.document()
        document["marks"] = {}
        store.path.write_text(json.dumps(document), encoding="ascii")
        self.assertIn("disappeared", store.read().why)

    def test_a_damaged_or_large_file_after_joining_counts_as_every_mark_and_is_never_repaired(self):
        for content in (b"{not json", b"x" * (session.MAX_STATE_FILE_BYTES + 1)):
            with self.subTest(size=len(content)):
                store = self.store()
                store.path.unlink(missing_ok=True)
                store.join()
                store.path.write_bytes(content)
                self.assertTrue(store.read().everything)
                self.assertTrue(store.add(["private"], "read_file").everything)
                self.assertEqual(store.path.read_bytes(), content)

    def test_a_strict_reader(self):
        store = self.store()
        store.join()
        good = self.document()
        bad = [
            dict(good, extra=1),
            dict(good, group="other"),
            dict(good, version=2),
            dict(good, instance="not-hex"),
            dict(good, members=["../x"]),
            dict(good, members=["a", "a"]),
            dict(good, marks={"private": {"tool": "t", "time": "", "server": "../x"}}),
            dict(good, marks={"sink": {"tool": "t", "time": "", "server": ""}}),
            dict(good, marks={"private": {"tool": "t", "time": ""}}),
        ]
        for document in bad:
            with self.subTest(document=document):
                store.path.write_text(json.dumps(document), encoding="ascii")
                self.assertTrue(store.read().everything)
        store.path.write_text(json.dumps(good), encoding="ascii")
        self.assertFalse(store.read().everything)

    def test_a_damaged_file_older_than_the_client_run_is_replaced_at_join(self):
        self.folder.mkdir(parents=True)
        path = self.folder / "claude-desktop.json"
        path.write_bytes(b"{damaged")
        old = time.time() - 3600
        os.utime(path, (old, old))
        joined = self.store(run_started=time.time() - 60).join()
        self.assertEqual(joined.status, REPLACED)
        self.assertIn("before this client started", joined.detail)

    def test_a_damaged_file_that_may_be_this_runs_counts_as_every_mark_and_is_left_alone(self):
        self.folder.mkdir(parents=True)
        path = self.folder / "claude-desktop.json"
        path.write_bytes(b"{damaged")
        for started in (None, time.time() - 60):  # unknown, or the file is newer than the client
            with self.subTest(started=started):
                store = self.store(run_started=started)
                self.assertEqual(store.join().status, UNUSABLE)
                self.assertTrue(store.read().everything)
                self.assertEqual(path.read_bytes(), b"{damaged")

    def test_a_lock_not_had_in_time_refuses(self):
        store = self.store(lock_timeout=0.2)
        store.join()
        held, release = threading.Event(), threading.Event()

        def hold():
            with locked(self.folder / "claude-desktop.lock"):
                held.set()
                release.wait(10)

        holder = threading.Thread(target=hold)
        holder.start()
        self.addCleanup(holder.join)
        self.addCleanup(release.set)
        held.wait(5)
        started = time.monotonic()
        self.assertTrue(store.read().everything)
        with self.assertRaises(SessionStateError):
            store.add(["private"], "read_file")
        with self.assertRaises(SessionStateError):
            self.store("other", lock_timeout=0.2).join()
        self.assertLess(time.monotonic() - started, 5)
        release.set()
        holder.join()
        self.assertFalse(store.read().everything)

    def test_the_folder_gone_counts_as_every_mark(self):
        store = self.store()
        store.join()
        shutil.rmtree(self.folder)
        self.assertTrue(store.read().everything)
        self.assertTrue(store.add(["private"], "read_file").everything)


class TheClientRun(unittest.TestCase):
    class Reader(client_run._Reader):
        def __init__(self, table):
            self.table = table

        def process(self, pid):
            return self.table.get(pid)

    @staticmethod
    def process(parent, name, started, image=""):
        return client_run._Process(parent, name, started, str(started), image)

    def walk(self, table):
        with mock.patch.object(os, "getpid", return_value=10):
            return client_run._walk_up(self.Reader(table), time.monotonic() + 5)

    def test_shells_and_launchers_are_passed_over(self):
        table = {10: self.process(9, "python", 50), 9: self.process(8, "cmd", 40), 8: self.process(7, "uvx", 30),
                 7: self.process(6, "claude", 20), 6: self.process(1, "explorer", 10)}
        self.assertEqual(self.walk(table), client_run.ClientRun("7@20", 20, "claude"))

    def test_a_parent_younger_than_its_child_is_a_reused_number(self):
        table = {10: self.process(9, "python", 50), 9: self.process(8, "bash", 60)}
        self.assertEqual(self.walk(table).id, client_run.UNKNOWN)

    def test_what_cannot_be_read_is_unknown(self):
        self.assertEqual(self.walk({10: self.process(9, "python", 50)}).id, client_run.UNKNOWN)
        self.assertEqual(self.walk({10: self.process(1, "python", 50)}).id, client_run.UNKNOWN)
        chain = {10 + index: self.process(11 + index, "sh", 100 - index) for index in range(40)}
        chain[10] = self.process(11, "python", 200)
        self.assertEqual(self.walk(chain).id, client_run.UNKNOWN)

    def test_which_programs_are_launchers(self):
        for name in ("cmd.exe", "bash", "-zsh", "pwsh.exe", "py.exe", "uvx", "agent-sentinel.exe", "conhost.exe"):
            self.assertTrue(client_run.is_launcher(name), name)
        for name in ("Claude.exe", "node", "Code.exe", "python.exe", "cursor"):
            self.assertFalse(client_run.is_launcher(name), name)

    def test_a_virtual_environments_python_stub_is_a_launcher(self):
        with tempfile.TemporaryDirectory() as folder:
            stub = Path(folder) / "venv" / "Scripts" / "python.exe"
            stub.parent.mkdir(parents=True)
            (stub.parent.parent / "pyvenv.cfg").write_text("home = x\n", encoding="ascii")
            self.assertTrue(client_run.is_launcher("python.exe", str(stub)))
            self.assertFalse(client_run.is_launcher("python.exe", str(Path(folder) / "python.exe")))

    def test_it_never_raises(self):
        with mock.patch.object(client_run, "_walk_up", side_effect=RuntimeError("bug")):
            self.assertEqual(client_run.find_client_run().id, client_run.UNKNOWN)

    def test_two_proxies_of_one_client_find_the_same_run(self):
        script = "import sys; sys.path.insert(0, sys.argv[1]); from agent_sentinel import client_run; " \
                 "print(client_run.find_client_run().id)"
        found = {subprocess.run([sys.executable, "-c", script, str(ROOT)], capture_output=True, text=True,
                                timeout=60).stdout.strip() for _ in range(2)}
        self.assertEqual(len(found), 1)
        (run,) = found
        if run == client_run.UNKNOWN and sys.platform not in ("win32", "linux"):
            self.skipTest("the processes cannot be read on this system")
        self.assertTrue(run.startswith(f"{os.getpid()}@"), run)  # this test process is their client


class TheFirewallReadsMarksOnlyWhenAFlowCanApply(unittest.TestCase):
    def test_a_call_no_flow_applies_to_does_not_read_the_store(self):
        class Counting(MemorySessionStore):
            reads = 0

            def read(self):
                Counting.reads += 1
                return super().read()

        firewall = Firewall(Policy.from_dict(FLOWS), session_store=Counting())
        firewall.check_call("search_notes", {"q": "x"})
        firewall.check_call("read_file", {"path": "p"})
        self.assertEqual(Counting.reads, 0)
        firewall.check_call("send_email", {"to": "x"})
        self.assertEqual(Counting.reads, 1)


class TheProxyJoinsItsGroup(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp()).resolve() / ".agent-sentinel"
        self.addCleanup(shutil.rmtree, self.home.parent, True)

    def test_the_group_file_is_in_the_home_folder(self):
        with mock.patch.dict(os.environ, {"AGENT_SENTINEL_HOME": str(self.home)}):
            group = mcp_proxy._join_session_group("claude-desktop", "files")
        self.assertEqual(group.store.path, self.home / "sessions" / "claude-desktop.json")
        self.assertEqual(group.joined.status, NEW_RUN)
        firewall = Firewall(Policy.from_dict(FLOWS), session_store=group.store)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            mcp_proxy._report_session_group(group, firewall, mcp_proxy._warn)
        self.assertIn("session group 'claude-desktop': began the flow session", err.getvalue())

    def test_a_home_folder_that_cannot_be_told_stops_the_proxy(self):
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"AGENT_SENTINEL_HOME": "relative/path"}), contextlib.redirect_stderr(err):
            self.assertIsNone(mcp_proxy._join_session_group("g", "files"))
        self.assertIn("cannot use --session-group", err.getvalue())

    def test_session_group_needs_a_name_and_a_plain_group(self):
        for argv in (["--policy", "p.json", "--session-group", "g", "--", "x"],
                     ["--policy", "p.json", "--name", "a", "--session-group", "../g", "--", "x"]):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as caught:
                mcp_proxy.main(argv)
            self.assertEqual(caught.exception.code, 2)


class WrapAndDoctor(unittest.TestCase):
    SETTINGS = ProxySettings("C:/py/python.exe" if sys.platform == "win32" else "/usr/bin/python3",
                             "/p/policy.json", "/p/audit.jsonl", "/p/pins", session_group="claude-desktop")

    def test_wrap_writes_the_group_after_the_name(self):
        entry = wrap_entry({"command": "npx", "args": ["server"]}, self.SETTINGS, "files", "/p/pins/f.json")
        proxy = proxy_command_of(entry)
        self.assertEqual(proxy.value("--session-group"), "claude-desktop")
        self.assertEqual(proxy.server, ["npx", "server"])

    def test_doctor_warns_about_servers_of_one_client_in_different_groups(self):
        def server(name, group, proxied=True):
            return ServerReport(name, "protected", proxied=proxied, session_group=group)

        self.assertEqual(session_group_lines([server("a", "g"), server("b", "g"), server("c", None, False)]), [])
        (mixed,) = session_group_lines([server("a", "g"), server("b", None)])
        self.assertEqual(mixed.level, "warn")
        self.assertIn("some wrapped servers have a --session-group and some do not: a (g), b (none)", mixed.text)
        (different,) = session_group_lines([server("a", "g"), server("b", "h")])
        self.assertIn("different session groups", different.text)
        self.assertIsInstance(different, Line)


if __name__ == "__main__":
    unittest.main()
