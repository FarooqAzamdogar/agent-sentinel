"""Tests for session groups (proxy --session-group): the store the proxies of one client share, how a proxy
finds its client run, and how the firewall, the proxy, wrap and doctor use them.

The attack: one server delivers untrusted text, another private data, a third sends it out. Each proxy used to
be a session of its own, so a flow rule never saw the three together.
"""

import argparse
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
    JOINED, MAX_GROUP_MEMBERS, MAX_GROUP_RUNS, NEW_RUN, REPLACED, UNUSABLE, GroupSessionStore, MemorySessionStore,
    SessionStateError, group_members,
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

    def run_in_file(self, index=-1):
        """A client run's session in the file: the one begun last, by default."""
        return self.document()["runs"][index]


class TheLifecycle(GroupStoreTest):
    def test_the_first_proxy_begins_a_run_and_the_others_join_it(self):
        first = self.store("files")
        self.assertEqual(first.join().status, NEW_RUN)
        second = self.store("mail")
        joined = second.join()
        self.assertEqual((joined.status, joined.members), (JOINED, ("files", "mail")))
        self.assertEqual(len(self.document()["runs"]), 1)
        self.assertEqual(self.run_in_file()["members"], ["files", "mail"])
        self.assertEqual(self.run_in_file()["run"], "100@1")

    def test_marks_one_member_sets_refuse_a_sink_of_another_and_name_where_they_came_from(self):
        files, web, mail = self.store("files"), self.store("web"), self.store("mail")
        for store in (files, web, mail):
            store.join()
        Firewall(Policy.from_dict(FLOWS), session_store=web).mark_delivered("fetch_page")
        Firewall(Policy.from_dict(FLOWS), session_store=files).mark_delivered("read_file")
        decision = Firewall(Policy.from_dict(FLOWS), session_store=mail).check_call("send_email", {"to": "x"})
        self.assertEqual((decision.allowed, decision.rule), (False, "flows[0]"))
        self.assertIn("from 'read_file' (server 'files', result)", decision.reason)
        self.assertIn("from 'fetch_page' (server 'web', result)", decision.reason)
        self.assertEqual(mail.read().marks["private"].server, "files")

    def test_a_member_the_client_restarts_joins_and_never_resets(self):
        files = self.store("files")
        files.join()
        files.add(["private"], "read_file")
        restarted = self.store("files")
        self.assertEqual(restarted.join().status, JOINED)
        self.assertEqual(restarted.read().labels, {"private"})
        self.assertEqual(self.run_in_file()["members"], ["files"])  # listed once

    def test_another_client_run_gets_a_session_of_its_own_beside_the_first(self):
        # Two windows (or two instances) of one client. The second used to replace the first's session,
        # and every proxy of the first then refused every sink call until it was restarted.
        first = self.store("files", run="100@1")
        first.join()
        first.add(["private", "untrusted"], "read_file")
        second = self.store("files", run="200@2")
        joined = second.join()
        self.assertEqual((joined.status, joined.replaced, joined.others), (NEW_RUN, (), 1))
        self.assertEqual(second.read().labels, frozenset())
        marks = first.read()
        self.assertFalse(marks.everything)
        self.assertEqual(marks.labels, {"private", "untrusted"})
        second.add(["untrusted"], "fetch_page")
        self.assertEqual(first.read().labels, {"private", "untrusted"})  # each run keeps its own marks
        self.assertEqual(second.read().labels, {"untrusted"})
        mail = self.store("mail", run="100@1")
        self.assertEqual((mail.join().status, mail.read().labels), (JOINED, {"private", "untrusted"}))
        self.assertEqual([run["run"] for run in self.document()["runs"]], ["100@1", "200@2"])
        flows = Policy.from_dict(FLOWS)
        self.assertFalse(Firewall(flows, session_store=mail).check_call("send_email", {"to": "x"}).allowed)
        self.assertTrue(Firewall(flows, session_store=second).check_call("send_email", {"to": "x"}).allowed)

    def test_a_proxy_that_cannot_find_its_client_shares_marks_with_every_run(self):
        # Review of 0.6: "unknown" was one more run beside the others, so when one proxy of a client found
        # the client and another did not, neither saw the other's marks, and a sink call passed.
        files = self.store("files", run="4242@1")  # its client was found
        mail = self.store("mail", run=client_run.UNKNOWN)  # the same client, not found
        other = self.store("files", run="77@7")  # another client altogether
        for store in (files, mail, other):
            self.assertEqual(store.join().status, NEW_RUN)
        files.add(["private"], "read_file")
        self.assertEqual(mail.read().labels, {"private"})  # may be its own client's: it counts
        self.assertEqual(mail.read().marks["private"].server, "files")
        self.assertEqual(other.read().labels, frozenset())  # two known runs stay apart
        answer = mail.add(["untrusted"], "fetch_page")
        self.assertEqual(answer.labels, {"private", "untrusted"})
        self.assertEqual(files.read().labels, {"private", "untrusted"})  # and the unknown one's count for every run
        self.assertEqual(other.read().labels, {"untrusted"})
        flows = Policy.from_dict(FLOWS)
        for store in (files, mail):
            decision = Firewall(flows, session_store=store).check_call("send_email", {"to": "x"})
            self.assertEqual((decision.allowed, decision.rule), (False, "flows[0]"))
        self.assertTrue(Firewall(flows, session_store=other).check_call("send_email", {"to": "x"}).allowed)
        # Each run's own marks are what the file holds: nothing is copied from one run to another.
        self.assertEqual({run["run"]: sorted(run["marks"]) for run in self.document()["runs"]},
                         {"4242@1": ["private"], "unknown": ["untrusted"], "77@7": []})
        # A mark a run only had from the unknown one is still recorded as its own when it sets it itself.
        files.add(["untrusted"], "fetch_page")
        self.assertEqual(sorted(self.run_in_file(0)["marks"]), ["private", "untrusted"])

    def test_a_mark_seen_from_another_run_stays_when_that_run_is_removed(self):
        files = self.store("files", run="4242@1")
        mail = self.store("mail", run=client_run.UNKNOWN)
        files.join()
        mail.join()
        mail.add(["untrusted"], "fetch_page")
        self.assertEqual(files.read().labels, {"untrusted"})
        document = self.document()
        document["runs"] = [run for run in document["runs"] if run["run"] != client_run.UNKNOWN]
        files.path.write_text(json.dumps(document), encoding="ascii")  # as when later client runs made room
        marks = files.read()
        self.assertEqual((marks.everything, marks.labels), (False, {"untrusted"}))
        self.assertTrue(mail.read().everything)  # its own run is gone: it fails closed, as any run does

    def test_more_marks_from_other_runs_than_can_be_kept_count_as_every_mark_for_good(self):
        files = self.store("files", run="4242@1")
        mail = self.store("mail", run=client_run.UNKNOWN)
        files.join()
        mail.join()
        mail.add(["untrusted"], "fetch_page")

        def unknown_run_marks(labels):
            document = self.document()
            unknown = next(run for run in document["runs"] if run["run"] == client_run.UNKNOWN)
            mark = next(iter(unknown["marks"].values()))
            unknown["marks"] = {label: mark for label in labels}
            files.path.write_text(json.dumps(document), encoding="ascii")  # a file someone tampered with

        unknown_run_marks([f"first{number}" for number in range(session.MAX_MARKS)])
        self.assertEqual(len(files.read().labels), session.MAX_MARKS)  # kept: as many as can be
        unknown_run_marks([f"second{number}" for number in range(3)])
        self.assertTrue(files.read().everything)  # seen, and no room to keep them
        unknown_run_marks(["untrusted"])
        self.assertTrue(files.read().everything)  # and so it stays: a mark seen is never forgotten
        self.assertTrue(files.add(["private"], "read_file").everything)

    def test_the_unknown_run_is_the_one_client_run_names(self):
        # The library does not load client_run (it starts programs), so the name is written out in session.
        self.assertEqual(session.UNKNOWN_RUN, client_run.UNKNOWN)

    def test_past_the_limit_the_run_begun_first_is_removed_and_its_members_fail_closed(self):
        oldest = self.store("files", run="run-0")
        oldest.join()
        for index in range(1, MAX_GROUP_RUNS):
            self.store("files", run=f"run-{index}").join()
        self.assertFalse(oldest.read().everything)
        joined = self.store("files", run="run-new").join()
        self.assertEqual((joined.status, joined.replaced, joined.others), (NEW_RUN, ("files",), MAX_GROUP_RUNS - 1))
        self.assertEqual(len(self.document()["runs"]), MAX_GROUP_RUNS)
        marks = oldest.read()
        self.assertTrue(marks.everything)
        self.assertIn("removed from the session group file", marks.why)
        self.assertTrue(oldest.add(["private"], "read_file").everything)  # and it is never put back
        self.assertNotIn("run-0", [run["run"] for run in self.document()["runs"]])

    def test_a_file_that_would_be_too_large_drops_the_runs_of_other_clients_first(self):
        stores = [self.store("files", run=f"run-{index}") for index in range(4)]
        for store in stores:
            store.join()
        labels = [f"l{index:03}" + "x" * 36 for index in range(session.MAX_MARKS)]
        tool = "t" * session.MAX_CAUSE_TOOL_CHARS
        for store in stores:  # four runs of as many long marks as a run takes do not fit in MAX_STATE_FILE_BYTES
            store.add(labels, tool)
        self.assertLessEqual((self.folder / "claude-desktop.json").stat().st_size, session.MAX_STATE_FILE_BYTES)
        self.assertNotIn("run-0", [run["run"] for run in self.document()["runs"]])
        self.assertTrue(stores[0].read().everything)
        self.assertEqual(len(stores[3].read().labels), session.MAX_MARKS)

    def test_doctor_reads_the_members_of_the_run_begun_last(self):
        self.store("files", run="100@1").join()
        self.store("mail", run="100@1").join()
        self.store("files", run="200@2").join()
        self.assertEqual(group_members(self.folder, "claude-desktop"), ("files",))

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
        (run,) = json.loads((self.folder / "g.json").read_text(encoding="ascii"))["runs"]
        members = run["members"]
        self.assertEqual(sorted(members), [f"m{index}" for index in range(5)])

    def test_the_list_of_members_is_bounded(self):
        for index in range(MAX_GROUP_MEMBERS + 5):
            self.store(f"m{index}").join()
        self.assertEqual(len(self.run_in_file()["members"]), MAX_GROUP_MEMBERS)
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
        document["runs"][0]["marks"] = {}
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
        (run,) = good["runs"]

        def with_run(**changes):
            return dict(good, runs=[dict(run, **changes)])

        bad = [
            dict(good, extra=1),
            dict(good, group="other"),
            dict(good, version=2),
            dict(good, version=True),  # equal to 1 in Python, and not a version
            dict(good, version=1.0),
            dict(good, version="1"),
            dict(good, runs=[]),
            dict(good, runs=[run, run]),
            dict(good, runs=[dict(run, run=f"r{index}") for index in range(MAX_GROUP_RUNS + 1)]),
            dict(good, runs=run),
            with_run(extra=1),
            with_run(instance="not-hex"),
            with_run(members=["../x"]),
            with_run(members=["a", "a"]),
            with_run(marks={"private": {"tool": "t", "time": "", "server": "../x", "channel": ""}}),
            with_run(marks={"sink": {"tool": "t", "time": "", "server": "", "channel": ""}}),
            with_run(marks={"private": {"tool": "t", "time": "", "server": ""}}),
            with_run(marks={"private": {"tool": "t", "time": ""}}),
            with_run(marks={"private": {"tool": "t", "time": "", "server": "", "channel": "c" * 200}}),
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

    # ---- Linux: /proc, read from a folder laid out like it ---------------------------------------------

    @staticmethod
    def system_stat(processors, interrupts):
        """The text of /proc/stat in the kernel's layout: the btime line comes after the processors and intr."""
        lines = ["cpu  2255 34 2290 22625563 6290 127 456 0 0 0"]
        lines += [f"cpu{n} 113244 3412 144123 113117181 367512 12712 43811 0 0 0" for n in range(processors)]
        lines.append("intr 114930548 " + " ".join(str(n * 7919 % 100000) for n in range(interrupts)))
        lines += ["ctxt 1990473", "btime 1762191376", "processes 2915", "procs_running 1", "procs_blocked 0"]
        return "\n".join(lines) + "\n"

    def proc(self, system_stat, processes):
        """A folder like /proc: `stat`, the boot id, and <pid>/stat for {pid: (name, parent, start in ticks)}."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "stat").write_text(system_stat, encoding="ascii")
        (root / "sys" / "kernel" / "random").mkdir(parents=True)
        (root / "sys" / "kernel" / "random" / "boot_id").write_text("0f0e0d0c-1111-2222-3333-444455556666\n")
        for pid, (name, parent, ticks) in processes.items():
            (root / str(pid)).mkdir()
            fields = ["S", str(parent), *["0"] * 17, str(ticks), *["0"] * 30]
            (root / str(pid) / "stat").write_text(f"{pid} ({name}) " + " ".join(fields) + "\n", encoding="ascii")
        return str(root)

    PROCESSES = {10: ("python3", 9, 5000), 9: ("bash", 8, 4000), 8: ("node (x) y", 1, 3000)}

    def test_the_boot_time_is_found_however_far_into_proc_stat_it_is(self):
        # Review of 0.6: only the first 4096 bytes were read, and on a machine with many processors or
        # interrupt counters the btime line is past them. The boot time then read as 0.
        for processors, interrupts in ((2, 20), (16, 600), (512, 20_000)):
            with self.subTest(processors=processors):
                text = self.system_stat(processors, interrupts)
                root = self.proc(text, {})
                self.assertEqual(client_run._boot_time(f"{root}/stat"), 1762191376.0)
        self.assertGreater(self.system_stat(16, 600).index("btime"), 4096)
        # The line of interrupt counts may be longer than one read: it is read in pieces.
        self.assertGreater(len(self.system_stat(512, 20_000).splitlines()[513]), client_run._MAX_STAT_LINE_BYTES)

    def test_without_a_boot_time_the_start_is_not_taken_for_a_date(self):
        for text in ("cpu 1 2 3\nctxt 5\n", "", "cpu 1 2 3\nbtime\n", "cpu 1\nbtime soon\n", "xbtime 5\n",
                     "intr " + "9 " * 40_000 + "btime 1762191376\n",  # in the middle of a line: not the line
                     "x" * (client_run._MAX_SYSTEM_STAT_BYTES + 10) + "\nbtime 1762191376\n"):  # too far to read
            with self.subTest(text=text[:30]):
                root = self.proc(text, self.PROCESSES)
                self.assertIsNone(client_run._boot_time(f"{root}/stat"))
                reader = client_run._ProcProcesses(root)
                self.assertFalse(reader.since_epoch)
                with mock.patch.object(os, "getpid", return_value=10):
                    run = client_run._walk_up(reader, time.monotonic() + 5)
                # The run is still told (by the boot id and the ticks), but when it started is not known:
                # a damaged group file is then never judged older than the client, so it is never replaced.
                self.assertEqual((run.id, run.started, run.program), ("8@0f0e0d0c-3000", None, "node (x) y"))
        self.assertIsNone(client_run._boot_time(str(Path(root) / "no such file")))

    def test_the_processes_of_proc_are_read(self):
        root = self.proc(self.system_stat(16, 600), self.PROCESSES)
        reader = client_run._ProcProcesses(root)
        self.assertTrue(reader.since_epoch)
        ticks = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
        found = reader.process(8)
        self.assertEqual((found.parent, found.name, found.start_key), (1, "node (x) y", "0f0e0d0c-3000"))
        self.assertEqual(found.started, 1762191376.0 + 3000 / ticks)
        self.assertIsNone(reader.process(4242))
        with mock.patch.object(os, "getpid", return_value=10):
            run = client_run._walk_up(reader, time.monotonic() + 5)
        self.assertEqual((run.id, run.started), ("8@0f0e0d0c-3000", 1762191376.0 + 3000 / ticks))

    def test_a_group_file_is_not_judged_by_a_start_that_is_not_a_date(self):
        folder = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, folder, True)
        (folder / "desk.json").write_bytes(b"{damaged")
        old = time.time() - 3600
        os.utime(folder / "desk.json", (old, old))
        # Seconds since the system started, taken for a date, would be 1970: the file never looked older.
        unknown_start = GroupSessionStore(folder, "desk", "8@0f0e0d0c-3000", "files", run_started=None)
        self.assertEqual(unknown_start.join().status, UNUSABLE)
        known_start = GroupSessionStore(folder, "desk", "8@0f0e0d0c-3000", "files", run_started=time.time() - 60)
        self.assertEqual(known_start.join().status, REPLACED)

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
            named = mcp_proxy._session_group_store("claude-desktop", "files")
        self.assertFalse((self.home / "sessions").exists())  # only named: the proxy joins just before the server starts
        group = mcp_proxy._join_session_group(*named)
        self.assertEqual(group.store.path, self.home / "sessions" / "claude-desktop.json")
        self.assertEqual(group.joined.status, NEW_RUN)
        firewall = Firewall(Policy.from_dict(FLOWS), session_store=group.store)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            mcp_proxy._report_session_group(group, firewall, mcp_proxy._warn)
        self.assertIn("session group 'claude-desktop': began the flow session", err.getvalue())

    def test_the_startup_line_names_the_other_client_runs_and_one_removed_to_make_room(self):
        store = GroupSessionStore(self.home / "sessions", "desk", "200@2", "files")
        joined = session.GroupJoin(NEW_RUN, ("files",), replaced=("web", "mail"), others=MAX_GROUP_RUNS - 1)
        group = mcp_proxy._JoinedGroup(store, joined, client_run.ClientRun("200@2", 2.0, "claude"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            mcp_proxy._report_session_group(group, Firewall(Policy.from_dict(FLOWS)), mcp_proxy._warn)
        self.assertIn(f"began the flow session of client run claude 200@2 (the file holds the sessions of "
                      f"{MAX_GROUP_RUNS - 1} other client run(s) too, each of its own); the session of the client "
                      "run begun first (its members: web, mail) was removed to make room", err.getvalue())

    def test_a_home_folder_that_cannot_be_told_stops_the_proxy(self):
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"AGENT_SENTINEL_HOME": "relative/path"}), contextlib.redirect_stderr(err):
            self.assertIsNone(mcp_proxy._session_group_store("g", "files"))
        self.assertIn("cannot use --session-group", err.getvalue())

    def test_session_group_needs_a_name_and_a_plain_group(self):
        for argv in (["--policy", "p.json", "--session-group", "g", "--", "x"],
                     ["--policy", "p.json", "--name", "a", "--session-group", "../g", "--", "x"],
                     ["--policy", "p.json", "--name", "a", "--session-group", "NUL", "--", "x"]):
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
        # Round-2 review (PA2-3): the proxy takes the name in lower case, so these are one group.
        self.assertEqual(session_group_lines([server("a", "Claude-Desktop"), server("b", "claude-desktop")]), [])


class GroupNames(GroupStoreTest):
    """Round-2 review (PA2-3): "G" and "g" named two groups, but on Windows and macOS one file, so the second proxy
    found the first's file, took it for another group's, and refused every sink-labelled call until it was deleted."""

    def test_names_that_differ_only_in_case_are_one_group(self):
        first = self.store("files", group="Claude-Desktop")
        self.assertEqual(first.join().status, NEW_RUN)
        second = self.store("mail", group="claude-DESKTOP")
        self.assertEqual(second.join().status, JOINED)
        self.assertEqual((first.group, second.group), ("claude-desktop", "claude-desktop"))
        self.assertEqual([path.name for path in self.folder.glob("*.json")], ["claude-desktop.json"])
        self.assertEqual(self.document()["group"], "claude-desktop")
        self.assertEqual(group_members(self.folder, "CLAUDE-desktop"), ("files", "mail"))
        self.assertEqual(mcp_proxy._session_group("Claude-Desktop"), "claude-desktop")

    def test_windows_device_names_are_refused(self):
        for name in ("nul", "NUL", "con", "Aux", "prn", "com1", "LPT9", "nul.json", "com3.x.y"):
            with self.subTest(name=name):
                self.assertIsNone(session.group_name(name))
                with self.assertRaises(ValueError):
                    self.store(group=name)
                with self.assertRaises(argparse.ArgumentTypeError):
                    mcp_proxy._session_group(name)
                self.assertIsNone(group_members(self.folder, name))
        for name in ("null", "console", "com10", "com", "lpt", "aux-tools", "my.nul", "nul_", ".", ".."):
            with self.subTest(name=name):
                self.assertEqual(session.group_name(name), name)


if __name__ == "__main__":
    unittest.main()
