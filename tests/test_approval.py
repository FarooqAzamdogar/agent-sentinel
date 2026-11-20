"""Tests for asking a human later: check_call(..., defer_ask=True) and finish_approval.

The proxy and the hook cannot block inside check_call while a human thinks:
the answer arrives later, on another path. So check_call can hand back a
pending decision, and finish_approval turns the answer into the final one.
"""

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from support import POLICY, without_ref
from agent_sentinel import Decision, Firewall, Policy
from agent_sentinel import firewall as firewall_module
from agent_sentinel.policy import NOT_PERMITTED

EMAIL = {"to": "a@example.com"}


def read_audit(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]


class PendingDecisions(unittest.TestCase):
    def test_an_ask_becomes_pending_without_calling_the_approver(self):
        called = []
        firewall = Firewall(POLICY, approver=lambda *a: called.append(a) or True)
        decision = firewall.check_call("send_email", EMAIL, defer_ask=True)
        self.assertTrue(decision.pending)
        self.assertFalse(decision.allowed)
        self.assertFalse(decision)  # code that ignores `pending` treats it as a refusal
        self.assertEqual(called, [])
        self.assertEqual(decision.rule, "tools.send_email")
        self.assertRegex(decision.ref, r"\A[0-9a-f]{8}\Z")
        self.assertIn("waiting for approval", decision.reason)

    def test_without_an_approver_an_ask_can_still_be_deferred(self):
        self.assertTrue(Firewall(POLICY).check_call("send_email", EMAIL, defer_ask=True).pending)

    def test_only_an_ask_is_ever_pending(self):
        firewall = Firewall(POLICY)
        allowed = firewall.check_call("read_file", {"path": "a.txt"}, defer_ask=True)
        blocked = firewall.check_call("delete_file", {"path": "a.txt"}, defer_ask=True)
        self.assertEqual((allowed.allowed, allowed.pending), (True, False))
        self.assertEqual((blocked.allowed, blocked.pending), (False, False))

    def test_the_secret_guard_and_the_policy_run_before_anything_is_pending(self):
        firewall = Firewall(POLICY)
        bad_address = firewall.check_call("send_email", {"to": "x@evil.example"}, defer_ask=True)
        secret = firewall.check_call("send_email", {"to": "a@example.com", "body": "ghp_" + "a1B2c3D4e5" * 4},
                                     defer_ask=True)
        self.assertFalse(bad_address.pending or secret.pending)
        self.assertEqual(secret.rule, "secrets")

    def test_the_rate_limit_is_counted_before_the_call_is_pending(self):
        policy = Policy.from_dict({"tools": {"send": {"action": "ask", "max_calls_per_minute": 1}}})
        firewall = Firewall(policy)
        self.assertTrue(firewall.check_call("send", {}, defer_ask=True).pending)
        second = firewall.check_call("send", {}, defer_ask=True)
        self.assertEqual((second.pending, second.rule), (False, "tools.send.max_calls_per_minute"))

    def test_monitor_mode_never_waits(self):
        decision = Firewall(POLICY, monitor=True).check_call("send_email", EMAIL, defer_ask=True)
        self.assertEqual((decision.allowed, decision.pending), (True, False))

    def test_a_pending_decision_cannot_be_allowed(self):
        with self.assertRaises(ValueError):
            Decision(True, "x", pending=True)


class FinishingAnApproval(unittest.TestCase):
    def setUp(self):
        self.firewall = Firewall(POLICY)
        self.pending = self.firewall.check_call("send_email", EMAIL, defer_ask=True)

    def test_exactly_true_approves(self):
        final = self.firewall.finish_approval(self.pending, True, "dialog")
        self.assertTrue(final.allowed)
        self.assertFalse(final.pending)
        self.assertEqual((final.rule, final.call_id), ("tools.send_email", self.pending.call_id))
        self.assertIn("approved by dialog", final.reason)

    def test_anything_else_refuses_and_keeps_the_reference(self):
        for answer in (False, None, 1, "yes", "true", [True]):
            with self.subTest(answer=answer):
                firewall = Firewall(POLICY)  # a new one each time: send_email allows 5 calls a minute
                pending = firewall.check_call("send_email", EMAIL, defer_ask=True)
                final = firewall.finish_approval(pending, answer, "elicitation")
                self.assertFalse(final.allowed)
                self.assertEqual(final.ref, pending.ref)
                self.assertTrue(final.public_reason.endswith(f"(ref {pending.ref})"))
                self.assertEqual(without_ref(final.public_reason), NOT_PERMITTED)
                self.assertNotIn("elicitation", final.public_reason)

    def test_a_decision_can_be_finished_only_once(self):
        self.assertFalse(self.firewall.finish_approval(self.pending, False, "timeout").allowed)
        late = self.firewall.finish_approval(self.pending, True, "dialog")
        self.assertFalse(late.allowed)
        self.assertIn("not waiting", late.reason)

    def test_a_pending_decision_from_another_firewall_is_refused(self):
        other = Firewall(POLICY).check_call("send_email", EMAIL, defer_ask=True)
        self.assertFalse(self.firewall.finish_approval(other, True, "dialog").allowed)

    def test_a_copy_of_a_pending_decision_is_refused(self):
        import dataclasses

        copy = dataclasses.replace(self.pending)
        self.assertFalse(self.firewall.finish_approval(copy, True, "dialog").allowed)
        self.assertTrue(self.firewall.finish_approval(self.pending, True, "dialog").allowed)

    def test_only_a_pending_decision_can_be_finished(self):
        allowed = self.firewall.check_call("read_file", {"path": "a.txt"})
        for decision in (allowed, Decision(False, "x"), "pending", None):
            with self.subTest(decision=decision):
                with self.assertRaises(ValueError):
                    self.firewall.finish_approval(decision, True, "dialog")

    def test_the_oldest_waiting_call_is_forgotten_and_then_refused(self):
        with mock.patch.object(firewall_module, "MAX_PENDING_APPROVALS", 2):
            first = self.firewall.check_call("send_email", EMAIL, defer_ask=True)
            for _ in range(2):
                self.firewall.check_call("send_email", EMAIL, defer_ask=True)
        self.assertFalse(self.firewall.finish_approval(self.pending, True, "dialog").allowed)
        self.assertFalse(self.firewall.finish_approval(first, True, "dialog").allowed)

    def test_monitor_mode_does_not_turn_a_refused_or_unmatched_answer_into_an_approval(self):
        # Monitor mode lifts what the policy would block. A human's "no", or an answer
        # for a call this firewall is not waiting for, is not a policy block.
        foreign = Firewall(POLICY).check_call("send_email", EMAIL, defer_ask=True)
        monitor = Firewall(POLICY, monitor=True)
        self.assertFalse(monitor.finish_approval(foreign, True, "dialog").allowed)
        self.firewall.monitor = True  # switched on while the call waited
        final = self.firewall.finish_approval(self.pending, False, "dialog")
        self.assertFalse(final.allowed)
        self.assertEqual(final.ref, self.pending.ref)

    def test_a_refusal_says_whether_anyone_was_asked(self):
        # "refused": a person or program said no, or let the time run out. "unavailable": nobody could be asked.
        refused = self.firewall.finish_approval(self.pending, False, "dialog (no answer within 120 seconds)")
        nobody = Firewall(POLICY)
        pending = nobody.check_call("send_email", EMAIL, defer_ask=True)
        unavailable = nobody.finish_approval(pending, False, "nobody (dialog: no display)", asked=False)
        self.assertEqual((refused.allowed, refused.approval), (False, "refused"))
        self.assertEqual((unavailable.allowed, unavailable.approval, unavailable.ref),
                         (False, "unavailable", pending.ref))

    def test_a_hostile_approver_label_is_made_printable_and_short(self):
        final = self.firewall.finish_approval(self.pending, False, "dia\x1b[2Jlog" + "x" * 1000)
        self.assertNotIn("\x1b", final.reason)
        self.assertLess(len(final.reason), 400)

    def test_answers_from_two_threads_finish_the_call_once(self):
        results = []
        threads = [
            threading.Thread(target=lambda: results.append(self.firewall.finish_approval(self.pending, True, "t")))
            for _ in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(1 for decision in results if decision.allowed), 1)


class FlowsWhileACallWaits(unittest.TestCase):
    POLICY = Policy.from_dict({
        "tools": {
            "fetch_page": {"action": "allow", "labels": ["untrusted"]},
            "read_file": {"action": "allow", "labels": ["private"]},
            "send_email": {"action": "ask", "labels": ["sink"]},
        },
        "flows": [{"after": ["untrusted", "private"], "action": "block"}],
    })

    def test_an_approved_call_is_refused_if_a_flow_now_blocks_it(self):
        firewall = Firewall(self.POLICY)
        pending = firewall.check_call("send_email", EMAIL, defer_ask=True)
        firewall.run("fetch_page", {"url": "u"}, lambda url: "page")
        firewall.run("read_file", {"path": "p"}, lambda path: "notes")
        final = firewall.finish_approval(pending, True, "dialog")
        self.assertFalse(final.allowed)
        self.assertEqual((final.rule, final.ref), ("flows[0]", pending.ref))
        self.assertIn("while the call waited", final.reason)

    def test_a_flow_that_asks_can_be_deferred_and_approved(self):
        policy = Policy.from_dict({
            "tools": {"fetch_page": {"action": "allow", "labels": ["untrusted"]},
                      "send_email": {"action": "allow", "labels": ["sink"]}},
            "flows": [{"after": ["untrusted"], "action": "ask"}],
        })
        firewall = Firewall(policy)
        firewall.run("fetch_page", {"url": "u"}, lambda url: "page")
        pending = firewall.check_call("send_email", EMAIL, defer_ask=True)
        self.assertEqual((pending.pending, pending.rule), (True, "flows[0]"))
        self.assertTrue(firewall.finish_approval(pending, True, "dialog").allowed)


class TheAuditTrail(unittest.TestCase):
    def test_the_wait_and_the_answer_are_both_recorded_with_one_call_id_and_ref(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "audit.jsonl"
            firewall = Firewall(POLICY, audit_path=audit)
            pending = firewall.check_call("send_email", EMAIL, defer_ask=True)
            firewall.finish_approval(pending, False, "dialog")
            asked, answered = read_audit(audit)
        self.assertEqual((asked["event"], asked["action"], asked["args"]), ("call", "ask", EMAIL))
        self.assertEqual((answered["event"], answered["action"]), ("approval", "block"))
        self.assertEqual(asked["call_id"], answered["call_id"])
        self.assertEqual(asked["ref"], answered["ref"])
        self.assertIn("refused by dialog", answered["reason"])
        self.assertNotIn("args", answered)


if __name__ == "__main__":
    unittest.main()
