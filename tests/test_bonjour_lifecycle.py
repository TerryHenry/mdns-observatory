import subprocess
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dnssd_browse import BonjourBrowser


class FakeProcess:
    def __init__(self, stubborn=False):
        self.returncode = None
        self.stubborn = stubborn
        self.terminated = False
        self.killed = False
        self.wait_calls = 0

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        if not self.stubborn:
            self.returncode = 0

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self.returncode is None:
            raise subprocess.TimeoutExpired("fake-dns-sd", timeout)
        return self.returncode


class BonjourLifecycleTests(unittest.TestCase):
    def test_stop_terminates_and_reaps_child_process(self):
        browser = BonjourBrowser(lambda _item: None, lambda _status: None)
        proc = FakeProcess()
        browser.cli_processes.append(proc)
        browser.stop()
        self.assertTrue(browser.stop_event.is_set())
        self.assertTrue(proc.terminated)
        self.assertEqual(proc.returncode, 0)

    def test_stop_kills_child_that_does_not_exit_after_terminate(self):
        browser = BonjourBrowser(lambda _item: None, lambda _status: None)
        proc = FakeProcess(stubborn=True)
        browser.cli_processes.append(proc)
        browser.stop()
        self.assertTrue(proc.terminated)
        self.assertTrue(proc.killed)

    def test_stop_does_not_join_current_worker_thread(self):
        browser = BonjourBrowser(lambda _item: None, lambda _status: None)
        browser.thread = threading.current_thread()
        browser.stop()
        self.assertTrue(browser.stop_event.is_set())


if __name__ == "__main__":
    unittest.main()
