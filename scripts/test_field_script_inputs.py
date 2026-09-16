"""Offline input-contract tests; no SSH, ping, runtime or user config access."""

import contextlib
import importlib.util
import io
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, pathlib.Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    # Import-time annotations must not require an installed SSH library. The
    # scenarios below never invoke a transport or create any SSH configuration.
    with mock.patch.dict(sys.modules, {name: module, "paramiko": types.ModuleType("paramiko")}):
        spec.loader.exec_module(module)
    return module


class FieldInputContract(unittest.TestCase):
    def setUp(self):
        self.outage = load_script("verify-control-plane-outage")
        self.multipath = load_script("verify-multipath-failover")

    def test_outage_requires_explicit_host(self):
        with mock.patch.object(sys, "argv", ["fixture"]), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                self.outage.parse_args()
        self.assertEqual(raised.exception.code, 2)

    def test_icmp_requires_explicit_target(self):
        with mock.patch.object(sys, "argv", ["fixture", "--chen-host", "node-a", "--ping-method", "icmp"]), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                self.outage.parse_args()
        self.assertEqual(raised.exception.code, 2)

    def test_no_implicit_user(self):
        with tempfile.TemporaryDirectory() as fixture:
            with mock.patch.object(pathlib.Path, "home", return_value=pathlib.Path(fixture)):
                with self.assertRaises(SystemExit):
                    self.outage.resolve_ssh_config("node-a", "")
                actual = self.outage.resolve_ssh_config("node-a", "fixture-user")
                self.assertEqual((actual.host, actual.user, actual.port), ("node-a", "fixture-user", 22))

    def test_multipath_has_no_deployment_default(self):
        with mock.patch.object(sys, "argv", ["fixture"]):
            args = self.multipath.parse_args()
        self.assertEqual((args.coordinator_host, args.relay_host, args.primary_host), ("", "", ""))
        with mock.patch.object(self.multipath, "run_command") as runner:
            with self.assertRaises(ValueError):
                self.multipath.run_remote_shell("", "", "synthetic", 1)
            with self.assertRaises(ValueError):
                self.multipath.run_remote_shell("<SSH_DESTINATION>", "", "synthetic", 1)
            runner.assert_not_called()

    def test_explicit_destination_is_forwarded_without_execution(self):
        with mock.patch.object(self.multipath, "run_command", return_value="synthetic-result") as runner:
            actual = self.multipath.run_remote_shell("192.0.2.20", "fixture-user", "synthetic", 1)
            self.assertEqual(actual, "synthetic-result")
            runner.assert_called_once_with(["ssh", "fixture-user" + chr(64) + "192.0.2.20", "synthetic"], 1)


if __name__ == "__main__":
    unittest.main()
