#!/usr/bin/env python3

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("update_cn_direct.py")


def load_module():
    spec = importlib.util.spec_from_file_location("update_cn_direct", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


OUTPUT_ATTRIBUTES = (
    ("FULL", "full.txt"),
    ("SAFE", "safe.txt"),
    ("GLINET", "glinet.txt"),
    ("COMBINED", "combined.txt"),
    ("PLUS", "plus.txt"),
    ("SIGNED_RUNTIME_PLUS", "runtime-plus.txt"),
)


class SimulatedCrash(BaseException):
    pass


def configure_outputs(module, root: Path, initial: bytes | None = None):
    paths = []
    for attribute, filename in OUTPUT_ATTRIBUTES:
        path = root / filename
        if initial is not None:
            path.write_bytes(initial)
        setattr(module, attribute, path)
        paths.append(path)
    module.TRANSACTION_DIR = root / ".output-transaction"
    return paths


def output_rows(paths):
    return {path: [f"new-{index}"] for index, path in enumerate(paths)}


class UpdateCnDirectTests(unittest.TestCase):
    def test_signed_runtime_keeps_numeric_and_reviewed_single_labels(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            configure_outputs(module, root)
            module.MIN_GLINET_DOMAINS = 0
            module.SIGNED_RUNTIME_SINGLE_LABELS = frozenset({"cn", "alibaba"})
            module.SIGNED_RUNTIME_REJECTED_SINGLE_LABELS = frozenset({"full", "ms"})
            module.fetch_domains = lambda: [
                "alpha.com",
                "163.com",
                "cn",
                "alibaba",
                "full",
                "ms",
                "beta.cn",
            ]
            module.fetch_cn_ipv4 = lambda: ["1.2.3.0/24"]
            module.EXTRA_DIRECT_DOMAINS = ["apple.com"]

            module.main()

            self.assertEqual(
                module.GLINET.read_text().splitlines(),
                ["alpha.com", "beta.cn"],
            )
            self.assertEqual(
                module.PLUS.read_text().splitlines(),
                ["alpha.com", "beta.cn", "apple.com", "1.2.3.0/24"],
            )
            self.assertEqual(
                module.SIGNED_RUNTIME_PLUS.read_text().splitlines(),
                [
                    "alpha.com",
                    "163.com",
                    "cn",
                    "alibaba",
                    "beta.cn",
                    "apple.com",
                    "1.2.3.0/24",
                ],
            )

    def test_signed_runtime_rejects_new_unreviewed_single_label(self):
        module = load_module()
        module.SIGNED_RUNTIME_SINGLE_LABELS = frozenset({"cn"})
        module.SIGNED_RUNTIME_REJECTED_SINGLE_LABELS = frozenset({"full", "ms"})
        with self.assertRaisesRegex(SystemExit, "single-label set changed"):
            module.signed_runtime_domains(["alpha.com", "cn", "full", "ms", "new-tld"])

    def test_signed_runtime_rejects_missing_reviewed_single_label(self):
        module = load_module()
        module.SIGNED_RUNTIME_SINGLE_LABELS = frozenset({"cn", "taobao"})
        module.SIGNED_RUNTIME_REJECTED_SINGLE_LABELS = frozenset({"full", "ms"})
        with self.assertRaisesRegex(SystemExit, "single-label set changed"):
            module.signed_runtime_domains(["alpha.com", "cn", "full", "ms"])

    def test_unknown_single_label_leaves_every_output_unchanged(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            outputs = configure_outputs(module, root, b"sentinel\n")
            module.MIN_GLINET_DOMAINS = 0
            module.SIGNED_RUNTIME_SINGLE_LABELS = frozenset({"cn"})
            module.SIGNED_RUNTIME_REJECTED_SINGLE_LABELS = frozenset({"full", "ms"})
            module.fetch_domains = lambda: [
                "alpha.com",
                "cn",
                "full",
                "ms",
                "new-tld",
            ]
            module.fetch_cn_ipv4 = lambda: self.fail("GeoIP fetch ran after a rejected domain set")

            with self.assertRaisesRegex(SystemExit, "single-label set changed"):
                module.main()

            self.assertTrue(all(path.read_text() == "sentinel\n" for path in outputs))

    def test_url_compatible_plus_still_rejects_numeric_extra(self):
        module = load_module()
        module.EXTRA_DIRECT_DOMAINS = ["163.com"]
        with self.assertRaisesRegex(SystemExit, "GL.iNet-incompatible"):
            module.validate_plus_domains()

    def test_forbidden_parent_stays_rejected(self):
        module = load_module()
        module.EXTRA_DIRECT_DOMAINS = ["google.com"]
        with self.assertRaisesRegex(SystemExit, "Forbidden broad Plus domain"):
            module.validate_plus_domains()

    def test_second_output_replace_failure_restores_every_old_file(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            paths = configure_outputs(module, root, b"old\n")
            destinations = set(paths)
            real_replace = module.os.replace
            output_replaces = 0

            def fail_second_replace(source, destination):
                nonlocal output_replaces
                if Path(destination) in destinations:
                    output_replaces += 1
                    if output_replaces == 2:
                        raise OSError("injected second output replace failure")
                return real_replace(source, destination)

            module.os.replace = fail_second_replace
            with self.assertRaisesRegex(OSError, "second output replace"):
                module.write_outputs(output_rows(paths))

            self.assertTrue(all(path.read_bytes() == b"old\n" for path in paths))
            self.assertFalse(module.TRANSACTION_DIR.exists())

    def test_originally_absent_output_is_absent_after_rollback(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            paths = configure_outputs(module, root, b"old\n")
            paths[0].unlink()
            destinations = set(paths)
            real_replace = module.os.replace
            output_replaces = 0

            def fail_second_replace(source, destination):
                nonlocal output_replaces
                if Path(destination) in destinations:
                    output_replaces += 1
                    if output_replaces == 2:
                        raise OSError("injected second output replace failure")
                return real_replace(source, destination)

            module.os.replace = fail_second_replace
            with self.assertRaises(OSError):
                module.write_outputs(output_rows(paths))

            self.assertFalse(paths[0].exists())
            self.assertTrue(all(path.read_bytes() == b"old\n" for path in paths[1:]))
            self.assertFalse(module.TRANSACTION_DIR.exists())

    def test_prepared_transaction_recovers_after_every_install_stage(self):
        for installed_before_crash in range(7):
            with self.subTest(installed_before_crash=installed_before_crash):
                module = load_module()
                with tempfile.TemporaryDirectory() as raw_tmp:
                    root = Path(raw_tmp)
                    paths = configure_outputs(module, root, b"old\n")
                    destinations = set(paths)
                    real_replace = module.os.replace
                    installed = 0

                    def crash_at_stage(source, destination):
                        nonlocal installed
                        if Path(destination) not in destinations:
                            return real_replace(source, destination)
                        if installed_before_crash == 0 and installed == 0:
                            raise SimulatedCrash("simulated process loss")
                        result = real_replace(source, destination)
                        installed += 1
                        if installed == installed_before_crash:
                            raise SimulatedCrash("simulated process loss")
                        return result

                    module.os.replace = crash_at_stage
                    with self.assertRaises(SimulatedCrash):
                        module.write_outputs(output_rows(paths))

                    self.assertEqual(
                        (module.TRANSACTION_DIR / "state").read_text().strip(),
                        module.TRANSACTION_PREPARED,
                    )
                    module.os.replace = real_replace
                    module.recover_output_transaction(paths)
                    self.assertTrue(all(path.read_bytes() == b"old\n" for path in paths))
                    self.assertFalse(module.TRANSACTION_DIR.exists())
                    module.recover_output_transaction(paths)

    def test_committed_transaction_reentry_keeps_new_outputs_and_cleans(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            paths = configure_outputs(module, root, b"old\n")
            real_remove = module._remove_transaction_dir

            def crash_before_cleanup():
                raise SimulatedCrash("simulated loss after commit")

            module._remove_transaction_dir = crash_before_cleanup
            with self.assertRaises(SimulatedCrash):
                module.write_outputs(output_rows(paths))
            self.assertEqual(
                (module.TRANSACTION_DIR / "state").read_text().strip(),
                module.TRANSACTION_COMMITTED,
            )

            module._remove_transaction_dir = real_remove
            module.recover_output_transaction(paths)
            self.assertEqual(
                [path.read_text().strip() for path in paths],
                [f"new-{index}" for index in range(6)],
            )
            self.assertFalse(module.TRANSACTION_DIR.exists())
            module.recover_output_transaction(paths)

    def test_prepared_recovery_can_itself_restart_at_every_restore_stage(self):
        for restored_before_crash in range(7):
            with self.subTest(restored_before_crash=restored_before_crash):
                module = load_module()
                with tempfile.TemporaryDirectory() as raw_tmp:
                    root = Path(raw_tmp)
                    paths = configure_outputs(module, root, b"old\n")
                    destinations = set(paths)
                    real_replace = module.os.replace
                    installed = 0

                    def interrupt_install(source, destination):
                        nonlocal installed
                        result = real_replace(source, destination)
                        if Path(destination) in destinations:
                            installed += 1
                            if installed == 3:
                                raise SimulatedCrash("leave PREPARED for recovery")
                        return result

                    module.os.replace = interrupt_install
                    with self.assertRaises(SimulatedCrash):
                        module.write_outputs(output_rows(paths))

                    restored = 0

                    def interrupt_recovery(source, destination):
                        nonlocal restored
                        if Path(destination) not in destinations:
                            return real_replace(source, destination)
                        if restored_before_crash == 0 and restored == 0:
                            raise SimulatedCrash("interrupt recovery")
                        result = real_replace(source, destination)
                        restored += 1
                        if restored == restored_before_crash:
                            raise SimulatedCrash("interrupt recovery")
                        return result

                    module.os.replace = interrupt_recovery
                    with self.assertRaises(SimulatedCrash):
                        module.recover_output_transaction(paths)
                    self.assertEqual(
                        (module.TRANSACTION_DIR / "state").read_text().strip(),
                        module.TRANSACTION_PREPARED,
                    )

                    module.os.replace = real_replace
                    module.recover_output_transaction(paths)
                    self.assertTrue(all(path.read_bytes() == b"old\n" for path in paths))
                    self.assertFalse(module.TRANSACTION_DIR.exists())


if __name__ == "__main__":
    unittest.main()
