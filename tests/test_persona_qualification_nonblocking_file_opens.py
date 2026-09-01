from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_binding
    as adoption_binding,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_adoption
    as capture_adoption,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_opaque_capture as opaque_capture,
)
from qualification_verifier import (  # noqa: E402
    john_lomein_persona_qualification_verifier as verifier,
)


class PersonaQualificationNonblockingFileOpenTests(unittest.TestCase):
    def test_critical_read_file_flags_are_nonblocking_not_directory(
        self,
    ) -> None:
        if not hasattr(os, "O_NONBLOCK"):
            self.skipTest("O_NONBLOCK is unavailable")
        for module, helper_name in (
            (adoption_binding, "_file_flags"),
            (capture_adoption, "_file_flags"),
            (opaque_capture, "_read_file_flags"),
            (verifier, "_read_file_flags"),
        ):
            with self.subTest(module=module.__name__):
                flags = getattr(module, helper_name)()
                self.assertEqual(
                    flags & os.O_NONBLOCK,
                    os.O_NONBLOCK,
                )
                self.assertEqual(flags & os.O_NOFOLLOW, os.O_NOFOLLOW)
                if hasattr(os, "O_CLOEXEC"):
                    self.assertEqual(
                        flags & os.O_CLOEXEC,
                        os.O_CLOEXEC,
                    )
                if hasattr(os, "O_DIRECTORY"):
                    self.assertFalse(flags & os.O_DIRECTORY)

        for module in (
            adoption_binding,
            capture_adoption,
            opaque_capture,
        ):
            with self.subTest(directory_module=module.__name__):
                self.assertFalse(
                    module._directory_flags() & os.O_NONBLOCK
                )

    def test_bound_manifest_reader_rejects_raced_fifo_descriptor(
        self,
    ) -> None:
        if not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"):
            self.skipTest("FIFO nonblocking opens are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / opaque_capture.OPAQUE_CAPTURE_MANIFEST
            regular.write_bytes(b"{}\n")
            regular.chmod(opaque_capture.SEALED_FILE_MODE)
            regular_info = regular.stat()
            fifo = root / "raced-fifo"
            os.mkfifo(fifo, opaque_capture.SEALED_FILE_MODE)
            parent_fd = os.open(root, os.O_RDONLY)
            fifo_fd = os.open(
                fifo,
                os.O_RDONLY | os.O_NONBLOCK,
            )
            self.addCleanup(os.close, parent_fd)
            self.addCleanup(os.close, fifo_fd)
            opened_flags: list[int] = []

            def raced_open(name, flags, *args, **kwargs):
                del name, args, kwargs
                opened_flags.append(flags)
                return os.dup(fifo_fd)

            with (
                mock.patch.object(
                    opaque_capture.os,
                    "stat",
                    return_value=regular_info,
                ),
                mock.patch.object(
                    opaque_capture.os,
                    "open",
                    side_effect=raced_open,
                ),
            ):
                with self.assertRaises(
                    opaque_capture.OpaqueCaptureError
                ) as caught:
                    opaque_capture._stable_open_sealed_file(
                        parent_fd,
                        opaque_capture.OPAQUE_CAPTURE_MANIFEST,
                        owner_uid=os.geteuid(),
                        verifier_gid=os.getegid(),
                        file_mode=opaque_capture.SEALED_FILE_MODE,
                        maximum_file_bytes=(
                            opaque_capture.MAX_MANIFEST_BYTES
                        ),
                        field="opaque_capture_manifest",
                    )
            self.assertEqual(
                caught.exception.code,
                "opaque_capture_manifest_changed_during_read",
            )
            self.assertEqual(len(opened_flags), 1)
            self.assertEqual(
                opened_flags[0] & os.O_NONBLOCK,
                os.O_NONBLOCK,
            )

    def test_real_fifo_is_rejected_without_an_unbounded_open(self) -> None:
        if not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"):
            self.skipTest("FIFO nonblocking opens are unavailable")
        program = textwrap.dedent(
            """
            import os
            import tempfile
            from qualification_attestor import (
                john_lomein_persona_qualification_capture_adoption
                as adoption,
            )

            with tempfile.TemporaryDirectory() as temporary:
                os.mkfifo(os.path.join(temporary, "pipe"), 0o600)
                parent_fd = os.open(temporary, os.O_RDONLY)
                try:
                    try:
                        adoption._open_bound_file(
                            parent_fd,
                            "pipe",
                            field="capture_adoption_fifo_test",
                        )
                    except adoption.CaptureAdoptionError as exc:
                        expected = (
                            "capture_adoption_fifo_test_inode_mismatch"
                        )
                        raise SystemExit(0 if exc.code == expected else 2)
                    raise SystemExit(3)
                finally:
                    os.close(parent_fd)
            """
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT)
        try:
            result = subprocess.run(
                [sys.executable, "-c", program],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            self.fail(f"special-file open blocked past timeout: {exc}")
        self.assertEqual(
            result.returncode,
            0,
            msg=result.stderr or result.stdout,
        )

    def test_bound_manifest_reader_preserves_regular_file_behavior(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = b'{"status":"sealed"}\n'
            manifest = root / opaque_capture.OPAQUE_CAPTURE_MANIFEST
            manifest.write_bytes(raw)
            manifest.chmod(opaque_capture.SEALED_FILE_MODE)
            parent_fd = os.open(root, os.O_RDONLY)
            try:
                observed, digest, info = (
                    opaque_capture._stable_open_sealed_file(
                        parent_fd,
                        opaque_capture.OPAQUE_CAPTURE_MANIFEST,
                        owner_uid=os.geteuid(),
                        verifier_gid=os.getegid(),
                        file_mode=opaque_capture.SEALED_FILE_MODE,
                        maximum_file_bytes=(
                            opaque_capture.MAX_MANIFEST_BYTES
                        ),
                        field="opaque_capture_manifest",
                    )
                )
            finally:
                os.close(parent_fd)
            self.assertEqual(observed, raw)
            self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
            self.assertTrue(os.path.isfile(manifest))
            self.assertEqual(info.st_size, len(raw))

    def test_bound_manifest_reader_rechecks_name_after_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / opaque_capture.OPAQUE_CAPTURE_MANIFEST
            replacement = root / "replacement"
            manifest.write_bytes(b"same-size\n")
            replacement.write_bytes(b"different\n")
            manifest.chmod(opaque_capture.SEALED_FILE_MODE)
            replacement.chmod(opaque_capture.SEALED_FILE_MODE)
            before = manifest.stat()
            rebound = replacement.stat()
            parent_fd = os.open(root, os.O_RDONLY)
            try:
                with mock.patch.object(
                    opaque_capture.os,
                    "stat",
                    side_effect=(before, rebound),
                ):
                    with self.assertRaises(
                        opaque_capture.OpaqueCaptureError
                    ) as caught:
                        opaque_capture._stable_open_sealed_file(
                            parent_fd,
                            opaque_capture.OPAQUE_CAPTURE_MANIFEST,
                            owner_uid=os.geteuid(),
                            verifier_gid=os.getegid(),
                            file_mode=opaque_capture.SEALED_FILE_MODE,
                            maximum_file_bytes=(
                                opaque_capture.MAX_MANIFEST_BYTES
                            ),
                            field="opaque_capture_manifest",
                        )
            finally:
                os.close(parent_fd)
            self.assertEqual(
                caught.exception.code,
                "opaque_capture_manifest_changed_during_read",
            )


if __name__ == "__main__":
    unittest.main()
