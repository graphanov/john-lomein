from __future__ import annotations
import os
from pathlib import Path
import tempfile
import pytest

FILES = {
    "test_persona_qualification_adopted_verifier_integration.py",
    "test_persona_qualification_adoption_binding.py",
    "test_persona_qualification_capture_adoption.py",
    "test_persona_qualification_capture_handoff_v2.py",
    "test_persona_qualification_opaque_capture.py",
    "test_persona_qualification_verifier.py",
}
NAMES = {
    "test_real_v2_capture_adoption_is_verified_and_tamper_bound",
    "test_replacing_the_named_root_is_detected_by_inode_identity",
    "test_name_replacement_cannot_rebind_retained_authority",
    "test_recovery_handoff_rejects_wrong_binding_and_rebound_name",
    "test_revalidation_binding_pins_retained_descriptor_and_name",
    "test_opaque_engine_mechanically_seals_export_provisional_modes",
    "test_aged_active_final_is_skipped_and_admission_remains_busy",
    "test_cleanup_rejects_replaced_name_before_deleting",
    "test_lease_is_cloexec_nonserializable_and_not_a_path_token",
    "test_max_slots_one_serializes_concurrent_capture_admission",
    "test_same_byte_rewrite_is_detected_during_and_after_capture",
    "test_source_destination_overlap_and_extra_sealed_inventory_reject",
    "test_successfully_copies_all_bytes_without_semantic_parsing",
    "test_unlocked_final_is_reaped_after_creator_crashes",
    "test_capture_selection_and_digest_tamper_fail_closed",
    "test_inventory_status_and_run_id_tamper_fail_closed",
    "test_plan_digest_sparse_layout_and_source_paths_are_strict",
    "test_real_opaque_capture_is_reconstructed_verified_and_bound",
    "test_runner_never_dereferences_identity_only_checkout",
}


def _sealed_rename_supported() -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        parent = Path(tmp)
        source = parent / "sealed"
        target = parent / "renamed"
        source.mkdir()
        source.chmod(0o550)
        try:
            os.rename(source, target)
        except PermissionError:
            source.chmod(0o700)
            return False
        target.chmod(0o700)
        return True


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if _sealed_rename_supported():
        return
    marker = pytest.mark.skip(
        reason="filesystem cannot atomically rename a sealed capture directory"
    )
    for item in items:
        if Path(str(item.path)).name in FILES and item.name in NAMES:
            item.add_marker(marker)
