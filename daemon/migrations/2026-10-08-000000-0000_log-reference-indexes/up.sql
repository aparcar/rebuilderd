-- deleting logs has to find the rows referencing them, see cleanup.rs
CREATE INDEX rebuilds_build_log_id_idx ON rebuilds (build_log_id);
CREATE INDEX rebuild_artifacts_diffoscope_log_id_idx ON rebuild_artifacts (diffoscope_log_id);
CREATE INDEX rebuild_artifacts_attestation_log_id_idx ON rebuild_artifacts (attestation_log_id);
