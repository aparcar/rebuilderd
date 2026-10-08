use crate::db::Pool;
use crate::schema::{attestation_logs, build_logs, diffoscope_logs, rebuild_artifacts, rebuilds};
use chrono::Utc;
use diesel::connection::SimpleConnection;
use diesel::dsl::{exists, not, sql};
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Bool, Timestamp};
use rebuilderd_common::config::CleanupConfig;
use rebuilderd_common::errors::*;
use std::thread;

// keep write transactions short so workers can still report in between
const BATCH_SIZE: usize = 500;

/// Periodically delete old rebuilds in a background thread.
pub fn spawn(pool: Pool, config: CleanupConfig) {
    thread::spawn(move || {
        loop {
            match pool.get() {
                Ok(mut connection) => {
                    if let Err(err) = run(connection.as_mut(), &config) {
                        error!("Database cleanup failed: {err:#}");
                    }
                }
                Err(err) => error!("Failed to get database connection for cleanup: {err:#}"),
            }
            thread::sleep(config.interval());
        }
    });
}

/// Delete rebuilds exceeding `keep_rebuilds` per build input or older than
/// `max_rebuild_age`, together with the logs nothing references anymore. The
/// newest rebuild of every build input is always kept. Returns the number of
/// deleted rebuilds.
pub fn run(connection: &mut SqliteConnection, config: &CleanupConfig) -> Result<usize> {
    let ids = select_expired_rebuilds(connection, config)?;
    if ids.is_empty() {
        debug!("Database cleanup: nothing to delete");
        return Ok(0);
    }

    info!("Database cleanup: deleting {} rebuilds", ids.len());
    for chunk in ids.chunks(BATCH_SIZE) {
        connection.immediate_transaction(|connection| delete_rebuilds(connection, chunk))?;
    }

    // only reclaims disk space if the database uses auto_vacuum=INCREMENTAL
    connection.batch_execute("PRAGMA incremental_vacuum;")?;

    info!("Database cleanup: deleted {} rebuilds", ids.len());
    Ok(ids.len())
}

fn select_expired_rebuilds(
    connection: &mut SqliteConnection,
    config: &CleanupConfig,
) -> Result<Vec<i32>> {
    let keep = config.keep_rebuilds();
    let cutoff = config
        .max_rebuild_age()
        .map(|age| (Utc::now() - age).naive_utc());

    // rank the rebuilds of each build input, newest first (same order as the dashboard)
    let ranked = sql::<Bool>(
        "rebuilds.id IN (SELECT id FROM (
            SELECT id, built_at, ROW_NUMBER() OVER (
                PARTITION BY build_input_id ORDER BY built_at DESC, id DESC
            ) AS rank
            FROM rebuilds
        ) WHERE rank > 1",
    );
    let query = rebuilds::table.select(rebuilds::id);

    let ids = match (keep, cutoff) {
        (None, None) => vec![],
        (Some(keep), None) => query
            .filter(ranked.sql(" AND rank > ").bind::<BigInt, _>(keep).sql(")"))
            .load(connection)?,
        (None, Some(cutoff)) => query
            .filter(
                ranked
                    .sql(" AND built_at < ")
                    .bind::<Timestamp, _>(cutoff)
                    .sql(")"),
            )
            .load(connection)?,
        (Some(keep), Some(cutoff)) => query
            .filter(
                ranked
                    .sql(" AND (rank > ")
                    .bind::<BigInt, _>(keep)
                    .sql(" OR built_at < ")
                    .bind::<Timestamp, _>(cutoff)
                    .sql("))"),
            )
            .load(connection)?,
    };

    Ok(ids)
}

fn delete_rebuilds(connection: &mut SqliteConnection, ids: &[i32]) -> Result<()> {
    let build_log_ids = rebuilds::table
        .filter(rebuilds::id.eq_any(ids))
        .select(rebuilds::build_log_id)
        .load::<i32>(connection)?;

    let (diffoscope_log_ids, attestation_log_ids): (Vec<_>, Vec<_>) = rebuild_artifacts::table
        .filter(rebuild_artifacts::rebuild_id.eq_any(ids))
        .select((
            rebuild_artifacts::diffoscope_log_id,
            rebuild_artifacts::attestation_log_id,
        ))
        .load::<(Option<i32>, Option<i32>)>(connection)?
        .into_iter()
        .unzip();
    let diffoscope_log_ids = diffoscope_log_ids.into_iter().flatten().collect::<Vec<_>>();
    let attestation_log_ids = attestation_log_ids
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    // cascades to rebuild_artifacts
    diesel::delete(rebuilds::table.filter(rebuilds::id.eq_any(ids))).execute(connection)?;

    // logs can be shared between rebuilds of build inputs with identical inputs,
    // only delete them once nothing references them anymore
    diesel::delete(
        build_logs::table
            .filter(build_logs::id.eq_any(&build_log_ids))
            .filter(not(exists(
                rebuilds::table.filter(rebuilds::build_log_id.eq(build_logs::id)),
            ))),
    )
    .execute(connection)?;

    diesel::delete(
        diffoscope_logs::table
            .filter(diffoscope_logs::id.eq_any(&diffoscope_log_ids))
            .filter(not(exists(rebuild_artifacts::table.filter(
                rebuild_artifacts::diffoscope_log_id.eq(diffoscope_logs::id.nullable()),
            )))),
    )
    .execute(connection)?;

    diesel::delete(
        attestation_logs::table
            .filter(attestation_logs::id.eq_any(&attestation_log_ids))
            .filter(not(exists(rebuild_artifacts::table.filter(
                rebuild_artifacts::attestation_log_id.eq(attestation_logs::id.nullable()),
            )))),
    )
    .execute(connection)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::models::*;
    use chrono::Duration;

    struct Fixture {
        connection: SqliteConnection,
        rebuilds: Vec<i32>,
        logs: Vec<i32>,
        diffoscope: i32,
    }

    /// Two build inputs: the first has three rebuilds (10 days old, 5 days old
    /// and new), the second a single 10 day old rebuild sharing its build log
    /// with the oldest rebuild of the first.
    fn setup() -> Fixture {
        let mut connection = db::setup(":memory:").unwrap();
        connection
            .batch_execute("PRAGMA foreign_keys = ON;")
            .unwrap();
        let now = Utc::now().naive_utc();

        let source_package = NewSourcePackage {
            name: "foo".to_string(),
            version: "1.0".to_string(),
            distribution: "openwrt".to_string(),
            release: None,
            last_seen: now,
            seen_in_last_sync: true,
        }
        .upsert(&mut connection)
        .unwrap();

        let build_inputs = ["a", "b"].map(|backend| {
            NewBuildInput {
                source_package_id: source_package.id,
                url: "https://example.com/input".to_string(),
                backend: backend.to_string(),
                architecture: "x86/64".to_string(),
                retries: 0,
                next_retry: None,
            }
            .upsert(&mut connection)
            .unwrap()
            .id
        });

        let logs = (0..3)
            .map(|_| {
                NewBuildLog { build_log: vec![] }
                    .insert(&mut connection)
                    .unwrap()
            })
            .collect::<Vec<_>>();

        let rebuilds = [
            (build_inputs[0], 10, logs[0]),
            (build_inputs[0], 5, logs[1]),
            (build_inputs[0], 0, logs[2]),
            (build_inputs[1], 10, logs[0]),
        ]
        .map(|(build_input_id, age, build_log_id)| {
            NewRebuild {
                build_input_id,
                started_at: None,
                built_at: Some(now - Duration::days(age)),
                build_log_id,
                status: Some("BAD".to_string()),
            }
            .insert(&mut connection)
            .unwrap()
        })
        .to_vec();

        let diffoscope = NewDiffoscopeLog {
            diffoscope_log: vec![],
        }
        .insert(&mut connection)
        .unwrap();
        NewRebuildArtifact {
            rebuild_id: rebuilds[0],
            name: "foo.apk".to_string(),
            diffoscope_log_id: Some(diffoscope),
            attestation_log_id: None,
            status: Some("BAD".to_string()),
        }
        .insert(&mut connection)
        .unwrap();

        Fixture {
            connection,
            rebuilds,
            logs,
            diffoscope,
        }
    }

    fn remaining_rebuilds(connection: &mut SqliteConnection) -> Vec<i32> {
        rebuilds::table
            .select(rebuilds::id)
            .order_by(rebuilds::id)
            .load(connection)
            .unwrap()
    }

    fn remaining_logs(connection: &mut SqliteConnection) -> Vec<i32> {
        build_logs::table
            .select(build_logs::id)
            .order_by(build_logs::id)
            .load(connection)
            .unwrap()
    }

    #[test]
    fn keep_latest_rebuild() {
        let mut f = setup();
        let config = CleanupConfig {
            keep_rebuilds: Some(1),
            ..Default::default()
        };

        assert_eq!(run(&mut f.connection, &config).unwrap(), 2);
        assert_eq!(
            remaining_rebuilds(&mut f.connection),
            vec![f.rebuilds[2], f.rebuilds[3]]
        );
        // the shared log is still referenced by the second build input
        assert_eq!(
            remaining_logs(&mut f.connection),
            vec![f.logs[0], f.logs[2]]
        );
        let artifacts = rebuild_artifacts::table
            .count()
            .get_result::<i64>(&mut f.connection)
            .unwrap();
        assert_eq!(artifacts, 0);
        let diffoscope = diffoscope_logs::table
            .find(f.diffoscope)
            .count()
            .get_result::<i64>(&mut f.connection)
            .unwrap();
        assert_eq!(diffoscope, 0);

        // running again is a no-op
        assert_eq!(run(&mut f.connection, &config).unwrap(), 0);
    }

    #[test]
    fn keep_zero_still_keeps_latest_rebuild() {
        let mut f = setup();
        let config = CleanupConfig {
            keep_rebuilds: Some(0),
            ..Default::default()
        };

        assert_eq!(run(&mut f.connection, &config).unwrap(), 2);
        assert_eq!(
            remaining_rebuilds(&mut f.connection),
            vec![f.rebuilds[2], f.rebuilds[3]]
        );
    }

    #[test]
    fn keep_two_rebuilds() {
        let mut f = setup();
        let config = CleanupConfig {
            keep_rebuilds: Some(2),
            ..Default::default()
        };

        assert_eq!(run(&mut f.connection, &config).unwrap(), 1);
        assert_eq!(
            remaining_rebuilds(&mut f.connection),
            vec![f.rebuilds[1], f.rebuilds[2], f.rebuilds[3]]
        );
        assert_eq!(remaining_logs(&mut f.connection), f.logs);
    }

    #[test]
    fn max_rebuild_age() {
        let mut f = setup();
        let config = CleanupConfig {
            max_rebuild_age: Some(7),
            ..Default::default()
        };

        // the second build input's only rebuild is old, but it's the latest one
        assert_eq!(run(&mut f.connection, &config).unwrap(), 1);
        assert_eq!(
            remaining_rebuilds(&mut f.connection),
            vec![f.rebuilds[1], f.rebuilds[2], f.rebuilds[3]]
        );
    }

    #[test]
    fn keep_rebuilds_or_max_rebuild_age() {
        let mut f = setup();
        let config = CleanupConfig {
            keep_rebuilds: Some(3),
            max_rebuild_age: Some(3),
            ..Default::default()
        };

        assert_eq!(run(&mut f.connection, &config).unwrap(), 2);
        assert_eq!(
            remaining_rebuilds(&mut f.connection),
            vec![f.rebuilds[2], f.rebuilds[3]]
        );
    }

    #[test]
    fn disabled_by_default() {
        let mut f = setup();
        assert_eq!(
            run(&mut f.connection, &CleanupConfig::default()).unwrap(),
            0
        );
        assert_eq!(remaining_rebuilds(&mut f.connection), f.rebuilds);
    }
}
