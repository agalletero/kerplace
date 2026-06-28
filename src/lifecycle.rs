//! Lifecycle / ILM background worker.
//!
//! Implements S3-compatible object expiration: periodically scans all buckets,
//! evaluates the stored `LifecycleConfiguration` rules and deletes objects
//! that match an enabled expiration rule.
//!
//! Only `Expiration` actions are executed in v0.1 (`Days` and `Date` variants).
//! `NoncurrentVersionExpiration` and transitions to other storage classes are
//! accepted in the XML but silently ignored until those features are added.
//!
//! Objects under an active legal hold are skipped — they must be removed
//! through `PUT ?legal-hold` first.

use std::sync::Arc;

use time::OffsetDateTime;
use tracing::{debug, info, warn};

use crate::s3::xml::{self, LifecycleConfiguration, ObjectRetention};
use crate::storage::ObjectStore;

/// Spawn the lifecycle background worker.
///
/// The worker runs one scan immediately on startup, then sleeps for
/// `interval` between scans.  It is a detached `tokio::spawn` task — the
/// caller does not need to await or track it; panics inside are logged and
/// the task exits.
///
/// # Parameters
/// - `store`: shared object store (any `ObjectStore` implementation).
/// - `interval`: sleep duration between full-bucket scans.
pub fn start_lifecycle_worker(store: Arc<dyn ObjectStore>, interval: tokio::time::Duration) {
    tokio::spawn(async move {
        loop {
            run_lifecycle_pass(&store).await;
            tokio::time::sleep(interval).await;
        }
    });
}

/// Run one complete lifecycle pass: every bucket, every enabled rule.
///
/// Errors per bucket are logged and do not abort the scan of remaining buckets.
///
/// # Parameters
/// - `store`: shared object store.
async fn run_lifecycle_pass(store: &Arc<dyn ObjectStore>) {
    let buckets = match store.list_buckets().await {
        Ok(b) => b,
        Err(e) => {
            warn!("lifecycle: list_buckets failed: {e}");
            return;
        }
    };

    for bucket in &buckets {
        if let Err(msg) = expire_bucket(store, &bucket.name).await {
            warn!(bucket = %bucket.name, "lifecycle: {msg}");
        }
    }
}

/// Apply lifecycle expiration rules to a single bucket.
///
/// Reads the bucket's `LifecycleConfiguration`, then for each `Enabled` rule
/// with an `Expiration` action, pages through all matching objects and deletes
/// those whose age exceeds the expiration threshold.
///
/// # Parameters
/// - `store`: shared object store.
/// - `bucket`: the bucket to scan.
///
/// # Returns
/// `Ok(())` always — per-object errors are logged and skipped.
/// `Err(String)` only if the lifecycle configuration itself is unreadable.
async fn expire_bucket(store: &Arc<dyn ObjectStore>, bucket: &str) -> Result<(), String> {
    let raw = match store.get_bucket_lifecycle(bucket).await {
        Ok(Some(xml)) => xml,
        Ok(None) => return Ok(()),
        Err(_) => return Ok(()),
    };

    let cfg: LifecycleConfiguration = xml::from_xml(&raw)
        .map_err(|e| format!("bad LifecycleConfiguration XML: {e}"))?;

    let now = OffsetDateTime::now_utc();

    for rule in &cfg.rules {
        if !rule.status.eq_ignore_ascii_case("Enabled") {
            continue;
        }

        let expiration = match &rule.expiration {
            Some(e) => e,
            None => continue,
        };

        let prefix = rule
            .filter
            .as_ref()
            .and_then(|f| f.prefix.as_deref())
            .unwrap_or("");

        expire_objects(store, bucket, prefix, expiration, now).await;
    }

    Ok(())
}

/// Delete all objects under `prefix` in `bucket` that satisfy the expiration rule.
///
/// Pages through `list_objects_v2` (up to 1 000 per page) and checks each
/// object's `last_modified` age.  Objects under an active legal hold are
/// silently skipped.
///
/// # Parameters
/// - `store`: shared object store.
/// - `bucket`: bucket to scan.
/// - `prefix`: key prefix filter (empty string = all keys).
/// - `expiration`: the expiration action from the lifecycle rule.
/// - `now`: current time (computed once per pass for consistency).
async fn expire_objects(
    store: &Arc<dyn ObjectStore>,
    bucket: &str,
    prefix: &str,
    expiration: &crate::s3::xml::LifecycleExpiration,
    now: OffsetDateTime,
) {
    let mut continuation: Option<String> = None;

    loop {
        let listing = match store
            .list_objects_v2(bucket, prefix, None, continuation.as_deref(), None, 1000)
            .await
        {
            Ok(l) => l,
            Err(e) => {
                warn!(bucket, prefix, "lifecycle: list_objects_v2 failed: {e}");
                break;
            }
        };

        for obj in &listing.objects {
            if should_expire(expiration, obj.last_modified, now) {
                // Object lock (legal hold or unexpired retention) overrides
                // lifecycle expiration, matching S3 semantics and the delete
                // handler's enforcement.
                if object_locked(store, bucket, &obj.key, now).await {
                    debug!(bucket, key = %obj.key, "lifecycle: skipping (object lock active)");
                    continue;
                }

                match store.delete_object(bucket, &obj.key).await {
                    Ok(_) => {
                        let age = (now - obj.last_modified).whole_days();
                        info!(bucket, key = %obj.key, age_days = age, "lifecycle: expired object");
                    }
                    Err(e) => warn!(bucket, key = %obj.key, "lifecycle: delete failed: {e}"),
                }
            }
        }

        if listing.is_truncated {
            continuation = listing.next_continuation_token;
        } else {
            break;
        }
    }
}

/// Return `true` if the object is protected from deletion by an active legal
/// hold or an unexpired retention period.
///
/// Mirrors the enforcement in the `DELETE` object handler so lifecycle
/// expiration never removes a locked object.
///
/// # Parameters
/// - `store`: shared object store.
/// - `bucket`: bucket containing the object.
/// - `key`: object key to check.
/// - `now`: current UTC time (computed once per pass).
///
/// # Returns
/// `true` if a legal hold is `ON` or the retention date is still in the future.
async fn object_locked(
    store: &Arc<dyn ObjectStore>,
    bucket: &str,
    key: &str,
    now: OffsetDateTime,
) -> bool {
    // Legal hold blocks unconditionally.
    if let Ok(Some(status)) = store.get_object_legal_hold(bucket, key).await {
        if status.eq_ignore_ascii_case("ON") {
            return true;
        }
    }

    // Retention blocks until its RetainUntilDate has passed.
    if let Ok(Some(raw)) = store.get_object_retention(bucket, key).await {
        if let Ok(r) = xml::from_xml::<ObjectRetention>(&raw) {
            if let Some(date_str) = r.retain_until_date {
                if let Ok(until) = OffsetDateTime::parse(
                    &date_str,
                    &time::format_description::well_known::Rfc3339,
                ) {
                    if until > now {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Return `true` if the object should be deleted under the given expiration rule.
///
/// Supports two variants:
/// - `Days`: object is expired when `now - last_modified >= days`.
/// - `Date`: object is expired when `now >= date`.
///
/// # Parameters
/// - `exp`: the `LifecycleExpiration` action from the rule.
/// - `last_modified`: the object's last-modified timestamp.
/// - `now`: current UTC time.
///
/// # Returns
/// `true` if the object matches the expiration condition.
fn should_expire(
    exp: &crate::s3::xml::LifecycleExpiration,
    last_modified: OffsetDateTime,
    now: OffsetDateTime,
) -> bool {
    if let Some(days) = exp.days {
        let age = (now - last_modified).whole_days();
        return age >= days as i64;
    }
    if let Some(ref date_str) = exp.date {
        if let Ok(exp_date) = OffsetDateTime::parse(
            date_str,
            &time::format_description::well_known::Rfc3339,
        ) {
            return now >= exp_date;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    /// `Days` expiration: object is expired when its age meets the threshold.
    #[test]
    fn days_expiration_logic() {
        let exp = crate::s3::xml::LifecycleExpiration { days: Some(30), date: None };
        let now = datetime!(2026-06-23 12:00:00 UTC);

        // 31 days old — should expire.
        let old = now - time::Duration::days(31);
        assert!(should_expire(&exp, old, now));

        // 29 days old — should not expire.
        let recent = now - time::Duration::days(29);
        assert!(!should_expire(&exp, recent, now));
    }

    /// `Date` expiration: object is expired when the fixed date has passed.
    #[test]
    fn date_expiration_logic() {
        let exp = crate::s3::xml::LifecycleExpiration {
            days: None,
            date: Some("2025-01-01T00:00:00Z".to_string()),
        };
        let now = datetime!(2026-06-23 12:00:00 UTC);
        let last_modified = datetime!(2024-01-01 00:00:00 UTC);

        // now is past the expiration date — should expire.
        assert!(should_expire(&exp, last_modified, now));

        // now is before the expiration date — should not expire.
        let early_now = datetime!(2024-06-01 00:00:00 UTC);
        assert!(!should_expire(&exp, last_modified, early_now));
    }
}
