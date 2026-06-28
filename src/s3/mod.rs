//! S3 protocol helpers: time formatting and the XML wire types.

pub mod xml;

use time::format_description::FormatItem;
use time::macros::format_description;
use time::OffsetDateTime;

/// ISO-8601 format with millisecond precision, e.g. `2006-01-02T15:04:05.000Z`,
/// used for `CreationDate` / `LastModified` in S3 list responses.
const ISO8601: &[FormatItem<'_>] = format_description!(
    "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
);

/// RFC 7231 IMF-fixdate format, e.g. `Wed, 21 Oct 2015 07:28:00 GMT`, used for
/// the HTTP `Last-Modified` response header.
const HTTP_DATE: &[FormatItem<'_>] = format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);

/// Format a timestamp as an S3 ISO-8601 string (millisecond precision, UTC).
///
/// # Parameters
/// - `dt`: the timestamp to format (treated as UTC).
///
/// # Returns
/// A string such as `2026-06-22T15:04:05.000Z`, or an empty string if
/// formatting fails (which it should not for valid timestamps).
pub fn iso8601(dt: OffsetDateTime) -> String {
    dt.to_offset(time::UtcOffset::UTC)
        .format(ISO8601)
        .unwrap_or_default()
}

/// Format a timestamp as an HTTP-date string for the `Last-Modified` header.
///
/// # Parameters
/// - `dt`: the timestamp to format (treated as UTC).
///
/// # Returns
/// A string such as `Wed, 21 Oct 2015 07:28:00 GMT`, or an empty string if
/// formatting fails.
pub fn http_date(dt: OffsetDateTime) -> String {
    dt.to_offset(time::UtcOffset::UTC)
        .format(HTTP_DATE)
        .unwrap_or_default()
}
