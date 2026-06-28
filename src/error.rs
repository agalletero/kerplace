//! S3-style error type and its conversion into an HTTP/XML response.
//!
//! Every error returned to a client is rendered as the standard S3 error
//! document, e.g.:
//!
//! ```xml
//! <?xml version="1.0" encoding="UTF-8"?>
//! <Error>
//!   <Code>NoSuchBucket</Code>
//!   <Message>The specified bucket does not exist.</Message>
//!   <Resource>/my-bucket</Resource>
//!   <RequestId>...</RequestId>
//! </Error>
//! ```

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

/// All error conditions the S3 API surface can return.
///
/// Each variant maps to a stable S3 error `Code`, a human-readable message
/// and an HTTP status code (see [`S3Error::code`], [`S3Error::message`],
/// [`S3Error::status`]).
#[derive(Debug, Clone, thiserror::Error)]
pub enum S3Error {
    #[error("bucket does not exist")]
    NoSuchBucket,
    #[error("key does not exist")]
    NoSuchKey,
    #[error("bucket already exists")]
    BucketAlreadyOwnedByYou,
    #[error("bucket not empty")]
    BucketNotEmpty,
    #[error("invalid bucket name")]
    InvalidBucketName,
    #[error("multipart upload does not exist")]
    NoSuchUpload,
    #[error("one or more parts could not be found")]
    InvalidPart,
    #[error("part too small")]
    // Reserved for multipart minimum-part-size enforcement (not yet wired up).
    #[allow(dead_code)]
    EntityTooSmall,
    #[error("access denied")]
    AccessDenied,
    #[error("signature mismatch")]
    SignatureDoesNotMatch,
    #[error("unknown access key")]
    InvalidAccessKeyId,
    #[error("malformed authorization header")]
    AuthorizationHeaderMalformed,
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("not implemented")]
    NotImplemented,
    #[error("internal error: {0}")]
    Internal(String),
    #[error("no encryption configuration for bucket")]
    NoSuchBucketEncryption,
    #[error("no policy for bucket")]
    NoSuchBucketPolicy,
    #[error("no lifecycle configuration for bucket")]
    NoSuchLifecycleConfiguration,
    #[error("object is locked and cannot be deleted or overwritten")]
    ObjectLocked,
    #[error("the specified version does not exist")]
    NoSuchVersion,
    #[error("method not allowed on this resource")]
    MethodNotAllowed,
}

impl S3Error {
    /// Return the stable S3 error code string for this error.
    ///
    /// # Parameters
    /// - `&self`: the error variant.
    ///
    /// # Returns
    /// The S3 `Code` value (e.g. `"NoSuchBucket"`).
    pub fn code(&self) -> &'static str {
        match self {
            S3Error::NoSuchBucket => "NoSuchBucket",
            S3Error::NoSuchKey => "NoSuchKey",
            S3Error::BucketAlreadyOwnedByYou => "BucketAlreadyOwnedByYou",
            S3Error::BucketNotEmpty => "BucketNotEmpty",
            S3Error::InvalidBucketName => "InvalidBucketName",
            S3Error::NoSuchUpload => "NoSuchUpload",
            S3Error::InvalidPart => "InvalidPart",
            S3Error::EntityTooSmall => "EntityTooSmall",
            S3Error::AccessDenied => "AccessDenied",
            S3Error::SignatureDoesNotMatch => "SignatureDoesNotMatch",
            S3Error::InvalidAccessKeyId => "InvalidAccessKeyId",
            S3Error::AuthorizationHeaderMalformed => "AuthorizationHeaderMalformed",
            S3Error::InvalidArgument(_) => "InvalidArgument",
            S3Error::NotImplemented => "NotImplemented",
            S3Error::Internal(_) => "InternalError",
            S3Error::NoSuchBucketEncryption => "ServerSideEncryptionConfigurationNotFoundError",
            S3Error::NoSuchBucketPolicy => "NoSuchBucketPolicy",
            S3Error::NoSuchLifecycleConfiguration => "NoSuchLifecycleConfiguration",
            S3Error::ObjectLocked => "ObjectLocked",
            S3Error::NoSuchVersion => "NoSuchVersion",
            S3Error::MethodNotAllowed => "MethodNotAllowed",
        }
    }

    /// Return the human-readable message for this error.
    ///
    /// # Parameters
    /// - `&self`: the error variant.
    ///
    /// # Returns
    /// An owned message string suitable for the `<Message>` element.
    pub fn message(&self) -> String {
        match self {
            S3Error::NoSuchBucket => "The specified bucket does not exist.".into(),
            S3Error::NoSuchKey => "The specified key does not exist.".into(),
            S3Error::BucketAlreadyOwnedByYou => {
                "The bucket you tried to create already exists, and you own it.".into()
            }
            S3Error::BucketNotEmpty => "The bucket you tried to delete is not empty.".into(),
            S3Error::InvalidBucketName => "The specified bucket is not valid.".into(),
            S3Error::NoSuchUpload => {
                "The specified multipart upload does not exist.".into()
            }
            S3Error::InvalidPart => {
                "One or more of the specified parts could not be found.".into()
            }
            S3Error::EntityTooSmall => {
                "Your proposed upload is smaller than the minimum allowed object size.".into()
            }
            S3Error::AccessDenied => "Access Denied.".into(),
            S3Error::SignatureDoesNotMatch => {
                "The request signature we calculated does not match the signature you provided."
                    .into()
            }
            S3Error::InvalidAccessKeyId => {
                "The access key Id you provided does not exist in our records.".into()
            }
            S3Error::AuthorizationHeaderMalformed => {
                "The authorization header that you provided is not valid.".into()
            }
            S3Error::InvalidArgument(m) => m.clone(),
            S3Error::NotImplemented => {
                "A header or operation you provided is not implemented.".into()
            }
            S3Error::Internal(m) => format!("We encountered an internal error: {m}"),
            S3Error::NoSuchBucketEncryption => {
                "The server side encryption configuration was not found.".into()
            }
            S3Error::NoSuchBucketPolicy => "The bucket policy does not exist.".into(),
            S3Error::NoSuchLifecycleConfiguration => {
                "The lifecycle configuration does not exist.".into()
            }
            S3Error::ObjectLocked => {
                "Object is protected by an active lock and cannot be deleted or modified.".into()
            }
            S3Error::NoSuchVersion => "The specified version does not exist.".into(),
            S3Error::MethodNotAllowed => {
                "The specified method is not allowed against this resource.".into()
            }
        }
    }

    /// Return the HTTP status code associated with this error.
    ///
    /// # Parameters
    /// - `&self`: the error variant.
    ///
    /// # Returns
    /// The [`StatusCode`] S3 uses for this error condition.
    pub fn status(&self) -> StatusCode {
        match self {
            S3Error::NoSuchBucket | S3Error::NoSuchKey | S3Error::NoSuchUpload => {
                StatusCode::NOT_FOUND
            }
            S3Error::BucketAlreadyOwnedByYou => StatusCode::CONFLICT,
            S3Error::BucketNotEmpty => StatusCode::CONFLICT,
            S3Error::InvalidBucketName
            | S3Error::InvalidPart
            | S3Error::EntityTooSmall
            | S3Error::AuthorizationHeaderMalformed
            | S3Error::InvalidArgument(_) => StatusCode::BAD_REQUEST,
            S3Error::AccessDenied
            | S3Error::SignatureDoesNotMatch
            | S3Error::InvalidAccessKeyId => StatusCode::FORBIDDEN,
            S3Error::NotImplemented => StatusCode::NOT_IMPLEMENTED,
            S3Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            S3Error::NoSuchBucketEncryption
            | S3Error::NoSuchBucketPolicy
            | S3Error::NoSuchLifecycleConfiguration => StatusCode::NOT_FOUND,
            S3Error::ObjectLocked => StatusCode::FORBIDDEN,
            S3Error::NoSuchVersion => StatusCode::NOT_FOUND,
            S3Error::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
        }
    }

    /// Render this error as a full HTTP response, including the `Resource`
    /// element so clients can correlate the failure with the request path.
    ///
    /// # Parameters
    /// - `&self`: the error variant.
    /// - `resource`: the request path (e.g. `/bucket/key`) echoed back to
    ///   the caller in the `<Resource>` element.
    ///
    /// # Returns
    /// An axum [`Response`] with the appropriate status, `application/xml`
    /// content type and a serialized S3 `<Error>` body.
    pub fn into_response_with_resource(&self, resource: &str) -> Response {
        let request_id = Uuid::new_v4().simple().to_string();
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<Error><Code>{code}</Code><Message>{message}</Message>\
<Resource>{resource}</Resource><RequestId>{request_id}</RequestId></Error>",
            code = self.code(),
            message = xml_escape(&self.message()),
            resource = xml_escape(resource),
        );
        (
            self.status(),
            [(header::CONTENT_TYPE, "application/xml")],
            body,
        )
            .into_response()
    }
}

impl IntoResponse for S3Error {
    /// Convert the error into a response without a known resource path.
    ///
    /// # Returns
    /// An axum [`Response`] with an empty `<Resource>` element. Prefer
    /// [`S3Error::into_response_with_resource`] when the path is available.
    fn into_response(self) -> Response {
        self.into_response_with_resource("")
    }
}

/// Escape the five XML predefined entities in a string.
///
/// # Parameters
/// - `s`: the raw text to escape.
///
/// # Returns
/// A new `String` safe to embed as XML element text or attribute content.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
