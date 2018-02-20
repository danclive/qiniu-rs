extern crate ring;
extern crate data_encoding;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

use ring::hmac;
use ring::digest::SHA1;
use data_encoding::BASE64URL;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PutPolicy {
    pub scope: String,                           // Bucket
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_prefixal_scope: Option<i32>,          // IsPrefixalScope
    pub deadline: u32,                           // UnixTimestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insert_only: Option<i32>,                // AllowFileUpdating
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_user: Option<String>,                // EndUserId
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_url: Option<String>,              // RedirectURL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_body: Option<String>,             // ResponseBodyForAppClient
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,            // RequestUrlForAppServer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_host: Option<String>,           // RequestHostForAppServer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_body: Option<String>,           // RequestBodyForAppServer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_body_type: Option<String>,      // RequestBodyTypeForAppServer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_ops: Option<String>,          // PersistentOpsCmds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_notify_url: Option<String>,   // PersistentNotifyUrl
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_pipeline: Option<String>,     // PersistentPipeline
    #[serde(skip_serializing_if = "Option::is_none")]
    pub save_key: Option<String>,                // SaveKey
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fsize_min: Option<i64>,                  // FileSizeMin
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fsize_limit: Option<i64>,                // FileSizeLimit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detect_mime: Option<i32>,                // AutoDetectMimeType
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_limit: Option<String>,              // MimeLimit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_type: Option<i32>                   // FileType
}

impl PutPolicy {
    pub fn new<S: Into<String>>(scope: S, deadline: u32) -> PutPolicy {
        PutPolicy {
            scope: scope.into(),
            is_prefixal_scope: None,
            deadline: deadline,
            insert_only: None,
            end_user: None,
            return_url: None,
            return_body: None,
            callback_url: None,
            callback_host: None,
            callback_body: None,
            callback_body_type: None,
            persistent_ops: None,
            persistent_notify_url: None,
            persistent_pipeline: None,
            save_key: None,
            fsize_min: None,
            fsize_limit: None,
            detect_mime: None,
            mime_limit: None,
            file_type: None
        }
    }

    pub fn to_base64(&self) -> String {
        BASE64URL.encode(&serde_json::to_vec(&self).unwrap())
    }

    pub fn generate_uptoken(&self, config: &Config) -> String {

        let sign_key = hmac::SigningKey::new(&SHA1, config.secret_key.as_bytes());

        let self_base64 = self.to_base64();

        let signature = hmac::sign(&sign_key, self_base64.as_bytes());

        let signature_base64 = data_encoding::BASE64URL.encode(signature.as_ref());

        format!(
            "{}:{}:{}",
            config.access_key,
            signature_base64,
            self_base64
        )
    }
}

pub struct Config {
    pub access_key: String,
    pub secret_key: String
}

impl Config {
    pub fn new<S: Into<String>>(access_key: S, secret_key: S) -> Config {
        Config {
            access_key: access_key.into(),
            secret_key: secret_key.into()
        }
    }
}
