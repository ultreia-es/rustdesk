use super::sigv4::{self, Credentials};
use hbb_common::{anyhow::anyhow, bail, chrono, ResultType};
use reqwest::blocking::{Client, Response};
use url::Url;

pub struct Target {
    pub endpoint: Url,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    pub path_style: bool,
}

impl Target {
    /// Plain HTTP is accepted only for a loopback endpoint (local test servers).
    pub fn new(
        endpoint: &str,
        region: &str,
        bucket: &str,
        access_key: &str,
        secret_key: &str,
        path_style: bool,
    ) -> ResultType<Self> {
        let endpoint = Url::parse(endpoint)?;
        match endpoint.scheme() {
            "https" => {}
            "http" if is_loopback(&endpoint) => {}
            _ => bail!("recording upload endpoint must use https"),
        }
        if endpoint.host_str().is_none() {
            bail!("recording upload endpoint has no host");
        }
        if region.is_empty() || bucket.is_empty() || access_key.is_empty() || secret_key.is_empty()
        {
            bail!("recording upload region, bucket and credentials are required");
        }
        Ok(Self {
            endpoint,
            region: region.to_owned(),
            bucket: bucket.to_owned(),
            access_key: access_key.to_owned(),
            secret_key: secret_key.to_owned(),
            path_style,
        })
    }

    fn host(&self) -> String {
        let host = self.endpoint.host_str().unwrap_or_default();
        let host = if self.path_style {
            host.to_owned()
        } else {
            format!("{}.{}", self.bucket, host)
        };
        match self.endpoint.port() {
            Some(port) => format!("{}:{}", host, port),
            None => host,
        }
    }

    fn path(&self, key: &str) -> String {
        if self.path_style {
            format!("/{}/{}", self.bucket, key)
        } else {
            format!("/{}", key)
        }
    }

    fn send(
        &self,
        client: &Client,
        method: &str,
        key: &str,
        query: &[(&str, &str)],
        extra_headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> ResultType<Response> {
        let payload_sha256 = sigv4::sha256_hex(&body);
        let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let host = self.host();
        let path = self.path(key);
        let mut headers: Vec<(&str, &str)> = vec![
            ("host", &host),
            ("x-amz-date", &amz_date),
            ("x-amz-content-sha256", &payload_sha256),
        ];
        headers.extend_from_slice(extra_headers);
        let authorization = sigv4::authorization(
            &Credentials {
                access_key: &self.access_key,
                secret_key: &self.secret_key,
                region: &self.region,
                service: "s3",
            },
            &sigv4::Request {
                method,
                path: &path,
                query,
                headers: &headers,
                payload_sha256: &payload_sha256,
            },
            &amz_date,
        )?;
        let mut url = format!(
            "{}://{}{}",
            self.endpoint.scheme(),
            host,
            sigv4::encode_path(&path)
        );
        if !query.is_empty() {
            url.push('?');
            url.push_str(&sigv4::encode_query(query));
        }
        let method = reqwest::Method::from_bytes(method.as_bytes())?;
        let mut req = client.request(method, url).body(body);
        for (k, v) in headers.iter().filter(|(k, _)| *k != "host") {
            req = req.header(*k, *v);
        }
        Ok(req.header("authorization", authorization).send()?)
    }
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// S3 error bodies carry `Code` and `Message`, never request credentials.
fn check(resp: Response, op: &str) -> ResultType<Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().unwrap_or_default();
    bail!(
        "{} failed: {} {}",
        op,
        status,
        xml_value(&body, "Code").unwrap_or_default()
    );
}

fn etag(resp: &Response) -> ResultType<String> {
    resp.headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("response has no ETag"))
}

fn xml_value(body: &str, tag: &str) -> Option<String> {
    let start = body.find(&format!("<{}>", tag))? + tag.len() + 2;
    let end = start + body[start..].find(&format!("</{}>", tag))?;
    Some(body[start..end].to_owned())
}

/// `headers` are extra signed headers such as `x-amz-meta-*`. Returns the
/// ETag, or `None` when an `If-None-Match: *` precondition failed because the
/// object already exists.
pub fn put_object(
    client: &Client,
    target: &Target,
    key: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> ResultType<Option<String>> {
    let resp = target.send(client, "PUT", key, &[], headers, body)?;
    if resp.status() == reqwest::StatusCode::PRECONDITION_FAILED {
        return Ok(None);
    }
    Ok(Some(etag(&check(resp, "PutObject")?)?))
}

pub fn create_multipart_upload(
    client: &Client,
    target: &Target,
    key: &str,
    headers: &[(&str, &str)],
) -> ResultType<String> {
    let resp = target.send(client, "POST", key, &[("uploads", "")], headers, vec![])?;
    let body = check(resp, "CreateMultipartUpload")?.text()?;
    xml_value(&body, "UploadId").ok_or_else(|| anyhow!("CreateMultipartUpload: no UploadId"))
}

pub fn upload_part(
    client: &Client,
    target: &Target,
    key: &str,
    upload_id: &str,
    part_number: u32,
    body: Vec<u8>,
) -> ResultType<String> {
    let part_number = part_number.to_string();
    let query = [
        ("partNumber", part_number.as_str()),
        ("uploadId", upload_id),
    ];
    let resp = target.send(client, "PUT", key, &query, &[], body)?;
    etag(&check(resp, "UploadPart")?)
}

/// `parts` are `(part_number, etag)` in ascending order. Returns the ETag.
pub fn complete_multipart_upload(
    client: &Client,
    target: &Target,
    key: &str,
    upload_id: &str,
    parts: &[(u32, String)],
) -> ResultType<String> {
    let mut body = String::from("<CompleteMultipartUpload>");
    for (n, etag) in parts {
        body.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
            n, etag
        ));
    }
    body.push_str("</CompleteMultipartUpload>");
    let resp = target.send(
        client,
        "POST",
        key,
        &[("uploadId", upload_id)],
        &[],
        body.into_bytes(),
    )?;
    let body = check(resp, "CompleteMultipartUpload")?.text()?;
    // S3 may report a failed completion with 200 and an <Error> body.
    if let Some(code) = xml_value(&body, "Code") {
        bail!("CompleteMultipartUpload failed: {}", code);
    }
    xml_value(&body, "ETag")
        .map(|etag| etag.replace("&quot;", "\""))
        .ok_or_else(|| anyhow!("CompleteMultipartUpload: no ETag"))
}

pub fn abort_multipart_upload(
    client: &Client,
    target: &Target,
    key: &str,
    upload_id: &str,
) -> ResultType<()> {
    let resp = target.send(
        client,
        "DELETE",
        key,
        &[("uploadId", upload_id)],
        &[],
        vec![],
    )?;
    check(resp, "AbortMultipartUpload")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_plain_http_except_loopback() {
        assert!(Target::new("http://s3.example.com", "r", "b", "a", "s", true).is_err());
        assert!(Target::new("http://127.0.0.1:9000", "r", "b", "a", "s", true).is_ok());
        assert!(Target::new("https://s3.example.com", "r", "b", "a", "s", false).is_ok());
    }

    #[test]
    fn builds_path_and_virtual_host_addresses() {
        let t = Target::new("https://s3.example.com:8443", "r", "bkt", "a", "s", true).unwrap();
        assert_eq!(
            (t.host(), t.path("k/x")),
            ("s3.example.com:8443".into(), "/bkt/k/x".into())
        );
        let t = Target::new("https://s3.example.com", "r", "bkt", "a", "s", false).unwrap();
        assert_eq!(
            (t.host(), t.path("k/x")),
            ("bkt.s3.example.com".into(), "/k/x".into())
        );
    }

    fn env_target() -> Option<Target> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Target::new(
            &var("RD_S3_ENDPOINT")?,
            &var("RD_S3_REGION")?,
            &var("RD_S3_BUCKET")?,
            &var("RD_S3_ACCESS_KEY_ID")?,
            &var("RD_S3_SECRET_ACCESS_KEY")?,
            true,
        )
        .ok()
    }

    /// Needs a real bucket: `cargo test -- --ignored` with the `RD_S3_*`
    /// variables set.
    #[test]
    #[ignore]
    fn uploads_to_real_bucket() {
        let Some(target) = env_target() else {
            eprintln!("RD_S3_* not set, skipping");
            return;
        };
        let client = Client::new();
        let stamp = chrono::Utc::now().format("%Y%m%d%H%M%S%3f").to_string();
        let key = format!("it/{}-small.bin", stamp);
        let headers = [("x-amz-meta-test", "small"), ("if-none-match", "*")];
        let body = b"recording upload test".to_vec();
        let etag = put_object(&client, &target, &key, &headers, body.clone()).unwrap();
        assert!(etag.is_some_and(|e| !e.is_empty()));
        assert_eq!(
            put_object(&client, &target, &key, &headers, body).unwrap(),
            None
        );

        let key = format!("it/{}-multipart.bin", stamp);
        let id = create_multipart_upload(&client, &target, &key, &[]).unwrap();
        let part = vec![b'x'; 5 * 1024 * 1024];
        let e1 = upload_part(&client, &target, &key, &id, 1, part).unwrap();
        let e2 = upload_part(&client, &target, &key, &id, 2, b"tail".to_vec()).unwrap();
        let etag =
            complete_multipart_upload(&client, &target, &key, &id, &[(1, e1), (2, e2)]).unwrap();
        assert!(!etag.is_empty());
    }
}
