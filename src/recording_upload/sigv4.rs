use hmac::{digest::InvalidLength, Hmac, Mac};
use sha2::{Digest, Sha256};

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

pub struct Credentials<'a> {
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
    pub service: &'a str,
}

/// `path` and `query` are raw (not percent-encoded). `headers` must include
/// `host` and `x-amz-date`; every header listed is signed.
pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a [(&'a str, &'a str)],
    pub headers: &'a [(&'a str, &'a str)],
    pub payload_sha256: &'a str,
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, InvalidLength> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn uri_encode(input: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if keep_slash => out.push('/'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Percent-encodes an object path the same way it is signed, so the URL sent
/// matches the canonical request.
pub fn encode_path(path: &str) -> String {
    uri_encode(path, true)
}

pub fn encode_query(query: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

fn canonical_headers(headers: &[(&str, &str)]) -> (String, String) {
    let mut list: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| {
            (
                k.to_ascii_lowercase(),
                v.split_whitespace().collect::<Vec<_>>().join(" "),
            )
        })
        .collect();
    list.sort();
    let canonical = list
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v))
        .collect::<String>();
    let signed = list
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    (canonical, signed)
}

/// Returns the `Authorization` header value. `amz_date` is the `x-amz-date`
/// value, e.g. `20130524T000000Z`.
pub fn authorization(
    creds: &Credentials,
    req: &Request,
    amz_date: &str,
) -> Result<String, InvalidLength> {
    let date = amz_date.get(..8).unwrap_or(amz_date);
    let (canonical_headers, signed_headers) = canonical_headers(req.headers);
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method,
        encode_path(req.path),
        encode_query(req.query),
        canonical_headers,
        signed_headers,
        req.payload_sha256
    );
    let scope = format!("{}/{}/{}/aws4_request", date, creds.region, creds.service);
    let string_to_sign = format!(
        "{}\n{}\n{}\n{}",
        ALGORITHM,
        amz_date,
        scope,
        sha256_hex(canonical_request.as_bytes())
    );
    let k_date = hmac_sha256(
        format!("AWS4{}", creds.secret_key).as_bytes(),
        date.as_bytes(),
    )?;
    let k_region = hmac_sha256(&k_date, creds.region.as_bytes())?;
    let k_service = hmac_sha256(&k_region, creds.service.as_bytes())?;
    let k_signing = hmac_sha256(&k_service, b"aws4_request")?;
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes())?);
    Ok(format!(
        "{} Credential={}/{}, SignedHeaders={}, Signature={}",
        ALGORITHM, creds.access_key, scope, signed_headers, signature
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // aws-sig-v4-test-suite: get-vanilla
    #[test]
    fn signs_generic_get_vanilla() {
        let creds = Credentials {
            access_key: "AKIDEXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            service: "service",
        };
        let req = Request {
            method: "GET",
            path: "/",
            query: &[],
            headers: &[
                ("Host", "example.amazonaws.com"),
                ("X-Amz-Date", "20150830T123600Z"),
            ],
            payload_sha256: &sha256_hex(b""),
        };
        assert_eq!(
            authorization(&creds, &req, "20150830T123600Z").unwrap(),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    fn s3_creds() -> Credentials<'static> {
        Credentials {
            access_key: "AKIAIOSFODNN7EXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            service: "s3",
        }
    }

    // Amazon S3 API reference, "Signature calculation: Transfer payload in a
    // single chunk", PUT Object example.
    #[test]
    fn signs_s3_put_object() {
        let body = b"Welcome to Amazon S3.";
        let hash = sha256_hex(body);
        assert_eq!(
            hash,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        let req = Request {
            method: "PUT",
            path: "/test$file.text",
            query: &[],
            headers: &[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("Date", "Fri, 24 May 2013 00:00:00 GMT"),
                ("x-amz-date", "20130524T000000Z"),
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
                ("x-amz-content-sha256", &hash),
            ],
            payload_sha256: &hash,
        };
        assert_eq!(
            authorization(&s3_creds(), &req, "20130524T000000Z").unwrap(),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, \
             Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    // Same reference, GET Object example (range request).
    #[test]
    fn signs_s3_get_object() {
        let hash = sha256_hex(b"");
        let req = Request {
            method: "GET",
            path: "/test.txt",
            query: &[],
            headers: &[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("Range", "bytes=0-9"),
                ("x-amz-content-sha256", &hash),
                ("x-amz-date", "20130524T000000Z"),
            ],
            payload_sha256: &hash,
        };
        assert_eq!(
            authorization(&s3_creds(), &req, "20130524T000000Z").unwrap(),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn query_is_sorted_and_encoded() {
        assert_eq!(
            encode_query(&[("uploadId", "a/b+c"), ("partNumber", "2")]),
            "partNumber=2&uploadId=a%2Fb%2Bc"
        );
        assert_eq!(encode_query(&[("uploads", "")]), "uploads=");
    }
}
