mod key;
mod s3;
mod sigv4;

use base::config::keys;
use hbb_common::{
    anyhow::anyhow,
    config::{Config, LocalConfig},
    lazy_static, log, ResultType,
};
use reqwest::blocking::Client;
use scrap::record::RecordState;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
        Mutex,
    },
    time::{Duration, SystemTime},
};

const SINGLE_PUT_MAX: u64 = 64 * 1024 * 1024;
const PART_SIZE: u64 = 16 * 1024 * 1024;
const MARKER_SUFFIX: &str = ".uploaded";
const RETRY_MIN: Duration = Duration::from_secs(30);
const RETRY_MAX: Duration = Duration::from_secs(30 * 60);
// A recorder creates its file just before it reports `NewFile`; skipping
// freshly written files keeps a scan in that gap from uploading it half done.
const MIN_FILE_AGE: Duration = Duration::from_secs(30);

lazy_static::lazy_static! {
    static ref ACTIVE: Mutex<HashSet<PathBuf>> = Default::default();
    static ref WORKER: Mutex<Option<Sender<()>>> = Default::default();
}

/// Returns the channel a `Recorder` reports to, or `None` when recording
/// upload is off.
pub fn sender() -> Option<Sender<RecordState>> {
    if !LocalConfig::get_bool_option(keys::OPTION_ALLOW_RECORDING_UPLOAD) {
        return None;
    }
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || track_recorder(rx));
    Some(tx)
}

fn track_recorder(rx: Receiver<RecordState>) {
    // Also retries whatever an earlier run left pending.
    notify_worker();
    let mut current: Option<PathBuf> = None;
    for state in rx {
        match state {
            RecordState::NewFile(path) => {
                let path = PathBuf::from(path);
                let mut active = ACTIVE.lock().unwrap();
                if let Some(old) = current.take() {
                    active.remove(&old);
                }
                active.insert(path.clone());
                current = Some(path);
            }
            RecordState::WriteTail | RecordState::RemoveFile => {
                if let Some(path) = current.take() {
                    ACTIVE.lock().unwrap().remove(&path);
                }
                notify_worker();
            }
            RecordState::NewFrame => {}
        }
    }
    if let Some(path) = current.take() {
        ACTIVE.lock().unwrap().remove(&path);
        notify_worker();
    }
}

fn notify_worker() {
    let mut worker = WORKER.lock().unwrap();
    if let Some(tx) = worker.as_ref() {
        if tx.send(()).is_ok() {
            return;
        }
    }
    let (tx, rx) = mpsc::channel();
    // Cannot fail: `rx` is alive until the worker thread owns it.
    tx.send(()).ok();
    std::thread::spawn(move || run_worker(rx));
    *worker = Some(tx);
}

fn run_worker(rx: Receiver<()>) {
    let mut retry: Option<Duration> = None;
    loop {
        let woke = match retry {
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(delay) => rx.recv_timeout(delay),
        };
        let backoff = match woke {
            Ok(()) => RETRY_MIN,
            Err(RecvTimeoutError::Timeout) => retry.map_or(RETRY_MIN, |d| (d * 2).min(RETRY_MAX)),
            Err(RecvTimeoutError::Disconnected) => return,
        };
        while rx.try_recv().is_ok() {}
        retry = if upload_pending() {
            None
        } else {
            Some(backoff)
        };
    }
}

fn option_is_yes(key: &str) -> bool {
    LocalConfig::get_option(key) == "Y"
}

/// Returns false when some file failed or was deferred and needs another pass.
fn upload_pending() -> bool {
    if !LocalConfig::get_bool_option(keys::OPTION_ALLOW_RECORDING_UPLOAD) {
        return true;
    }
    let target = match s3::Target::new(
        &LocalConfig::get_option(keys::OPTION_RECORDING_UPLOAD_ENDPOINT),
        &LocalConfig::get_option(keys::OPTION_RECORDING_UPLOAD_REGION),
        &LocalConfig::get_option(keys::OPTION_RECORDING_UPLOAD_BUCKET),
        &LocalConfig::get_option(keys::OPTION_RECORDING_UPLOAD_ACCESS_KEY),
        &LocalConfig::get_option(keys::OPTION_RECORDING_UPLOAD_SECRET_KEY),
        option_is_yes(keys::OPTION_RECORDING_UPLOAD_PATH_STYLE),
    ) {
        Ok(target) => target,
        Err(e) => {
            log::error!("recording upload misconfigured: {}", e);
            return true;
        }
    };
    let client = if target.endpoint.scheme() == "https" {
        match crate::hbbs_http::create_http_client_with_url_strict(target.endpoint.as_str()) {
            Ok(client) => client,
            Err(e) => {
                log::error!("recording upload misconfigured: {}", e);
                return true;
            }
        }
    } else {
        Client::new()
    };
    let dir = PathBuf::from(crate::ui_interface::video_save_directory(false));
    let active = ACTIVE.lock().unwrap().clone();
    let (files, deferred) = match pending_files(&dir, &active, SystemTime::now()) {
        Ok(found) => found,
        Err(e) => {
            log::warn!("recording upload: cannot read {}: {}", dir.display(), e);
            return false;
        }
    };
    let prefix = LocalConfig::get_option(keys::OPTION_RECORDING_UPLOAD_PREFIX);
    let local_id = Config::get_id();
    let delete_local = option_is_yes(keys::OPTION_RECORDING_UPLOAD_DELETE_LOCAL);
    let mut all_ok = !deferred;
    for path in files {
        if let Err(e) = upload_file(&client, &target, &prefix, &local_id, &path, delete_local) {
            log::warn!("recording upload failed: {}: {}", path.display(), e);
            all_ok = false;
        }
    }
    all_ok
}

fn marker_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(MARKER_SUFFIX);
    PathBuf::from(name)
}

/// Returns the files to upload now and whether a recently written one was
/// deferred to a later pass.
fn pending_files(
    dir: &Path,
    active: &HashSet<PathBuf>,
    now: SystemTime,
) -> io::Result<(Vec<PathBuf>, bool)> {
    let mut files = Vec::new();
    let mut deferred = false;
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !(name.ends_with(".webm") || name.ends_with(".mp4")) {
            continue;
        }
        if key::parse_filename(name).map_or(true, |n| n.direction != "outgoing") {
            continue;
        }
        if active.contains(&path) || marker_path(&path).exists() {
            continue;
        }
        let modified = std::fs::metadata(&path)?.modified()?;
        if now.duration_since(modified).unwrap_or_default() < MIN_FILE_AGE {
            deferred = true;
            continue;
        }
        files.push(path);
    }
    files.sort();
    Ok((files, deferred))
}

fn file_sha256(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn upload_file(
    client: &Client,
    target: &s3::Target,
    prefix: &str,
    local_id: &str,
    path: &Path,
    delete_local: bool,
) -> ResultType<()> {
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("invalid file name"))?;
    let name = key::parse_filename(filename).ok_or_else(|| anyhow!("not a recording"))?;
    let key = key::object_key(prefix, local_id, filename)
        .ok_or_else(|| anyhow!("cannot build object key"))?;
    let size = std::fs::metadata(path)?.len();
    // Hash the bytes actually sent, so the recorded digest always matches the object.
    let body = if size <= SINGLE_PUT_MAX {
        Some(std::fs::read(path)?)
    } else {
        None
    };
    let sha256 = match &body {
        Some(body) => sigv4::sha256_hex(body),
        None => file_sha256(path)?,
    };
    let meta = [
        ("x-amz-meta-sha256", sha256.as_str()),
        ("x-amz-meta-direction", name.direction),
        ("x-amz-meta-remote-id", name.peer_id),
        ("x-amz-meta-local-id", local_id),
        ("x-amz-meta-client-version", crate::VERSION),
    ];
    let etag = match body {
        Some(body) => {
            let mut headers = meta.to_vec();
            headers.push(("if-none-match", "*"));
            // A failed precondition means an earlier attempt stored this key but
            // its marker was not written.
            s3::put_object(client, target, &key, &headers, body)?
                .unwrap_or_else(|| "existing".to_owned())
        }
        None => upload_multipart(client, target, &key, &meta, path)?,
    };
    if delete_local {
        std::fs::remove_file(path)?;
    } else {
        std::fs::write(
            marker_path(path),
            format!("key={}\nsha256={}\netag={}\n", key, sha256, etag),
        )?;
    }
    log::info!(
        "recording uploaded: {} ({} bytes, sha256 {}) to {}/{}",
        filename,
        size,
        sha256,
        target.bucket,
        key
    );
    Ok(())
}

fn upload_multipart(
    client: &Client,
    target: &s3::Target,
    key: &str,
    meta: &[(&str, &str)],
    path: &Path,
) -> ResultType<String> {
    let upload_id = s3::create_multipart_upload(client, target, key, meta)?;
    let res = upload_parts(client, target, key, &upload_id, path);
    if res.is_err() {
        if let Err(e) = s3::abort_multipart_upload(client, target, key, &upload_id) {
            log::warn!("recording upload: abort failed for {}: {}", key, e);
        }
    }
    res
}

fn upload_parts(
    client: &Client,
    target: &s3::Target,
    key: &str,
    upload_id: &str,
    path: &Path,
) -> ResultType<String> {
    let mut file = File::open(path)?;
    let mut parts = Vec::new();
    for part_number in 1u32.. {
        let mut buf = Vec::with_capacity(PART_SIZE as usize);
        (&mut file).take(PART_SIZE).read_to_end(&mut buf)?;
        if buf.is_empty() {
            break;
        }
        let etag = s3::upload_part(client, target, key, upload_id, part_number, buf)?;
        parts.push((part_number, etag));
    }
    s3::complete_multipart_upload(client, target, key, upload_id, &parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_only_finished_outgoing_recordings() {
        let dir =
            std::env::temp_dir().join(format!("rustdesk-recording-upload-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ts = "20261119103015123";
        let old = SystemTime::now() - Duration::from_secs(3600);
        let touch = |name: &str, modified: SystemTime| {
            let path = dir.join(name);
            File::create(&path).unwrap().set_modified(modified).unwrap();
            path
        };
        let pending = touch(&format!("outgoing_111_{ts}_display0_vp9.webm"), old);
        touch(&format!("outgoing_222_{ts}_display0_vp9.webm"), old);
        touch(
            &format!("outgoing_222_{ts}_display0_vp9.webm.uploaded"),
            old,
        );
        let active = touch(&format!("outgoing_333_{ts}_display1_vp9.webm"), old);
        touch(
            &format!("outgoing_444_{ts}_display0_vp9.webm"),
            SystemTime::now(),
        );
        touch(&format!("incoming_555_{ts}_display0_vp9.webm"), old);
        touch("notes.txt", old);

        let found = pending_files(&dir, &HashSet::from([active]), SystemTime::now()).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(found, (vec![pending], true));
    }
}
