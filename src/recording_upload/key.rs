/// Fields recovered from a recording file name produced by
/// `scrap::record::RecorderContext2::set_filename`:
/// `{incoming|outgoing}_{id}_{%Y%m%d%H%M%S%3f}_{display|camera}{idx}_{codec}.{ext}`.
/// The peer id may itself contain `_` (sanitized `:`), so the name is split
/// from the right.
#[derive(Debug, PartialEq)]
pub struct RecordingName<'a> {
    pub direction: &'a str,
    pub peer_id: &'a str,
    pub timestamp: &'a str,
}

pub fn parse_filename(name: &str) -> Option<RecordingName<'_>> {
    let mut parts = name.rsplitn(4, '_');
    let _codec = parts.next()?;
    let source = parts.next()?;
    let timestamp = parts.next()?;
    let head = parts.next()?;
    if !(source.starts_with("display") || source.starts_with("camera")) {
        return None;
    }
    if timestamp.len() != 17 || !timestamp.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (direction, peer_id) = head.split_once('_')?;
    if !matches!(direction, "incoming" | "outgoing") || peer_id.is_empty() {
        return None;
    }
    Some(RecordingName {
        direction,
        peer_id,
        timestamp,
    })
}

/// Builds the object key as `prefix + filename`. The prefix template accepts
/// `{local_id}`, `{remote_id}`, `{direction}`, `{yyyy}`, `{mm}` and `{dd}`;
/// the date is the recording start time from the file name, so a retry after
/// a restart maps to the same key.
pub fn object_key(template: &str, local_id: &str, filename: &str) -> Option<String> {
    let name = parse_filename(filename)?;
    let prefix = template
        .replace("{local_id}", local_id)
        .replace("{remote_id}", name.peer_id)
        .replace("{direction}", name.direction)
        .replace("{yyyy}", &name.timestamp[0..4])
        .replace("{mm}", &name.timestamp[4..6])
        .replace("{dd}", &name.timestamp[6..8]);
    Some(format!("{}{}", prefix.trim_start_matches('/'), filename))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_peer_id_containing_underscores() {
        assert_eq!(
            parse_filename("outgoing_192.168.1.2_21118_20261119103015123_display0_vp9.webm"),
            Some(RecordingName {
                direction: "outgoing",
                peer_id: "192.168.1.2_21118",
                timestamp: "20261119103015123",
            })
        );
        assert_eq!(parse_filename("notes.txt"), None);
        assert_eq!(
            parse_filename("outgoing_123_2026111910301512_display0_vp9.webm"),
            None
        );
    }

    #[test]
    fn expands_prefix_template() {
        let file = "outgoing_987654321_20261119103015123_camera1_h264.mp4";
        assert_eq!(
            object_key("/{local_id}/{yyyy}/{mm}/{dd}/{direction}-{remote_id}/", "123456789", file)
                .as_deref(),
            Some("123456789/2026/11/19/outgoing-987654321/outgoing_987654321_20261119103015123_camera1_h264.mp4")
        );
        assert_eq!(object_key("", "1", file).as_deref(), Some(file));
        assert_eq!(object_key("{local_id}/", "1", "random.webm"), None);
    }
}
