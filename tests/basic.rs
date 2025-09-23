use std::fs::File;
use std::io::Write;
use faillog::{is_valid_ip, parse_log_file};

#[test]
fn test_is_valid_ip() {
    assert!(is_valid_ip("192.168.1.1"));
    assert!(is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    assert!(!is_valid_ip("999.999.999.999"));
    assert!(!is_valid_ip("not.an.ip"));
}

#[test]
fn test_parse_log_file() {
    let log_content = "2025-09-22 00:37:57,665 fail2ban.actions [36646]: NOTICE  [sshd] Ban 45.134.26.79\n2025-09-22 00:41:54,286 fail2ban.actions [36927]: NOTICE  [sshd] Ban 103.252.73.219\n";
    let tmpfile = "test_ban_log.txt";
    let mut file = File::create(tmpfile).unwrap();
    file.write_all(log_content.as_bytes()).unwrap();
    let counts = parse_log_file(tmpfile);
    std::fs::remove_file(tmpfile).unwrap();
    assert_eq!(counts.get("45.134.26.79"), Some(&1));
    assert_eq!(counts.get("103.252.73.219"), Some(&1));
}
