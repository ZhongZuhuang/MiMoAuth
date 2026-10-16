//! Manual experiment: replicate fprintd-verify's call sequence.
//! Run: cargo run -p mimoauth-common --example fp_test -- [sleep_ms]
use mimoauth_common::dbus::{FprintDeviceProxyBlocking, FprintManagerProxyBlocking};

fn main() {
    let sleep_ms: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let conn = zbus::blocking::Connection::system().expect("system bus");
    let mgr = FprintManagerProxyBlocking::new(&conn).expect("manager");
    let path = mgr.get_default_device().expect("get_default_device");
    println!("device = {path}");
    assert!(path.as_str() != "/", "no device");

    let dev = FprintDeviceProxyBlocking::builder(&conn)
        .path(path.as_str())
        .expect("path")
        .build()
        .expect("proxy");

    let user = std::env::var("USER").expect("USER");
    println!("user = {user}");

    match dev.claim(&user) {
        Ok(()) => println!("Claim: ok"),
        Err(e) => {
            println!("Claim: ERR {e}");
            return;
        }
    }

    match dev.list_enrolled_fingers(&user) {
        Ok(f) => println!("ListEnrolledFingers: {f:?}"),
        Err(e) => println!("ListEnrolledFingers: ERR {e}"),
    }

    if sleep_ms > 0 {
        println!("sleeping {sleep_ms}ms …");
        std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
    }

    // fprintd >= 1.90: VerifyStart takes a FINGER name, not a username.
    // "unknown" means "any enrolled finger" (what fprintd-verify passes).
    let finger = std::env::args().nth(2).unwrap_or_else(|| "unknown".into());
    match dev.verify_start(&finger) {
        Ok(()) => println!("VerifyStart({finger}): ok (waiting for finger)"),
        Err(e) => println!("VerifyStart({finger}): ERR {e}"),
    }

    let _ = dev.verify_stop();
    let _ = dev.release();
    println!("done");
}
