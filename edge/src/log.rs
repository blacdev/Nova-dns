//! One line per event on standard output, with the time (docker logs keeps them). Never a
//! token or a key.

pub fn say(what: &str) {
    println!("[nova-edge] {} {what}", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"));
}
