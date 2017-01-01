extern crate pam_sm;

use pam_sm::pam::{PamServiceModule, Pam, PamFlag, PamReturnCode, size_t};
use std::error::Error;
use std::ffi::CStr;
use std::process::{Command, Stdio};
use std::io::Write;

struct SM;

fn add_key(token: &CStr) -> Result<(), Box<Error>> {
    let mut process = try!(Command::new("/usr/bin/e4crypt").stdin(Stdio::piped()).arg("add_key").arg("-q").spawn());
    let result = match process.stdin {
        Some(ref mut stdin) => stdin.write_all(token.to_bytes()).and_then(|_| stdin.flush()).map_err(|e| From::from(e)),
        None => Err(From::from("failed to write to e4crypt stdin")),
    };
    try!(process.wait());
    result
}

impl PamServiceModule for SM {
    fn authenticate(self: &Self, pamh: Pam, _: PamFlag,
                        _: size_t, _: *const *const u8) -> PamReturnCode {
        println!("Getting auth token");
        match pamh.get_authtok() {
            Err(e) => {
                println!("Error getting password : {}", e);
                PamReturnCode::SERVICE_ERR
            }
            Ok(None) => {
                println!("No auth token available");
                PamReturnCode::CRED_UNAVAIL
            }
            Ok(Some(token)) => {
                println!("Got token !");
                if let Err(e) = add_key(token) {
                    println!("Error adding key : {}", e);
                    PamReturnCode::SYSTEM_ERR
                } else {
                    PamReturnCode::IGNORE
                }
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn get_pam_sm() -> Box<PamServiceModule> {
    return Box::new(SM {});
}
