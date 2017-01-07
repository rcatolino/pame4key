#[macro_use] extern crate nix;
extern crate pam_sm;
extern crate ring;

use pam_sm::pam::{PamServiceModule, Pam, PamFlag, PamReturnCode};
use ring::{digest, pbkdf2};
use std::error::Error;
use std::ffi::CStr;
use std::fmt;
use std::fs::File;
use std::process::{Command, Stdio};
use std::io::Write;
use std::os::unix::io::AsRawFd;

static PBKDF2_ITERATIONS: usize = 0xFFFF;

struct SM;

struct Salt([u8; 16]);

impl Salt {
    fn new() -> Self {
        Salt([0u8; 16])
    }

    fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }
}

impl fmt::Display for Salt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in self.0.iter() {
            try!(write!(f, "{:02X}", b));
        }
        Ok(())
    }
}

struct Ext4Key {
    key: [u8; 64],
    key_ref: [u8; 8],
}

impl Ext4Key {
    fn new(token: &[u8], salt: Salt) -> Ext4Key {
        let mut key = [0u8; 64];
        println!("Using token: {:?}", token);
        println!("Using salt : {}", salt);
        pbkdf2::derive(&pbkdf2::HMAC_SHA512, PBKDF2_ITERATIONS, &salt.0, token, &mut key);
        let digest = digest::digest(&digest::SHA512, digest::digest(&digest::SHA512, &key).as_ref());
        let mut key_ref = [0u8; 8];
        for (src, dst) in digest.as_ref().iter().zip(key_ref.iter_mut()) {
            *dst = *src;
        }
        Ext4Key { key: key, key_ref: key_ref }
    }
}

impl fmt::Display for Ext4Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in self.key.iter() {
            try!(write!(f, "{:02X}", b));
        }
        try!(write!(f, "::"));
        for b in self.key_ref.iter() {
            try!(write!(f, "{:02X}", b));
        }
        Ok(())
    }
}

fn add_key(token: &CStr) -> Result<(), Box<Error>> {
    let mut process = try!(Command::new("/usr/bin/e4crypt").stdin(Stdio::piped()).arg("add_key").arg("-q").spawn());
    let result = match process.stdin {
        Some(ref mut stdin) => stdin.write_all(token.to_bytes()).and_then(|_| stdin.flush()).map_err(|e| From::from(e)),
        None => Err(From::from("failed to write to e4crypt stdin")),
    };
    try!(process.wait());
    result
}

ioctl!(write buf fs_get_pwsalt with b'f', 20 ; u8);

fn get_salt(path: &String) -> Result<Salt, Box<Error>> {
    let f = try!(File::open(path));
    let salt = Salt::new();
    println!("File descriptor of {} : {}", path, f.as_raw_fd());
    try!(unsafe {
        fs_get_pwsalt(f.as_raw_fd(), salt.as_ptr(), 16)
    });
    Ok(salt)
}

impl PamServiceModule for SM {
    fn authenticate(self: &Self, pamh: Pam, _: PamFlag, args: Vec<String>) -> PamReturnCode {
        println!("In pam open_session !");
        println!("Getting auth token");
        println!("Args : {:?}", args);
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
                for arg in args.iter() {
                    match get_salt(arg) {
                        Err(e) => println!("Error getting salt : {}", e),
                        Ok(salt) => {
                            println!("Got salt {}", salt);
                            println!("Got key {}", Ext4Key::new(token.to_bytes(), salt));
                        }
                    }
                }
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

// This is used in some of rings tests and for some reason needs to be defined or pam fails to dlopen
// pam_e4crypt.so
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn RAND_bytes(_: *mut u8, _: *mut u8, _: usize) -> i32 {
    0
}
