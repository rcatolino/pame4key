extern crate keyutils;
#[macro_use] extern crate nix;
extern crate pam_sm;
extern crate ring;

use keyutils::{Keyring, SpecialKeyring};
use pam_sm::pam::{PamServiceModule, Pam, PamFlag, PamReturnCode};
use ring::{digest, pbkdf2};
use std::error::Error;
use std::ffi::CStr;
use std::fmt;
use std::fs::File;
use std::mem::transmute;
use std::process::{Command, Stdio};
use std::io::Write;
use std::os::unix::io::AsRawFd;

const PBKDF2_ITERATIONS: usize = 0xFFFF;
const SALT_SIZE: usize = 16;
const KEY_SIZE: usize = 64;

struct SM;

struct Salt([u8; SALT_SIZE]);

impl Salt {
    ioctl!(write buf fs_get_pwsalt with b'f', 20 ; u8);
    fn new(path: &String) -> Result<Salt, Box<Error>> {
        let f = try!(File::open(path));
        let salt = [0u8; SALT_SIZE];
        println!("File descriptor of {} : {}", path, f.as_raw_fd());
        try!(unsafe {
            Salt::fs_get_pwsalt(f.as_raw_fd(), salt.as_ptr(), SALT_SIZE)
        });
        Ok(Salt(salt))
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

#[allow(dead_code)]
#[derive(Copy, Clone)]
enum Ext4EncryptionMode {
    Invalid=0,
    Aes256Xts=1,
    Aes256Gcm=2,
    Aes256Cbc=3,
    Aes256Cts=4,
}

struct Ext4Key {
    key: [u8; KEY_SIZE],
    mode: Ext4EncryptionMode,
    key_ref: [u8; 8],
}

impl Ext4Key {
    fn new(token: &[u8], salt: Salt) -> Ext4Key {
        let mut key = Ext4Key {
            key: [0u8; KEY_SIZE],
            mode: Ext4EncryptionMode::Aes256Xts,
            key_ref: Default::default()
        };
        println!("Using token: {:?}", token);
        println!("Using salt : {}", salt);
        pbkdf2::derive(&pbkdf2::HMAC_SHA512, PBKDF2_ITERATIONS, &salt.0, token, &mut key.key);
        let digest = digest::digest(&digest::SHA512, &key.key);
        for (src, dst) in digest.as_ref().iter().zip(key.key_ref.iter_mut()) {
            *dst = *src;
        }
        key
    }

    fn key_ref_str(&self) -> Result<String, fmt::Error> {
        use std::fmt::Write;
        let prefix = "ext4:";
        let mut ref_str = String::with_capacity(prefix.len() + self.key_ref.len()*2);
        ref_str.push_str(prefix);
        for b in self.key_ref.iter() {
            try!(write!(ref_str, "{:02x}", b));
        }
        println!("key description str : {}", &ref_str);
        Ok(ref_str)
    }

    fn to_payload(&self) -> Vec<u8> {
        let mut buff = Vec::with_capacity(8+KEY_SIZE); // sizeof(u32 + [u8; KEY_SIZE] + u32)
        buff.extend(unsafe { &transmute::<u32, [u8; 4]>(self.mode as u32) });
        buff.extend(self.key.iter());
        buff.extend(unsafe { &transmute::<u32, [u8; 4]>(KEY_SIZE as u32) });
        buff
    }
}

impl fmt::Display for Ext4Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in self.key.iter() {
            try!(write!(f, "{:02x}", b));
        }
        try!(write!(f, "::"));
        for b in self.key_ref.iter() {
            try!(write!(f, "{:02x}", b));
        }
        Ok(())
    }
}

fn add_key2(key: &Ext4Key) -> Result<(), String> {
    let mut keyring = try!(Keyring::attach(SpecialKeyring::SessionKeyring).map_err(|e| format!("{}", e)));
    key.key_ref_str().map_err(|e| format!("{}", e)).
        and_then(|ref refstr| keyring.add_logon_key(refstr, &key.to_payload()).map_err(|e| format!("{}", e))).
        map(|_| ())
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
                    match Salt::new(arg).
                        map(|salt| Ext4Key::new(token.to_bytes(), salt)).
                        and_then(|key| add_key2(&key).map_err(|e| From::from(e))) {
                        Err(e) => {
                            println!("Error : {}", e);
                            return PamReturnCode::SERVICE_ERR;
                        }
                        Ok(_) => println!("Key added successfuly for directory {}", arg),
                    }
                }
                PamReturnCode::IGNORE
                /*
                if let Err(e) = add_key2(token) {
                    println!("Error adding key : {}", e);
                    PamReturnCode::SYSTEM_ERR
                } else {
                    PamReturnCode::IGNORE
                }
                */
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
    panic!();
}
