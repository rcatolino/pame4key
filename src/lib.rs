extern crate pam_sm;

use pam_sm::pam::{PamServiceModule, PamHandle, PamFlag, PamReturnCode, size_t};

struct SM;

impl PamServiceModule for SM {
    fn authenticate(self: &Self, _: PamHandle, _: PamFlag,
                        _: size_t, _: *const *const u8) -> PamReturnCode {
        println!("Trololo !");
        PamReturnCode::SERVICE_ERR
    }
}

#[no_mangle]
pub extern "C" fn get_pam_sm() -> Box<PamServiceModule> {
    return Box::new(SM {});
}
