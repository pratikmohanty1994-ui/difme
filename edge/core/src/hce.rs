//! Simulated NFC: the APDU responder behind Android Host Card Emulation. On a device, the Kotlin
//! `DifmeHceService` (a `HostApduService`) hands each command APDU to this function through the edge plugin and
//! returns the response; on desktop and in tests it is called directly ("simulated NFC", owner decision 2026-11-17).
//!
//! Commands (ISO 7816-4):
//! * `SELECT` by AID `F0 44 49 46 4D 45 01` ("DIFME" proprietary, version 1) → `90 00`
//! * `GET DATA` `80 CA 00 01 00` after a select → the last signed payment intent (COSE_Sign1) + `90 00`
//! * anything else → `6D 00` (instruction not supported), `6A 82` (unknown AID), `69 85` (no selection / no intent)

pub const AID: &[u8] = &[0xF0, 0x44, 0x49, 0x46, 0x4D, 0x45, 0x01];
pub const SW_OK: [u8; 2] = [0x90, 0x00];
pub const SW_FILE_NOT_FOUND: [u8; 2] = [0x6A, 0x82];
pub const SW_CONDITIONS: [u8; 2] = [0x69, 0x85];
pub const SW_INS_NOT_SUPPORTED: [u8; 2] = [0x6D, 0x00];
pub const SW_WRONG_LENGTH: [u8; 2] = [0x67, 0x00];

#[derive(Default)]
pub struct HceSession {
    selected: bool,
}

impl HceSession {
    /// Processes one command APDU. `signed_intent` is the payment the user armed for a tap.
    pub fn process(&mut self, apdu: &[u8], signed_intent: Option<&[u8]>) -> Vec<u8> {
        if apdu.len() < 4 {
            return SW_WRONG_LENGTH.to_vec();
        }
        match (apdu[0], apdu[1], apdu[2], apdu[3]) {
            (0x00, 0xA4, 0x04, 0x00) => {
                let lc = apdu.get(4).copied().unwrap_or(0) as usize;
                let Some(aid) = apdu.get(5..5 + lc) else { return SW_WRONG_LENGTH.to_vec() };
                self.selected = aid == AID;
                if self.selected { SW_OK.to_vec() } else { SW_FILE_NOT_FOUND.to_vec() }
            }
            (0x80, 0xCA, 0x00, 0x01) => match (self.selected, signed_intent) {
                (true, Some(intent)) => [intent, &SW_OK].concat(),
                _ => SW_CONDITIONS.to_vec(),
            },
            _ => SW_INS_NOT_SUPPORTED.to_vec(),
        }
    }

    /// The reader moved away (`HostApduService.onDeactivated`).
    pub fn deactivate(&mut self) {
        self.selected = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn select(aid: &[u8]) -> Vec<u8> {
        [&[0x00, 0xA4, 0x04, 0x00, aid.len() as u8][..], aid, &[0x00]].concat()
    }

    #[test]
    fn select_then_get_intent() {
        let mut s = HceSession::default();
        let get = [0x80, 0xCA, 0x00, 0x01, 0x00];
        assert_eq!(s.process(&get, Some(b"cose")), SW_CONDITIONS, "nothing selected yet");
        assert_eq!(s.process(&select(&[0xA0, 0, 0, 0, 3]), None), SW_FILE_NOT_FOUND);
        assert_eq!(s.process(&select(AID), None), SW_OK);
        assert_eq!(s.process(&get, None), SW_CONDITIONS, "no armed intent");
        assert_eq!(s.process(&get, Some(b"cose")), b"cose\x90\x00");
        assert_eq!(s.process(&[0x00, 0xB0, 0, 0], None), SW_INS_NOT_SUPPORTED);
        s.deactivate();
        assert_eq!(s.process(&get, Some(b"cose")), SW_CONDITIONS);
        assert_eq!(s.process(&[0x00], None), SW_WRONG_LENGTH);
    }
}
