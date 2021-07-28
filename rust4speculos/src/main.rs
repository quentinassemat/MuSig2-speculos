#![no_std]
#![no_main]

mod crypto_helpers;
mod utils;
mod data_types;

use core::str::from_utf8;
use crypto_helpers::*;
use data_types::*;
use nanos_sdk::bindings;
use nanos_sdk::buttons::ButtonEvent;
use nanos_sdk::io;
use nanos_sdk::io::SyscallError;
use nanos_ui::ui;

pub const N_BYTES: u32 = 32;

nanos_sdk::set_panic!(nanos_sdk::exiting_panic);

/// Display public key in two separate
/// message scrollers
fn show_pubkey() {
    let pubkey = get_pubkey();
    match pubkey {
        Ok(pk) => {
            {
                let hex0 = utils::to_hex(&pk.W[1..33]).unwrap();
                let m = from_utf8(&hex0).unwrap();
                ui::MessageScroller::new(m).event_loop();
            }
            {
                let hex1 = utils::to_hex(&pk.W[33..65]).unwrap();
                let m = from_utf8(&hex1).unwrap();
                ui::MessageScroller::new(m).event_loop();
            }
        }
        Err(_) => ui::popup("Error"),
    }
}

/// Basic nested menu. Will be subject
/// to simplifications in the future.
#[allow(clippy::needless_borrow)]
fn menu_example() {
    loop {
        match ui::Menu::new(&[&"PubKey", &"Infos", &"Back", &"Exit App"]).show() {
            0 => show_pubkey(),
            1 => loop {
                match ui::Menu::new(&[&"Copyright", &"Authors", &"Back"]).show() {
                    0 => ui::popup("2020 Ledger"),
                    1 => ui::popup("???"),
                    _ => break,
                }
            },
            2 => return,
            3 => nanos_sdk::exit_app(0),
            _ => (),
        }
    }
}

#[no_mangle]
extern "C" fn sample_main() {
    let mut comm = io::Comm::new();
    comm.reply_ok();
    loop {
        // Draw some 'welcome' screen
        ui::SingleMessage::new("Welcome MuSig2").show();
        // Wait for either a specific button push to exit the app
        // or an APDU command

        match comm.next_event() {
            io::Event::Button(ButtonEvent::RightButtonRelease) => nanos_sdk::exit_app(0),
            io::Event::Command(ins) => match handle_apdu(&mut comm, ins) {
                Ok(()) => comm.reply_ok(),
                Err(sw) => {
                    ui::popup("Erreur2");
                    comm.reply(sw);
                }
            },
            _ => (),
        }
    }
}

fn add_int(message: &[u8]) -> Result<Option<[u8; 4]>, SyscallError> {
    if ui::Validator::new("Add int ?").ask() {
        let mut int1_bytes: [u8; 4] = [0; 4];
        int1_bytes[0] = message[0];
        int1_bytes[1] = message[1];
        int1_bytes[2] = message[2];
        int1_bytes[3] = message[3];

        {
            let hex = utils::to_hex(&message[0..4]).map_err(|_| SyscallError::Overflow)?;
            let m = from_utf8(&hex).map_err(|_| SyscallError::InvalidParameter)?;
            ui::popup("Int 1");
            ui::popup(m);
        }

        let mut int2_bytes: [u8; 4] = [0; 4];
        int2_bytes[0] = message[4];
        int2_bytes[1] = message[5];
        int2_bytes[2] = message[6];
        int2_bytes[3] = message[7];

        {
            let hex = utils::to_hex(&message[4..8]).map_err(|_| SyscallError::Overflow)?;
            let m = from_utf8(&hex).map_err(|_| SyscallError::InvalidParameter)?;
            ui::popup("Int 2");
            ui::popup(m);
        }

        Ok(Some(
            (u32::from_be_bytes(int1_bytes) + u32::from_be_bytes(int2_bytes)).to_be_bytes(),
        ))
    } else {
        ui::popup("Cancelled");
        Ok(None)
    }
}

fn add_field(message: &[u8]) -> Result<Option<[u8; N_BYTES as usize]>, SyscallError> {
    // on essaye d'optimiser la place sur la stack avec les {}
    if ui::Validator::new("Add field ?").ask() {
        unsafe {
            match bindings::cx_bn_lock(N_BYTES, 0) {
                bindings::CX_OK => (),
                bindings::CX_LOCKED => return Err(SyscallError::InvalidState),
                _ => return Err(SyscallError::Unspecified),
            }
        }
        // déclaration
        let mut mod_bytes: [u8; N_BYTES as usize] = hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"); // mod = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        let mod_bytes_ptr: *mut u8 = mod_bytes.as_mut_ptr();

        let mut field1_bytes = [0_u8; N_BYTES as usize];
        let field1_bytes_ptr = field1_bytes.as_mut_ptr();

        let mut field2_bytes = [0_u8; N_BYTES as usize];
        let field2_bytes_ptr = field2_bytes.as_mut_ptr();

        let field1: Field = Field::new_init(field1_bytes_ptr)?;
        let field2: Field = Field::new_init(field2_bytes_ptr)?;
        let modulo: Field = Field::new_init(mod_bytes_ptr)?;

        let field3 = field1.add(field2, modulo)?;
        Ok(Some(field3.bytes))
    } else {
        ui::popup("Cancelled");
        Ok(None)
    }
}

fn add_point(message: &[u8]) -> Result<Option<[u8; 2 * N_BYTES as usize + 1_usize]>, SyscallError> {
    if ui::Validator::new("Add point ?").ask() {
        unsafe {
            match bindings::cx_bn_lock(N_BYTES, 0) {
                bindings::CX_OK => (),
                bindings::CX_LOCKED => return Err(SyscallError::InvalidState),
                _ => return Err(SyscallError::Unspecified),
            }
        }

        let mut sum_bytes: [u8; 2 * N_BYTES as usize + 1] = [0; 2 * N_BYTES as usize + 1]; // ce qu'on cherche à export

        unsafe {
            let mut point1 = bindings::cx_ecpoint_t::default();
            match bindings::cx_ecpoint_alloc(&mut point1, bindings::CX_CURVE_SECP256K1) {
                bindings::CX_OK => (),
                bindings::CX_EC_INVALID_CURVE => return Err(SyscallError::InvalidParameter),
                bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
                bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
                bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
                _ => return Err(SyscallError::Unspecified),
            }

            let mut point2 = bindings::cx_ecpoint_t::default();
            match bindings::cx_ecpoint_alloc(&mut point2, bindings::CX_CURVE_SECP256K1) {
                bindings::CX_OK => (),
                bindings::CX_EC_INVALID_CURVE => return Err(SyscallError::InvalidParameter),
                bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
                bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
                bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
                _ => return Err(SyscallError::Unspecified),
            }

            let mut point_sum = bindings::cx_ecpoint_t::default();
            match bindings::cx_ecpoint_alloc(&mut point_sum, bindings::CX_CURVE_SECP256K1) {
                bindings::CX_OK => (),
                bindings::CX_EC_INVALID_CURVE => return Err(SyscallError::InvalidParameter),
                bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
                bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
                bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
                _ => return Err(SyscallError::Unspecified),
            }

            let mut x_point1_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
            for i in 0..N_BYTES {
                x_point1_bytes[i as usize] = message[1 + i as usize];
            }

            let mut y_point1_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
            for i in 0..N_BYTES {
                y_point1_bytes[i as usize] = message[1 + N_BYTES as usize + i as usize];
            }

            let point1_ptr: *mut bindings::cx_ecpoint_t = &mut point1;
            bindings::cx_ecpoint_init(
                point1_ptr,
                x_point1_bytes.as_ptr(),
                N_BYTES,
                y_point1_bytes.as_ptr(),
                N_BYTES,
            );

            let mut x_point2_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
            for i in 0..N_BYTES {
                x_point2_bytes[i as usize] = message[2 + i as usize + 2 * N_BYTES as usize];
            }

            let mut y_point2_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
            for i in 0..N_BYTES {
                y_point2_bytes[i as usize] = message[2 + 3 * N_BYTES as usize + i as usize];
            }

            let point2_ptr: *mut bindings::cx_ecpoint_t = &mut point2;
            bindings::cx_ecpoint_init(
                point2_ptr,
                x_point2_bytes.as_ptr(),
                N_BYTES,
                y_point2_bytes.as_ptr(),
                N_BYTES,
            );

            let point_sum_ptr: *mut bindings::cx_ecpoint_t = &mut point_sum;
            let point1_ptr_copy = point1_ptr;
            let point2_ptr_copy = point2_ptr;

            // on fait l'addition des deux points

            match bindings::cx_ecpoint_add(point_sum_ptr, point1_ptr_copy, point2_ptr_copy) {
                bindings::CX_OK => (),
                bindings::CX_EC_INVALID_CURVE => return Err(SyscallError::InvalidParameter),
                bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
                bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
                bindings::CX_EC_INVALID_POINT => return Err(SyscallError::InvalidParameter),
                bindings::CX_EC_INFINITE_POINT => return Err(SyscallError::InvalidParameter),
                bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
                _ => return Err(SyscallError::Unspecified),
            }

            //on export on renvoie en non compressé :

            let mut x_sum_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
            let mut y_sum_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];

            match bindings::cx_ecpoint_export(
                point_sum_ptr,
                x_sum_bytes.as_mut_ptr(),
                N_BYTES,
                y_sum_bytes.as_mut_ptr(),
                N_BYTES,
            ) {
                bindings::CX_OK => (),
                bindings::CX_INVALID_PARAMETER_VALUE => return Err(SyscallError::InvalidParameter),
                bindings::CX_INVALID_PARAMETER_SIZE => return Err(SyscallError::InvalidParameter),
                bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
                bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
                _ => return Err(SyscallError::Unspecified),
            }

            sum_bytes[0] = 4; // on dit qu'on fait non compressé;
            for i in 0..N_BYTES {
                sum_bytes[1 + i as usize] = x_sum_bytes[i as usize];
                sum_bytes[1 + i as usize + N_BYTES as usize] = y_sum_bytes[i as usize];
            }
        }
        unsafe {
            match bindings::cx_bn_unlock() {
                bindings::CX_OK => (),
                bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
                _ => return Err(SyscallError::Unspecified),
            }
        }
        Ok(Some(sum_bytes))
    } else {
        ui::popup("Cancelled");
        Ok(None)
    }
}

#[repr(u8)]
enum Ins {
    GetPubkey,
    RecInt,
    RecField,
    RecPoint,
    Menu,
    ShowPrivateKey,
    Exit,
}

impl From<u8> for Ins {
    fn from(ins: u8) -> Ins {
        match ins {
            1 => Ins::GetPubkey,
            2 => Ins::Menu,
            3 => Ins::RecInt,
            4 => Ins::RecField,
            5 => Ins::RecPoint,
            0xfe => Ins::ShowPrivateKey,
            0xff => Ins::Exit,
            _ => panic!(),
        }
    }
}

use nanos_sdk::io::Reply;

fn handle_apdu(comm: &mut io::Comm, ins: Ins) -> Result<(), Reply> {
    if comm.rx == 0 {
        return Err(io::StatusWords::NothingReceived.into());
    }

    match ins {
        Ins::GetPubkey => comm.append(&get_pubkey()?.W),
        Ins::Menu => menu_example(),
        Ins::ShowPrivateKey => comm.append(&bip32_derive_secp256k1(&BIP32_PATH)?),
        Ins::Exit => nanos_sdk::exit_app(0),
        Ins::RecInt => {
            let out = add_int(comm.get_data()?)?;
            if let Some(o) = out {
                comm.append(&o)
            }
        }
        Ins::RecField => {
            let out = add_field(comm.get_data()?)?;
            if let Some(o) = out {
                comm.append(&o)
            }
        }
        Ins::RecPoint => {
            let out = add_point(comm.get_data()?)?;
            if let Some(o) = out {
                comm.append(&o)
            }
        }
    }
    Ok(())
}
