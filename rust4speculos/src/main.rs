#![no_std]
#![no_main]

mod crypto_helpers;
mod cx_helpers;
mod data_types;
mod utils;

use core::str::from_utf8;
use crypto_helpers::*;
use data_types::Field;
use nanos_sdk::bindings;
use nanos_sdk::buttons::ButtonEvent;
use nanos_sdk::io;
use nanos_sdk::io::SyscallError;
use nanos_ui::ui;

use hex_literal::hex;

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
        let int1_bytes: [u8; 4] = [message[0], message[1], message[2], message[3]];
        {
            let hex = utils::to_hex(&int1_bytes).map_err(|_| SyscallError::Overflow)?;
            let m = from_utf8(&hex).map_err(|_| SyscallError::InvalidParameter)?;
            ui::popup("Int 1");
            ui::popup(m);
        }

        let int2_bytes: [u8; 4] = [message[4], message[5], message[6], message[7]];
        {
            let hex = utils::to_hex(&int2_bytes).map_err(|_| SyscallError::Overflow)?;
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
        let mod_bytes: [u8; N_BYTES as usize] =
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"); // mod = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        
        let mut field1_bytes = [0_u8; N_BYTES as usize];
        for i in 0..N_BYTES {
            field1_bytes[i as usize] = message[i as usize];
        }

        let mut field2_bytes = [0_u8; N_BYTES as usize];
        for i in 0..N_BYTES {
            field2_bytes[i as usize] = message[i as usize + N_BYTES as usize];
        }

        let field1: Field = Field::new_init(&field1_bytes)?;
        let field2: Field = Field::new_init(&field2_bytes)?;
        let modulo: Field = Field::new_init(&mod_bytes)?;

        let field3 = field1.add(field2, modulo)?;
        Ok(Some(field3.bytes))
    } else {
        ui::popup("Cancelled");
        Ok(None)
    }
}

use crate::cx_helpers::*;
fn add_point(message: &[u8]) -> Result<Option<[u8; 2 * N_BYTES as usize + 1_usize]>, SyscallError> {
    if ui::Validator::new("Add point ?").ask() {
        cx_bn_lock(N_BYTES, 0)?;

        let mut sum_bytes: [u8; 2 * N_BYTES as usize + 1] = [0; 2 * N_BYTES as usize + 1]; // ce qu'on cherche à export

        let mut point1 = cx_ecpoint_alloc(bindings::CX_CURVE_SECP256K1)?;
        let mut point2 = cx_ecpoint_alloc(bindings::CX_CURVE_SECP256K1)?;
        let mut point_sum = cx_ecpoint_alloc(bindings::CX_CURVE_SECP256K1)?;

        cx_ecpoint_init(&mut point1, &message[1..33], &message[33..65])?;
        cx_ecpoint_init(&mut point2, &message[66..98], &message[98..130])?;

        // on fait l'addition des deux points
        cx_ecpoint_add(&mut point_sum, &point1, &point2)?;

        //on export on renvoie en non compressé :

        let mut x_sum_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
        let mut y_sum_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];

        cx_ecpoint_export(&point_sum, &mut x_sum_bytes, &mut y_sum_bytes)?;

        sum_bytes[0] = 4; // on dit qu'on fait non compressé;
        for i in 0..N_BYTES {
            sum_bytes[1 + i as usize] = x_sum_bytes[i as usize];
            sum_bytes[1 + i as usize + N_BYTES as usize] = y_sum_bytes[i as usize];
        }
        cx_bn_unlock()?;
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
    ShowPrivateKey,
    Exit,
}

impl From<u8> for Ins {
    fn from(ins: u8) -> Ins {
        match ins {
            1 => Ins::GetPubkey,
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
