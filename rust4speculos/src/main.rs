#![no_std]
#![no_main]
#![cfg_attr(test, main)]
#![feature(custom_test_frameworks)]
#![reexport_test_harness_main = "test_main"]
#![test_runner(nanos_sdk::sdk_test_runner)]

mod crypto_helpers;
mod cx_helpers;
mod data_types;
mod utils;

use crypto_helpers::*;
use data_types::*;

use nanos_sdk::exit_app;
use nanos_sdk::io;
use nanos_sdk::io::Reply;
use nanos_sdk::TestType;
use nanos_ui::ui;

use core::str::from_utf8;

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
#[cfg(not(test))]
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

fn add_int(message: &[u8]) -> Result<Option<[u8; 4]>, CxSyscallError> {
    if ui::Validator::new("Add int ?").ask() {
        let int1_bytes: [u8; 4] = [message[0], message[1], message[2], message[3]];
        {
            let hex = utils::to_hex(&int1_bytes).map_err(|_| CxSyscallError::Overflow)?;
            let m = from_utf8(&hex).map_err(|_| CxSyscallError::InvalidParameter)?;
            ui::popup("Int 1");
            ui::popup(m);
        }

        let int2_bytes: [u8; 4] = [message[4], message[5], message[6], message[7]];
        {
            let hex = utils::to_hex(&int2_bytes).map_err(|_| CxSyscallError::Overflow)?;
            let m = from_utf8(&hex).map_err(|_| CxSyscallError::InvalidParameter)?;
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

fn add_field(message: &[u8]) -> Result<Option<[u8; N_BYTES as usize]>, CxSyscallError> {
    // on essaye d'optimiser la place sur la stack avec les {}
    if ui::Validator::new("Add field ?").ask() {
        cx_bn_lock(N_BYTES, 0)?;

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
        ui::popup("field 1");
        field1.show()?;
        let field2: Field = Field::new_init(&field2_bytes)?;
        ui::popup("field 2");
        field2.show()?;
        let modulo: Field = Field::new_init(&mod_bytes)?;

        let field3 = field1.add(field2, modulo)?;
        cx_bn_unlock()?;
        Ok(Some(field3.bytes))
    } else {
        ui::popup("Cancelled");
        Ok(None)
    }
}

use crate::cx_helpers::*;
fn add_point(
    message: &[u8],
) -> Result<Option<[u8; 2 * N_BYTES as usize + 1_usize]>, CxSyscallError> {
    if ui::Validator::new("Add point ?").ask() {
        cx_bn_lock(N_BYTES, 0)?;

        let point1 = Point::new_init(&message[1..33], &message[33..65])?;
        ui::popup("point 1");
        point1.show()?;
        let point2 = Point::new_init(&message[66..98], &message[98..130])?;
        ui::popup("point 2");
        point2.show()?;

        // on fait l'addition des deux points
        let point3 = point1.add(point2)?;
        ui::popup("point 3");
        point3.show()?;

        let (x, y) = point3.coords()?;

        let bytes = point3.export_apdu()?;

        cx_bn_unlock()?;
        Ok(Some(bytes))
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

// TESTS

#[macro_export]
macro_rules! assert_eq_err {
    ($left:expr, $right:expr) => {{
        match (&$left, &$right) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    nanos_sdk::debug_print("assertion failed: `(left == right)`\n");
                    return Err(());
                }
            }
        }
    }};
}

#[cfg(test)]
#[no_mangle]
fn sample_main() {
    test_main();
    exit_app(0);
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::assert_eq_err as assert_eq;
    use testmacro::test_item as test;

    use core::str::from_utf8;
    use data_types::Field;
    use nanos_sdk::io::SyscallError;
    use nanos_sdk::TestType;

    use hex_literal::hex;

    #[test]
    fn test_field_add1() {
        cx_bn_lock(N_BYTES, 0).unwrap();
        let mod_bytes: [u8; N_BYTES as usize] =
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"); // mod = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        let modulo: Field = Field::new_init(&mod_bytes).unwrap();

        let field1_bytes: [u8; N_BYTES as usize] =
            hex!("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001");
        let field2_bytes: [u8; N_BYTES as usize] =
            hex!("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001");
        let field1: Field = Field::new_init(&field1_bytes).unwrap();
        let field2: Field = Field::new_init(&field1_bytes).unwrap();
        let field_add = field1.add(field2, modulo).unwrap();
        let field_add_test_bytes: [u8; N_BYTES as usize] =
            hex!("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000002");
        let field_add_test: Field = Field::new_init(&field_add_test_bytes).unwrap();

        assert_eq!(field_add_test.bytes, field_add.bytes);
        cx_bn_unlock().unwrap();
    }

    #[test]
    fn test_field_add2() {
        cx_bn_lock(N_BYTES, 0).unwrap();
        let mod_bytes: [u8; N_BYTES as usize] =
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"); // mod = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        let modulo: Field = Field::new_init(&mod_bytes).unwrap();

        let field1_bytes: [u8; N_BYTES as usize] =
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364142");
        let field2_bytes: [u8; N_BYTES as usize] =
            hex!("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001");
        let field1: Field = Field::new_init(&field1_bytes).unwrap();
        let field2: Field = Field::new_init(&field2_bytes).unwrap();
        let field_add = field1.add(field2, modulo).unwrap();
        let field_add_test_bytes: [u8; N_BYTES as usize] =
            hex!("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000002");
        let field_add_test: Field = Field::new_init(&field_add_test_bytes).unwrap();

        assert_eq!(field_add_test.bytes, field_add.bytes);
        cx_bn_unlock().unwrap();
    }

    #[test]
    fn test_field_mul1() {
        cx_bn_lock(N_BYTES, 0).unwrap();
        let mod_bytes: [u8; N_BYTES as usize] =
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"); // mod = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        let modulo: Field = Field::new_init(&mod_bytes).unwrap();

        let field1_bytes: [u8; N_BYTES as usize] =
            hex!("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000002"); //  = 2
        let field2_bytes: [u8; N_BYTES as usize] =
            hex!("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000003"); // = 3
        let field1: Field = Field::new_init(&field1_bytes).unwrap();
        let field2: Field = Field::new_init(&field2_bytes).unwrap();
        let field_mul = field1.mul(field2, modulo).unwrap();
        let field_mul_test_bytes: [u8; N_BYTES as usize] =
            hex!("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000006");
        let field_mul_test: Field = Field::new_init(&field_mul_test_bytes).unwrap();

        assert_eq!(field_mul_test.bytes, field_mul.bytes);
        cx_bn_unlock().unwrap();
    }

    #[test]
    fn test_field_mul2() {
        cx_bn_lock(N_BYTES, 0).unwrap();
        let mod_bytes: [u8; N_BYTES as usize] =
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"); // mod = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        let modulo: Field = Field::new_init(&mod_bytes).unwrap();

        let field1_bytes: [u8; N_BYTES as usize] =
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364143"); //  = 2
        let field2_bytes: [u8; N_BYTES as usize] =
            hex!("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000003"); // = 3
        let field1: Field = Field::new_init(&field1_bytes).unwrap();
        let field2: Field = Field::new_init(&field2_bytes).unwrap();
        let field_mul = field1.mul(field2, modulo).unwrap();
        let field_mul_test_bytes: [u8; N_BYTES as usize] =
            hex!("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000006");
        let field_mul_test: Field = Field::new_init(&field_mul_test_bytes).unwrap();

        assert_eq!(field_mul_test.bytes, field_mul.bytes);
        cx_bn_unlock().unwrap();
    }

    #[test]
    fn test_field_pow() {
        cx_bn_lock(N_BYTES, 0).unwrap();
        let mod_bytes: [u8; N_BYTES as usize] =
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"); // mod = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        let modulo: Field = Field::new_init(&mod_bytes).unwrap();

        let field1_bytes: [u8; N_BYTES as usize] =
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364143"); //  = 2
        let field1: Field = Field::new_init(&field1_bytes).unwrap();

        let field2_bytes: [u8; N_BYTES as usize] =
            hex!("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000003"); // = 3
        let field2: Field = Field::new_init(&field2_bytes).unwrap();

        let field_mul = field1.pow(field2, modulo).unwrap();
        let field_mul_test_bytes: [u8; N_BYTES as usize] =
            hex!("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000008");
        let field_mul_test: Field = Field::new_init(&field_mul_test_bytes).unwrap();

        assert_eq!(field_mul_test, field_mul);
        cx_bn_unlock().unwrap();
    }

    #[test]
    fn test_point_new_gen() {
        cx_bn_lock(N_BYTES, 0).unwrap();
        let gen_x_bytes: [u8; N_BYTES as usize] =
            hex!("79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798"); // mod = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        let gen_y_bytes: [u8; N_BYTES as usize] =
            hex!("483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8"); // mod = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141

        let gen: Point = Point::new_gen().unwrap();
        let gen_test: Point = Point::new_init(&gen_x_bytes, &gen_y_bytes).unwrap();

        assert_eq!(gen, gen_test);
        cx_bn_unlock().unwrap(); // !!!! unlock efface la mémoire donc échanger ces deux lignes la fait une erreur
    }

    #[test]
    fn test_point_add() {
        cx_bn_lock(N_BYTES, 0).unwrap();

        // 2 * G
        let p1_x_bytes: [u8; N_BYTES as usize] =
            hex!("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
        let p1_y_bytes: [u8; N_BYTES as usize] =
            hex!("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a");
        let p1: Point = Point::new_init(&p1_x_bytes, &p1_y_bytes).unwrap();

        // 3 * G
        let p2_x_bytes: [u8; N_BYTES as usize] =
            hex!("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
        let p2_y_bytes: [u8; N_BYTES as usize] =
            hex!("388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672");
        let p2: Point = Point::new_init(&p2_x_bytes, &p2_y_bytes).unwrap();

        // 5 * G
        let p3_x_bytes: [u8; N_BYTES as usize] =
            hex!("2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4");
        let p3_y_bytes: [u8; N_BYTES as usize] =
            hex!("d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6");
        let p3: Point = Point::new_init(&p3_x_bytes, &p3_y_bytes).unwrap();

        let p3_test = p1.add(p2).unwrap();
        assert_eq!(p3,p3_test);
        cx_bn_unlock().unwrap();
    }

    #[test]
    fn test_point_mul_scalar() {
        cx_bn_lock(N_BYTES, 0).unwrap();

        let mut gen: Point = Point::new_gen().unwrap(); // mut car mul_scalar change le Point

        // 2 * G
        let p1_x_bytes: [u8; N_BYTES as usize] =
            hex!("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
        let p1_y_bytes: [u8; N_BYTES as usize] =
            hex!("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a");
        let p1: Point = Point::new_init(&p1_x_bytes, &p1_y_bytes).unwrap();

        // 2
        let field1_bytes: [u8; N_BYTES as usize] =
        hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364143"); //  = 2
        let field1: Field = Field::new_init(&field1_bytes).unwrap();

        gen.mul_scalar(field1).unwrap();

        assert_eq!(gen, p1);
        cx_bn_unlock().unwrap();
    }

    #[test]
    fn test_point_export_apdu() {
        cx_bn_lock(N_BYTES, 0).unwrap();

        // 2 * G
        let p1_x_bytes: [u8; N_BYTES as usize] =
            hex!("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
        let p1_y_bytes: [u8; N_BYTES as usize] =
            hex!("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a");
        let p1: Point = Point::new_init(&p1_x_bytes, &p1_y_bytes).unwrap();

        let apdu: [u8; 2 * N_BYTES as usize + 1] = hex!("04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a");
        let apdu_test = p1.export_apdu().unwrap();
        assert_eq!(apdu, apdu_test);

        cx_bn_unlock().unwrap();
    }


    #[test]
    fn test_point_is_at_infinity() {
        cx_bn_lock(N_BYTES, 0).unwrap();

        // 2 * G
        let p1_x_bytes: [u8; N_BYTES as usize] =
            hex!("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
        let p1_y_bytes: [u8; N_BYTES as usize] =
            hex!("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a");
        let p1: Point = Point::new_init(&p1_x_bytes, &p1_y_bytes).unwrap();

        assert_eq!(false, p1.is_at_infinity().unwrap());
        cx_bn_unlock().unwrap();
    }
}
// IS_ON_CURVE PAS SUPPORTÉ PAR SPECULOS IL SEMBLE 
    // #[test]
    // fn test_point_is_on_curve1() {
    //     cx_bn_lock(N_BYTES, 0);

    //     let p1_x_bytes: [u8; N_BYTES as usize] =
    //         hex!("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
    //     let p1_y_bytes: [u8; N_BYTES as usize] =
    //         hex!("388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672");
    //     let p1: Point = Point::new_init(&p1_x_bytes, &p1_y_bytes).unwrap();

    //     let p1_test = p1.is_on_curve().unwrap();
    //     // let p1_test = true;
    //     assert_eq!(true,p1_test);
    //     cx_bn_unlock();
    // }

    // #[test]
    // fn test_point_is_on_curve2() {
    //     cx_bn_lock(N_BYTES, 0);

    //     let p1_x_bytes: [u8; N_BYTES as usize] =
    //         hex!("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f8");
    //     let p1_y_bytes: [u8; N_BYTES as usize] =
    //         hex!("388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672");
    //     let p1: Point = Point::new_init(&p1_x_bytes, &p1_y_bytes).unwrap();

    //     let p1_test = p1.is_on_curve().unwrap();
    //     assert_eq!(false,p1_test);
    //     cx_bn_unlock();
    // }
