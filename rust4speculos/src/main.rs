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
mod signer;

use crate::cx_helpers::*;
use crate::crypto_helpers::*;
use crate::data_types::*;
use crate::signer::*;

use nanos_sdk::buttons::ButtonEvent;
use nanos_sdk::exit_app;
use nanos_sdk::io;
use nanos_sdk::io::Reply;
use nanos_sdk::TestType;
use nanos_ui::ui;

use core::str::from_utf8;

use hex_literal::hex;

pub const N_BYTES: u32 = 32;

nanos_sdk::set_panic!(nanos_sdk::exiting_panic);

/// Basic nested menu. Will be subject
/// to simplifications in the future.
#[allow(clippy::needless_borrow)]
fn show_menu(s: &mut Signer) {
    loop {
        match ui::Menu::new(&[&"PubKey", &"Infos", &"Back", &"Exit App"]).show() {
            0 => show_pubkey(s).unwrap(),
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

/// Display public key in two separate
/// message scrollers
fn show_pubkey(s: &mut Signer) -> Result<(), CxSyscallError> {
    let pubkey = s.get_pubkey();
    match pubkey {
        Ok(pk) => {
            {
                let hex0 = utils::to_hex(&pk[1..33]).unwrap();
                let m = from_utf8(&hex0).unwrap();
                ui::MessageScroller::new(m).event_loop();
            }
            {
                let hex1 = utils::to_hex(&pk[33..65]).unwrap();
                let m = from_utf8(&hex1).unwrap();
                ui::MessageScroller::new(m).event_loop();
            }
        }
        Err(e) => e.show(),
    }
    Ok(())
}

#[no_mangle]
#[cfg(not(test))]
extern "C" fn sample_main() {
    let mut comm = io::Comm::new();
    comm.reply_ok();
    let mut s: Signer = Signer::new().unwrap();
    loop {
        // Draw some 'welcome' screen
        ui::SingleMessage::new("Welcome MuSig2").show();
        // Wait for either a specific button push to exit the app
        // or an APDU command

        match comm.next_event() {
            io::Event::Button(ButtonEvent::RightButtonRelease) => nanos_sdk::exit_app(0),
            io::Event::Button(ButtonEvent::LeftButtonRelease) => show_menu(&mut s),
            io::Event::Command(ins) => match handle_apdu(&mut comm, ins, &mut s) {
                Ok(()) => comm.reply_ok(),
                Err(sw) => {
                    comm.reply(sw);
                }
            },
            _ => (),
        }
    }
}

// FONCTIONS POUR GÉRER LES DIFFÉRENTS APDU

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

        let bytes = point3.export_apdu()?;

        cx_bn_unlock()?;
        Ok(Some(bytes))
    } else {
        ui::popup("Cancelled");
        Ok(None)
    }
}

fn sign_musig_2(comm: &mut io::Comm, s: &mut Signer) -> Result<Option<[u8; N_BYTES as usize]>, CxSyscallError> { // fonction renvoie la signature en binaire
    // on envoie pas les clefs publiques, les autres sont censées les avoir (speculos génère toujours les mêmes de tout façon)
    // on les affiches dans le debug pour les rentrer dans le python


    // on est censé déjà avoir les clefs publiques des autres donc on les reçoit pas 

    //génération private nonces
    s.gen_private_nonces()?;

    //mode attente et envoie des privates nonces au server 
    comm.reply_ok();
    loop {
        // Draw some 'Wainting ...' screen
        ui::SingleMessage::new("Waiting ...").show();
        // Wait for a valid instruction
        match comm.next_event() {
            io::Event::Command(ins) =>  {
                match ins {
                    Ins::SendNonces => {
                        let pn = s.get_public_nonces()?;
                        for i in 0..NB_NONCES {
                            comm.append(&pn[i as usize]);
                            // comm.reply_ok();
                            nanos_sdk::debug_print("test boucle");
                        }
                        comm.reply_ok();
                        ui::popup("ok");
                        break;
                    },
                    _ => {
                        ui::popup("Invalid : signing");
                    },
                }
            },
            _ => (),
        }
    }
    ui::popup("quit sign");

    Ok(None)

}

// REPRÉSENTATION DES INSTRUCTIONS

// à modifier pour mettres les envoies de nonces/réception etc 
#[repr(u8)]
enum Ins {
    GetPubkey,
    SignMuSig2,
    SendNonces,
    ShowPrivateKey,
    Exit,
}

// mettre que si on les reçoit d'ici ça marque  : instruction invalide : pas en signature
impl From<u8> for Ins {
    fn from(ins: u8) -> Ins {
        match ins {
            1 => Ins::GetPubkey,
            2 => Ins::SignMuSig2,
            3 => Ins::SendNonces,
            0xfe => Ins::ShowPrivateKey,
            0xff => Ins::Exit,
            _ => panic!(),
        }
    }
}

// à bien différencier pour le sign et pas le sign 
fn handle_apdu(comm: &mut io::Comm, ins: Ins, s: &mut Signer) -> Result<(), Reply> {
    if comm.rx == 0 {
        return Err(io::StatusWords::NothingReceived.into());
    }

    match ins {
        Ins::GetPubkey => comm.append(&s.get_pubkey()?),
        Ins::ShowPrivateKey => comm.append(&bip32_derive_secp256k1(&BIP32_PATH)?),
        Ins::Exit => nanos_sdk::exit_app(0),
        Ins::SignMuSig2 => {
            let out = sign_musig_2(comm, s)?;
            ui::popup("test");
            if let Some(o) = out {
                comm.append(&o)
            }
        }
        Ins::SendNonces => {
            ui::popup("Not signing");
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

    use data_types::Field;

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
        let field2: Field = Field::new_init(&field2_bytes).unwrap();
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

    //test juste pour voir sur l'ui que le random a l'air de bien marcher... pas un vrai test

    // #[test]
    // fn test_show_rand() {
    //     cx_bn_lock(N_BYTES, 0).unwrap();

    //     let rand: Field = Field::new_rand().unwrap();
    //     rand.show().unwrap();

    //     assert_eq!(0, 0);
    //     cx_bn_unlock().unwrap();
    // }

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
        assert_eq!(p3, p3_test);
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

    #[test]
    fn test_hash() {
        cx_bn_lock(N_BYTES, 0).unwrap();

        let mut hash = Hash::new().unwrap();

        let test: [u8; N_BYTES as usize] =
            hex!("132f39a98c31baaddba6525f5d43f2954472097fa15265f45130bfdb70e51def"); // résultat censé être obtenu
        let gen: Point = Point::new_gen().unwrap();
        let x: Field = gen.x_affine().unwrap();
        let bytes = x.bytes;

        hash.update(&bytes, N_BYTES).unwrap();
        let digest = hash.digest().unwrap();

        //pour afficher le hash en debug_print

        // let hex = utils::to_hex(&digest).map_err(|_| CxSyscallError::Overflow).unwrap();
        // let m = from_utf8(&hex).map_err(|_| CxSyscallError::InvalidParameter).unwrap();
        // nanos_sdk::debug_print(m);

        assert_eq!(digest, test);

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
