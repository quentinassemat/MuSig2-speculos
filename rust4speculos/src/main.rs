// REMPLACER LES POINTS/FIELD PAR POINTBYTES ET FIELDBYTES 
// REFAIRE LES FONCTIONS DE TRANSITIONS _ -> BYTES POUR QU'ELLE PRENNE MOINS DE RAM (JUSTE RÉÉCRIRE DANS LE TABLEAU)
// AJOUTER LES TRANSITIONS POUR LES CALCULS DANS TOUS LE NEXT_ROUND


#![no_std]
#![no_main]
#![cfg_attr(test, main)]
#![feature(custom_test_frameworks)]
#![reexport_test_harness_main = "test_main"]
#![test_runner(nanos_sdk::sdk_test_runner)]

mod crypto_helpers;
mod cx_helpers;
mod data_types;
mod signer;
mod utils;

use crate::crypto_helpers::*;
use crate::cx_helpers::*;
use crate::data_types::*;
use crate::signer::*;

use nanos_sdk::buttons::ButtonEvent;
use nanos_sdk::io;
use nanos_ui::ui;
use nanos_sdk::io::Reply;

use core::str::from_utf8;

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

fn sign_musig_2(
    comm: &mut io::Comm,
    s: &mut Signer,
) -> Result<Option<[u8; N_BYTES as usize]>, CxSyscallError> {
    // fonction renvoie la signature en binaire

    let mut s1 = Signer1::new(s)?;

    // reception des clefs publiques des autres (nous sommes censées déjà les avoir dans l'app)


    {
        // réception des clefs publiques de la part du server
        comm.reply_ok();
        loop {
            // Draw some 'Waiting ...' screen
            ui::SingleMessage::new("Recep pubkeys ...").show();
            // Wait for a valid instruction
            match comm.next_event() {
                io::Event::Command(ins) => match ins {
                    Ins::SendPubkeys => {
                        match comm.get_data() {
                            Ok(data) => {
                                s1.recep_pubkeys(data)?;
                                comm.reply_ok();
                            }
                            Err(e) => {
                                nanos_sdk::debug_print("badlen\n");
                            }
                        }
                        break;
                    }
                    _ => (),
                },
                _ => (),
            }
        }
    }

    //génération private nonces
    {
        s1.gen_private_nonces()?;
    }
    {
        //mode attente et envoie des privates nonces au server
        comm.reply_ok();
        for i in 0..NB_NONCES {
            let pn = s1.get_public_nonces()?;
            loop {
                // Draw some 'Sending nonces ...' screen
                ui::SingleMessage::new("Sending nonces ...").show();
                // Wait for a valid instruction
                match comm.next_event() {
                    io::Event::Command(ins) => match ins {
                        Ins::SendNonces => {
                            comm.append(&pn[i as usize]);
                            comm.reply_ok();
                            break;
                        }
                        _ => (),
                    },
                    _ => (),
                }
            }
        }
    }
    
    {
        // réception des nonces de la part du server

        for i in 0..NB_PARTICIPANT {
            loop {
                // Draw some 'Waiting ...' screen
                ui::SingleMessage::new("Recep nonces ...").show();
                // Wait for a valid instruction
                match comm.next_event() {
                    io::Event::Command(ins) => match ins {
                        Ins::RecepNonces => {
                            match comm.get_data() {
                                Ok(data) => {
                                    s1.recep_nonces(data)?;
                                    comm.reply_ok();
                                }
                                Err(e) => {
                                    nanos_sdk::debug_print("badlen\n");
                                }
                            }
                            break;
                        }
                        _ => (),
                    },
                    _ => (),
                }
            }
        }
    }

    let mut s2 = s1.next_round()?;

    {
    //mode attente et envoie des privates nonces au server
        let sign = s2.get_sign()?;
        loop {
            // Draw some 'Sending nonces ...' screen
            ui::SingleMessage::new("Sending signatures ...").show();
            // Wait for a valid instruction
            match comm.next_event() {
                io::Event::Command(ins) => match ins {
                    Ins::SendSignatures => {
                        comm.append(&sign);
                        comm.reply_ok();
                        break;
                    }
                    _ => (),
                },
                _ => (),
            }
        }
    }

    {
        // réception des nonces de la part du server

        loop {
            // Draw some 'Waiting ...' screen
            ui::SingleMessage::new("Recep signatures ...").show();
            // Wait for a valid instruction
            match comm.next_event() {
                io::Event::Command(ins) => match ins {
                    Ins::RecepSignatures => {
                        match comm.get_data() {
                            Ok(data) => {
                                s2.recep_signs(data)?;
                                comm.reply_ok();
                            }
                            Err(e) => {
                                nanos_sdk::debug_print("badlen\n");
                            }
                        }
                        break;
                    }
                    _ => (),
                },
                _ => (),
            }
        }
    }

    {
        let valid = s2.verif()?;
        if valid {
            ui::popup("True :)");
        }
        else {
            ui::popup("False :(");
        }
    }

    // pour avoir le bon return tant que le programme n'est pas complet
    {
        let sign = s2.signature()?;
        Ok(Some(sign.bytes))
    }
}

// REPRÉSENTATION DES INSTRUCTIONS

// à modifier pour mettres les envoies de nonces/réception etc
#[repr(u8)]
enum Ins {
    GetPubkey,
    SignMuSig2,
    SendNonces,
    RecepNonces,
    SendSignatures,
    RecepSignatures,
    SendPubkeys,
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
            4 => Ins::RecepNonces,
            5 => Ins::SendSignatures,
            6 => Ins::RecepSignatures,
            7 => Ins::SendPubkeys,
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
            if let Some(o) = out {
                comm.append(&o)
            }
        }
        // les autres cas correspondent à une instruction erronnée ou à une instruction pendant la signature
        // dans les deux cas on ne fait rien
        _ => {
            let o: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
            comm.append(&o);
        }
    }
    Ok(())
}
