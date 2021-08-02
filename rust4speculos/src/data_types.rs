// FICHIER QUI GÈRE L'IMPLÉMENTATION DES DIFFÉRENTS TYPES DE DONNÉES POUR WRAPPER LES UNSAFE DU C
//pour les tests

use crate::cx_helpers::*;
use crate::utils;
use core::str::from_utf8;
use nanos_sdk::bindings;
use nanos_sdk::exit_app;
use nanos_sdk::io::SyscallError;
use nanos_sdk::TestType;
use nanos_ui::ui;

// CONSTANTES UTILES

pub const NB_NONCES: u32 = 3;
pub const NB_PARTICIPANT: u32 = 2;
pub const N_BYTES: u32 = 32;

pub const M: &str = "Alice donne 1 Bitcoin à Bob";

// STRUCTURE DE DONNÉES
// TOUT S'UTILISE UNIQUEMENT EN LOCK

pub struct Field {
    pub index: CxBn,
    pub bytes: [u8; N_BYTES as usize],
}

impl Field {
    pub fn new() -> Result<Field, SyscallError> {
        // new avec init à 0
        // déclaration
        let bytes = [0u8; N_BYTES as usize];

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(SyscallError::InvalidState);
        }

        // on alloue la mémoire
        let index = cx_bn_alloc_init(N_BYTES, &bytes)?;

        // on renvoie
        Ok(Field { index, bytes })
    }

    pub fn new_init(init: &[u8]) -> Result<Field, SyscallError> {
        // init avec un pointeur vers un tableau de [u8 : N_BYTES = 32]

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(SyscallError::InvalidState);
        }

        // on alloue la mémoire
        let index = cx_bn_alloc_init(N_BYTES, &init)?;

        // on stocke en bytes
        let mut bytes = [0u8; N_BYTES as usize];
        cx_bn_export(index, &mut bytes)?;

        // on renvoie
        Ok(Field { index, bytes })
    }

    pub fn add(&self, other: Field, modulo: Field) -> Result<Field, SyscallError> {
        // addition de self et other avec le modulo ( qui sera l'ordre de la courbe SECP256K1)
        // déclaration
        let mut bytes = [0u8; N_BYTES as usize];

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(SyscallError::InvalidState);
        }

        // on alloue la mémoire pour le resultat
        let index = cx_bn_alloc(N_BYTES)?;

        // on fait l'addition
        cx_bn_mod_add(index, self.index, other.index, modulo.index)?;

        // on stocke le binaire
        cx_bn_export(index, &mut bytes)?;

        // on renvoie le résultat
        Ok(Field { index, bytes })
    }

    pub fn mul(&self, other: Field, modulo: Field) -> Result<Field, SyscallError> {
        // multiplication de self et other avec le modulo ( qui sera l'ordre de la courbe SECP256K1)
        // déclaration
        let mut bytes = [0u8; N_BYTES as usize];

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(SyscallError::InvalidState);
        }

        // on alloue la mémoire pour le resultat
        let index = cx_bn_alloc(N_BYTES)?;

        // on fait l'addition
        cx_bn_mod_mul(index, self.index, other.index, modulo.index)?;

        // on stocke le binaire
        cx_bn_export(index, &mut bytes)?;

        // on renvoie le résultat
        Ok(Field { index, bytes })
    }

    pub fn pow(&self, exp: Field, modulo: Field) -> Result<Field, SyscallError> {
        // calcul de self^pow mod modulo. Petit théorème de Fermat assure que ça sert à rien de mettre des exposants plus grand que le mod
        // déclaration
        let mut bytes = [0u8; N_BYTES as usize];

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(SyscallError::InvalidState);
        }

        // on alloue la mémoire pour le resultat
        let index = cx_bn_alloc(N_BYTES)?;

        // on fait l'addition
        cx_bn_mod_pow_bn(index, self.index, exp.index, modulo.index)?;

        // on stocke le binaire
        cx_bn_export(index, &mut bytes)?;

        // on renvoie le résultat
        Ok(Field { index, bytes })
    }

    //affichage

    pub fn show(&self) -> Result<(), SyscallError> {
        let hex = utils::to_hex(&self.bytes).map_err(|_| SyscallError::Overflow)?;
        let m = from_utf8(&hex).map_err(|_| SyscallError::InvalidParameter)?;
        ui::MessageScroller::new(m).event_loop();
        Ok(())
    }
}

impl PartialEq for Field {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

pub struct Point {
    pub p: bindings::cx_ecpoint_t,
}

impl Point {
    pub fn new() -> Result<Point, SyscallError> {
        // new sans init
        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(SyscallError::InvalidState);
        }

        // on alloue la mémoire
        let p = cx_ecpoint_alloc(bindings::CX_CURVE_SECP256K1)?;

        // on renvoie
        Ok(Point { p })
    }

    pub fn new_init(x: &[u8], y: &[u8]) -> Result<Point, SyscallError> {
        // new avec init
        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(SyscallError::InvalidState);
        }
        // on alloue la mémoire
        let mut p = cx_ecpoint_alloc(bindings::CX_CURVE_SECP256K1)?;
        // on init
        cx_ecpoint_init(&mut p, x, y)?;
        // on renvoie
        Ok(Point { p })
    }

    pub fn new_gen() -> Result<Point, SyscallError> {
        let mut p = cx_ecpoint_alloc(bindings::CX_CURVE_SECP256K1)?;
        let p = cx_ecdomain_generator_bn(bindings::CX_CURVE_SECP256K1, &mut p)?;
        Ok(Point { p })
    }

    pub fn add(&self, other: Point) -> Result<Point, SyscallError> {
        // addition de self et other avec l'addition de la courbe elliptique
        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(SyscallError::InvalidState);
        }

        // on alloue la mémoire
        //debug
        match cx_ecpoint_alloc(bindings::CX_CURVE_SECP256K1) {
            Ok(mut p) => {
                // on fait l'addition
                match cx_ecpoint_add(&mut p, &self.p, &other.p) {
                    Ok(()) => {
                        // on renvoie le résultat
                        Ok(Point { p })
                    }
                    Err(e) => {
                        nanos_sdk::debug_print("debug add");
                        match e {
                            SyscallError::InvalidParameter => nanos_sdk::debug_print("inva"),
                            SyscallError::Overflow => nanos_sdk::debug_print("ov"),
                            SyscallError::Security => nanos_sdk::debug_print("sec"),
                            SyscallError::InvalidCrc => nanos_sdk::debug_print("invacrc"),
                            SyscallError::InvalidChecksum => nanos_sdk::debug_print("invachechsum"),
                            SyscallError::InvalidCounter => nanos_sdk::debug_print("incacounter"),
                            SyscallError::NotSupported => nanos_sdk::debug_print("not supported"),
                            SyscallError::InvalidState => nanos_sdk::debug_print("inva state"),
                            SyscallError::Timeout => nanos_sdk::debug_print("timeout"),
                            SyscallError::Unspecified => nanos_sdk::debug_print("uns"),
                            _ => nanos_sdk::debug_print("unss"),
                        }
                        Err(e)
                    }
                }
            }
            Err(e) => {
                nanos_sdk::debug_print("debug alloc");
                Err(e)
            }
        }
        // let mut p = cx_ecpoint_alloc(bindings::CX_CURVE_SECP256K1)?;

        // // on fait l'addition
        // cx_ecpoint_add(&mut p, &self.p, &other.p)?;

        // // on renvoie le résultat
        // Ok(Point { p })
    }

    pub fn mul_scalar(&mut self, other: Field) -> Result<(), SyscallError> {
        // multiplication de self par other (Field) (!! modifie self !!)
        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(SyscallError::InvalidState);
        }

        // on fait la multiplication
        cx_ecpoint_rnd_scalarmul_bn(&mut self.p, other.index)
    }

    //

    pub fn is_at_infinity(&self) -> Result<bool, SyscallError> {
        let mut res: bool = false;
        let mut res_ptr: *mut bool = &mut res;
        cx_ecpoint_is_at_infinity(&self.p, res_ptr)?;
        Ok(res)
    }

    pub fn is_on_curve(&self) -> Result<bool, SyscallError> {
        let mut res: bool = false;
        let mut res_ptr: *mut bool = &mut res;
        cx_ecpoint_is_on_curve(&self.p, res_ptr)?;
        Ok(res)
    }

    // les trois getters des coordonnées

    pub fn coords(&self) -> Result<(Field, Field), SyscallError> {
        let mut x_bytes = [0_u8; N_BYTES as usize];
        let mut y_bytes = [0_u8; N_BYTES as usize];
        cx_ecpoint_export(&self.p, &mut x_bytes, &mut y_bytes)?;
        let x = Field::new_init(&x_bytes)?;
        let y = Field::new_init(&y_bytes)?;

        Ok((x, y))
    }

    pub fn x_affine(&self) -> Result<Field, SyscallError> {
        let (x, _y) = self.coords()?;
        Ok(x)
    }

    pub fn y_affine(&self) -> Result<Field, SyscallError> {
        let (_x, y) = self.coords()?;
        Ok(y)
    }

    pub fn export_apdu(&self) -> Result<[u8; 2 * N_BYTES as usize + 1], SyscallError> {
        let (x, y) = self.coords()?;
        let mut bytes: [u8; 2 * N_BYTES as usize + 1] = [0; 2 * N_BYTES as usize + 1];
        bytes[0] = 4; // on dit qu'on fait non compressé;
        for i in 0..N_BYTES {
            bytes[1 + i as usize] = x.bytes[i as usize];
            bytes[1 + i as usize + N_BYTES as usize] = y.bytes[i as usize];
        }
        Ok(bytes)
    }

    // affichage

    pub fn show(&self) -> Result<(), SyscallError> {
        let (x, y) = self.coords()?;
        x.show()?;
        y.show()?;
        Ok(())
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        let (self_x, self_y) = self.coords().unwrap();
        let (other_x, other_y) = other.coords().unwrap();
        (self_x == other_x) && (self_y == other_y)
    }
}
