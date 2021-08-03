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
    pub fn new() -> Result<Field, CxSyscallError> {
        // new avec init à 0
        // déclaration
        let bytes = [0u8; N_BYTES as usize];

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
        }

        // on alloue la mémoire
        let index = cx_bn_alloc_init(N_BYTES, &bytes)?;

        // on renvoie
        Ok(Field { index, bytes })
    }

    pub fn new_init(init: &[u8]) -> Result<Field, CxSyscallError> {
        // init avec un pointeur vers un tableau de [u8 : N_BYTES = 32]

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
        }

        // on alloue la mémoire
        let index = cx_bn_alloc_init(N_BYTES, &init)?;

        // on stocke en bytes
        let mut bytes = [0u8; N_BYTES as usize];
        cx_bn_export(index, &mut bytes)?;

        // on renvoie
        Ok(Field { index, bytes })
    }

    pub fn add(&self, other: Field, modulo: Field) -> Result<Field, CxSyscallError> {
        // addition de self et other avec le modulo ( qui sera l'ordre de la courbe SECP256K1)
        // déclaration
        let mut bytes = [0u8; N_BYTES as usize];

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
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

    pub fn mul(&self, other: Field, modulo: Field) -> Result<Field, CxSyscallError> {
        // multiplication de self et other avec le modulo ( qui sera l'ordre de la courbe SECP256K1)
        // déclaration
        let mut bytes = [0u8; N_BYTES as usize];

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
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

    pub fn pow(&self, exp: Field, modulo: Field) -> Result<Field, CxSyscallError> {
        // calcul de self^pow mod modulo. Petit théorème de Fermat assure que ça sert à rien de mettre des exposants plus grand que le mod
        // déclaration
        let mut bytes = [0u8; N_BYTES as usize];

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
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

    pub fn show(&self) -> Result<(), CxSyscallError> {
        let hex = utils::to_hex(&self.bytes).map_err(|_| CxSyscallError::Overflow)?;
        let m = from_utf8(&hex).map_err(|_| CxSyscallError::InvalidParameter)?;
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
    pub fn new() -> Result<Point, CxSyscallError> {
        // new sans init

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
        }

        // on alloue la mémoire
        let p = cx_ecpoint_alloc(bindings::CX_CURVE_SECP256K1)?;

        // on renvoie
        Ok(Point { p })
    }

    pub fn new_init(x: &[u8], y: &[u8]) -> Result<Point, CxSyscallError> {
        // new avec init

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
        }

        // on alloue la mémoire
        let mut p = cx_ecpoint_alloc(bindings::CX_CURVE_SECP256K1)?;
        // on init
        cx_ecpoint_init(&mut p, x, y)?;
        // on renvoie
        Ok(Point { p })
    }

    pub fn new_gen() -> Result<Point, CxSyscallError> {
        let mut p = cx_ecpoint_alloc(bindings::CX_CURVE_SECP256K1)?;
        let p = cx_ecdomain_generator_bn(bindings::CX_CURVE_SECP256K1, &mut p)?;
        Ok(Point { p })
    }

    pub fn add(&self, other: Point) -> Result<Point, CxSyscallError> {
        // addition de self et other avec l'addition de la courbe elliptique

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
        }

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
                        // nanos_sdk::debug_print("debug add\n");
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

    pub fn mul_scalar(&mut self, other: Field) -> Result<(), CxSyscallError> {
        // multiplication de self par other (Field) (!! modifie self !!)

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
        }

        // on fait la multiplication
        cx_ecpoint_rnd_scalarmul_bn(&mut self.p, other.index)
    }

    //

    pub fn is_at_infinity(&self) -> Result<bool, CxSyscallError> {
        let mut res: bool = false;
        let mut res_ptr: *mut bool = &mut res;
        cx_ecpoint_is_at_infinity(&self.p, res_ptr)?;
        Ok(res)
    }

    pub fn is_on_curve(&self) -> Result<bool, CxSyscallError> {
        let mut res: bool = false;
        let mut res_ptr: *mut bool = &mut res;
        cx_ecpoint_is_on_curve(&self.p, res_ptr)?;
        Ok(res)
    }

    // les trois getters des coordonnées

    pub fn coords(&self) -> Result<(Field, Field), CxSyscallError> {
        let mut x_bytes = [0_u8; N_BYTES as usize];
        let mut y_bytes = [0_u8; N_BYTES as usize];
        cx_ecpoint_export(&self.p, &mut x_bytes, &mut y_bytes)?;
        let x = Field::new_init(&x_bytes)?;
        let y = Field::new_init(&y_bytes)?;

        Ok((x, y))
    }

    pub fn x_affine(&self) -> Result<Field, CxSyscallError> {
        let (x, _y) = self.coords()?;
        Ok(x)
    }

    pub fn y_affine(&self) -> Result<Field, CxSyscallError> {
        let (_x, y) = self.coords()?;
        Ok(y)
    }

    pub fn export_apdu(&self) -> Result<[u8; 2 * N_BYTES as usize + 1], CxSyscallError> {
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

    pub fn show(&self) -> Result<(), CxSyscallError> {
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
