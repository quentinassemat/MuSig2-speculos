// FICHIER QUI GÈRE L'IMPLÉMENTATION DES DIFFÉRENTS TYPES DE DONNÉES POUR WRAPPER LES UNSAFE DU C
//pour les tests

use crate::cx_helpers::*;
use crate::utils;
use core::str::from_utf8;
use nanos_sdk::bindings;
use nanos_ui::ui;
use hex_literal::hex;

// CONSTANTES UTILES

pub const NB_NONCES: u32 = 3;
pub const NB_PARTICIPANT: u32 = 2;
pub const N_BYTES: u32 = 32;

pub const M: &str = "Alice donne 1 Bitcoin à Bob";

// STRUCTURE DE DONNÉES
// TOUT S'UTILISE UNIQUEMENT EN LOCK

#[derive(Copy, Clone)]
pub struct FieldBytes {
    pub bytes: [u8; N_BYTES as usize],
}

impl FieldBytes {
    pub fn new() -> Result<FieldBytes, CxSyscallError> {
        let bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
        Ok(FieldBytes { bytes })
    }

    pub fn new_init(init: &[u8]) -> Result<FieldBytes, CxSyscallError> {
        let mut bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
        for i in 0..N_BYTES {
            bytes[i as usize] = init[i as usize];
        }
        Ok(FieldBytes { bytes })
    }

    //affichage

    pub fn show(&self) -> Result<(), CxSyscallError> {
        let hex = utils::to_hex(&self.bytes).map_err(|_| CxSyscallError::Overflow)?;
        let m = from_utf8(&hex).map_err(|_| CxSyscallError::InvalidParameter)?;
        ui::MessageScroller::new(m).event_loop();
        Ok(())
    }

    pub fn debug_show(&self) -> Result<(), CxSyscallError> {
        let hex = utils::to_hex(&self.bytes).map_err(|_| CxSyscallError::Overflow)?;
        let m = from_utf8(&hex).map_err(|_| CxSyscallError::InvalidParameter)?;
        nanos_sdk::debug_print("value : ");
        nanos_sdk::debug_print(m);
        nanos_sdk::debug_print("\n");
        Ok(())
    }

    // into crypto ram

    pub fn into_crypto_ram(self) -> Result<Field, CxSyscallError> {
        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
        }

        // on alloue la mémoire
        let index = cx_bn_alloc_init(N_BYTES, &self.bytes)?;

        Ok(Field { index })
    }
}

impl PartialEq for FieldBytes {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

#[derive(Copy, Clone)]
pub struct Field {
    pub index: CxBn,
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
        Ok(Field { index })
    }

    pub fn new_init(init: &[u8]) -> Result<Field, CxSyscallError> {
        // init avec un pointeur vers un tableau de [u8 : N_BYTES = 32]

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
        }

        // on alloue la mémoire
        let index = cx_bn_alloc_init(N_BYTES, &init)?;

        // on renvoie
        Ok(Field { index })
    }

    pub fn new_rand() -> Result<Field, CxSyscallError> {
        // init avec un pointeur vers un tableau de [u8 : N_BYTES = 32]

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
        }

        let index = cx_bn_alloc(N_BYTES)?;

        cx_bn_rand(index)?;

        // on renvoie
        Ok(Field { index })
    }

    pub fn add(&self, other: Field, modulo: Field) -> Result<Field, CxSyscallError> {
        // addition de self et other avec le modulo ( qui sera l'ordre de la courbe SECP256K1)

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
        }

        // on alloue la mémoire pour le resultat
        let index = cx_bn_alloc(N_BYTES)?;

        // on fait l'addition
        cx_bn_mod_add(index, self.index, other.index, modulo.index)?;

        // on renvoie le résultat
        Ok(Field { index })
    }

    pub fn mul(&self, other: Field, modulo: Field) -> Result<Field, CxSyscallError> {
        // multiplication de self et other avec le modulo ( qui sera l'ordre de la courbe SECP256K1)

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
        }

        // on alloue la mémoire pour le resultat
        let index = cx_bn_alloc(N_BYTES)?;

        // on fait l'addition
        cx_bn_mod_mul(index, self.index, other.index, modulo.index)?;

        // on renvoie le résultat
        Ok(Field { index })
    }

    pub fn pow(&self, exp: Field, modulo: Field) -> Result<Field, CxSyscallError> {
        // calcul de self^pow mod modulo. Petit théorème de Fermat assure que ça sert à rien de mettre des exposants plus grand que le mod

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
        }

        // on alloue la mémoire pour le resultat
        let index = cx_bn_alloc(N_BYTES)?;

        // on fait l'addition
        cx_bn_mod_pow_bn(index, self.index, exp.index, modulo.index)?;

        // on renvoie le résultat
        Ok(Field { index })
    }

    // memory optimisation

    pub fn into_ram(self) -> Result<FieldBytes, CxSyscallError> {
        let mut bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
        cx_bn_export(self.index, &mut bytes)?;
        cx_bn_destroy(self.index)?;
        Ok(FieldBytes { bytes })
    }

    pub fn destroy(self) -> Result<(), CxSyscallError> {
        cx_bn_destroy(self.index)?;
        Ok(())
    }
}

impl PartialEq for Field {
    fn eq(&self, other: &Self) -> bool {
        let diff = 0;
        cx_bn_cmp(self.index, other.index, diff).unwrap();
        diff == 0
    }
}

#[derive(Copy, Clone)]
pub struct PointBytes {
    pub x_bytes: [u8; N_BYTES as usize],
    pub y_bytes: [u8; N_BYTES as usize],
}

impl PointBytes {
    pub fn new_gen() -> Result<PointBytes, CxSyscallError> {
        let x_bytes: [u8; N_BYTES as usize] = hex!("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let y_bytes: [u8; N_BYTES as usize] = hex!("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
        Ok(PointBytes{x_bytes, y_bytes})
    }

    pub fn new_init(x: &[u8], y: &[u8]) -> Result<PointBytes, CxSyscallError> {
        let mut x_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
        let mut y_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
        for i in 0..N_BYTES {
            x_bytes[i as usize] = x[i as usize];
            y_bytes[i as usize] = y[i as usize];
        }
        Ok(PointBytes{x_bytes, y_bytes})
    }

    // into crypto ram

    pub fn into_crypto_ram(self) -> Result<Point, CxSyscallError> {
        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
        }

        // on alloue la mémoire
        let mut p = cx_ecpoint_alloc(bindings::CX_CURVE_SECP256K1)?;

        // on init
        cx_ecpoint_init(&mut p, &self.x_bytes, &self.y_bytes)?;

        Ok(Point { p })
    }

    // affichage

    pub fn show(&self) -> Result<(), CxSyscallError> {
        {
            let hex = utils::to_hex(&self.x_bytes).map_err(|_| CxSyscallError::Overflow)?;
            let m = from_utf8(&hex).map_err(|_| CxSyscallError::InvalidParameter)?;
            ui::MessageScroller::new(m).event_loop();
        }
        {
            let hex = utils::to_hex(&self.y_bytes).map_err(|_| CxSyscallError::Overflow)?;
            let m = from_utf8(&hex).map_err(|_| CxSyscallError::InvalidParameter)?;
            ui::MessageScroller::new(m).event_loop();
        }
        Ok(())
    }

    pub fn debug_show(&self) -> Result<(), CxSyscallError> {
        {
            let hex = utils::to_hex(&self.x_bytes).map_err(|_| CxSyscallError::Overflow)?;
            let m = from_utf8(&hex).map_err(|_| CxSyscallError::InvalidParameter)?;
            nanos_sdk::debug_print("x : ");
            nanos_sdk::debug_print(m);
            nanos_sdk::debug_print("\n");
        }
        {
            let hex = utils::to_hex(&self.y_bytes).map_err(|_| CxSyscallError::Overflow)?;
            let m = from_utf8(&hex).map_err(|_| CxSyscallError::InvalidParameter)?;
            nanos_sdk::debug_print("y : ");
            nanos_sdk::debug_print(m);
            nanos_sdk::debug_print("\n");
        }
        Ok(())
    }

    pub fn export_apdu(&self) -> Result<[u8; 2 * N_BYTES as usize + 1], CxSyscallError> {
        let mut bytes = [0u8; 65];
        bytes[0] = 4;
        for i in 0..N_BYTES {
            bytes[i as usize + 1_usize] = self.x_bytes[i as usize];
            bytes[i as usize + 1_usize + N_BYTES as usize] = self.y_bytes[i as usize];
        }
        Ok(bytes)
    }
}

impl PartialEq for PointBytes {
    fn eq(&self, other: &Self) -> bool {
        (self.x_bytes == other.x_bytes) && (self.y_bytes == other.y_bytes)
    }
}

#[derive(Copy, Clone)]
pub struct Point {
    pub p: bindings::cx_ecpoint_t,
}

impl Point {
    pub fn new() -> Result<Point, CxSyscallError> {
        // new sans init
        // déclaration
        let x_bytes = [0u8; N_BYTES as usize];
        let y_bytes = [0u8; N_BYTES as usize];

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
        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
        }
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

        let mut p = cx_ecpoint_alloc(bindings::CX_CURVE_SECP256K1)?;

        // on fait l'addition
        cx_ecpoint_add(&mut p, &self.p, &other.p)?;

        Ok(Point { p })
    }

    pub fn mul_scalar(&mut self, other: Field) -> Result<(), CxSyscallError> {
        // multiplication de self par other (Field) (!! modifie self !!)

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(CxSyscallError::NotLocked);
        }

        // on fait la multiplication
        cx_ecpoint_rnd_scalarmul_bn(&mut self.p, other.index)?;

        Ok(())
    }

    //

    pub fn is_at_infinity(&mut self) -> Result<bool, CxSyscallError> {
        // executable que si chargé en ram crypto
        let mut res: bool = false;
        let res_ptr: *mut bool = &mut res;
        cx_ecpoint_is_at_infinity(&mut self.p, res_ptr)?;
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

    pub fn y_affine(&self) -> Result<Field,  CxSyscallError> {
        let (_x, y) = self.coords()?;
        Ok(y)
    }

    pub fn export_apdu(&self) -> Result<[u8; 2 * N_BYTES as usize + 1], CxSyscallError> {
        let mut bytes: [u8; 2 * N_BYTES as usize + 1] = [0; 2 * N_BYTES as usize + 1];
        bytes[0] = 4; // on dit qu'on fait non compressé;
        let mut x_bytes = [0_u8; N_BYTES as usize];
        let mut y_bytes = [0_u8; N_BYTES as usize];
        cx_ecpoint_export(&self.p, &mut x_bytes, &mut y_bytes)?;
        for i in 0..N_BYTES {
            bytes[1 + i as usize] = x_bytes[i as usize];
            bytes[1 + i as usize + N_BYTES as usize] = y_bytes[i as usize];
        }
        Ok(bytes)
    }

    // memory optimisation

    pub fn into_ram(mut self) -> Result<PointBytes, CxSyscallError> {
        let mut x_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
        let mut y_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
        cx_ecpoint_export(&self.p, &mut x_bytes, &mut y_bytes)?;
        cx_ecpoint_destroy(&mut self.p)?;
        Ok(PointBytes { x_bytes, y_bytes })
    }

    pub fn destroy(mut self) -> Result<(), CxSyscallError> {
        cx_ecpoint_destroy(&mut self.p)?;
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

// WRAPPERS AUTOUR DES FONCTIONS DE HASH
extern "C" {
    pub fn cx_sha256_update(
        ctx: *mut bindings::cx_sha256_t,
        data: *const u8,
        in_len: bindings::size_t,
    ) -> bindings::cx_err_t;
    pub fn cx_sha256_final(
        ctx: *mut bindings::cx_sha256_t,
        digest: *const u8,
    ) -> bindings::cx_err_t;
}

#[derive(Clone, Copy)]
pub struct Hash {
    pub h: bindings::cx_sha256_t,
}

impl Hash {
    pub fn new() -> Result<Hash, CxSyscallError> {
        let mut h = bindings::cx_sha256_t::default();
        let err =
            unsafe { bindings::cx_sha256_init_no_throw(&mut h as *mut bindings::cx_sha256_t) };
        if err != 0 {
            let cx_err: CxSyscallError = err.into();
            nanos_sdk::debug_print("err cx_hash_new\n");
            cx_err.show();
            Err(cx_err)
        } else {
            Ok(Hash { h })
        }
    }

    pub fn update(&mut self, input: &[u8], in_len: u32) -> Result<(), CxSyscallError> {
        let err = unsafe { cx_sha256_update(&mut self.h, input.as_ptr(), in_len) };
        if err != 0 {
            let cx_err: CxSyscallError = err.into();
            nanos_sdk::debug_print("err cx_hash_update\n");
            cx_err.show();
            Err(cx_err)
        } else {
            Ok(())
        }
    }

    pub fn digest(&mut self) -> Result<[u8; N_BYTES as usize], CxSyscallError> {
        let mut digest: [u8; N_BYTES as usize] = [0u8; N_BYTES as usize];
        let err = unsafe { cx_sha256_final(&mut self.h, digest.as_mut_ptr()) };
        if err != 0 {
            let cx_err: CxSyscallError = err.into();
            nanos_sdk::debug_print("err cx_hash_digest\n");
            cx_err.show();
            Err(cx_err)
        } else {
            Ok(digest)
        }
    }
}
