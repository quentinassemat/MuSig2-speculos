// FICHIER QUI GÈRE L'IMPLÉMENTATION DES DIFFÉRENTS TYPES DE DONNÉES POUR WRAPPER LES UNSAFE DU C

use core::str::from_utf8;
use nanos_sdk::bindings;
<<<<<<< Updated upstream
use nanos_sdk::ecc;
=======
>>>>>>> Stashed changes
use nanos_sdk::io::SyscallError;
use nanos_ui::ui;

// CONSTANTES UTILES

pub const NB_NONCES: u32 = 3;
pub const NB_PARTICIPANT: u32 = 2;
pub const N_BYTES: u32 = 32;

pub const M: &str = "Alice donne 1 Bitcoin à Bob";

// STRUCTURE DE DONNÉES
// TOUT S'UTILISE UNIQUEMENT EN LOCK

pub struct Field {
<<<<<<< Updated upstream
    pub index: u32,
    pub bytes: [u8; N_BYTES as usize],
    pub ptr: *mut u8,
=======
    pub index: CxBn,
    pub bytes: [u8; N_BYTES as usize],
>>>>>>> Stashed changes
}

impl Field {
    pub fn new() -> Result<Field, SyscallError> {
        // new avec init à 0
        // déclaration
        let mut index = 0_u32;
        let mut bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
        let ptr: *mut u8 = bytes.as_mut_ptr();
        unsafe {
            // on check si c'est lock
            // match bindings::cx_bn_locked() {
            //     bindings::CX_OK => (),
            //     bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
            //     _ => return Err(SyscallError::Unspecified),
            // }

            // on alloue la mémoire
            match bindings::cx_bn_alloc_init(&mut index, N_BYTES, ptr, N_BYTES) {
                bindings::CX_OK => (),
                bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
                bindings::CX_INVALID_PARAMETER_SIZE => return Err(SyscallError::InvalidParameter),
                _ => return Err(SyscallError::Unspecified),
            }
        }
        // on renvoie
<<<<<<< Updated upstream
        Ok(Field { index, bytes, ptr })
    }

    pub fn new_init(init: *const u8) -> Result<Field, SyscallError> {
        // init avec un pointeur vers un tableau de [u8 : N_BYTES = 32]
        // déclaration
        let mut index = 0_u32;
        let mut bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
        let ptr: *mut u8 = bytes.as_mut_ptr();

        unsafe {
            // on check si c'est lock
            // match bindings::cx_bn_locked() {
            //     bindings::CX_OK => (),
            //     bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
            //     _ => return Err(SyscallError::Unspecified),
            // }

            // on alloue la mémoire
            match bindings::cx_bn_alloc_init(&mut index, N_BYTES, init, N_BYTES) {
                bindings::CX_OK => (),
                bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
                bindings::CX_INVALID_PARAMETER_SIZE => return Err(SyscallError::InvalidParameter),
                _ => return Err(SyscallError::Unspecified),
            }

            // on stocke en bytes
            match bindings::cx_bn_export(index, ptr, N_BYTES) {
                bindings::CX_OK => (),
                bindings::CX_INVALID_PARAMETER_VALUE => return Err(SyscallError::InvalidParameter),
                bindings::CX_INVALID_PARAMETER_SIZE => return Err(SyscallError::InvalidParameter),
                bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
                bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
                _ => return Err(SyscallError::Unspecified),
            }
=======
        Ok(Field { index, bytes })
    }

    pub fn new_init(init: &[u8]) -> Result<Field, SyscallError> {
        // init avec un pointeur vers un tableau de [u8 : N_BYTES = 32]

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(SyscallError::InvalidState);
>>>>>>> Stashed changes
        }

        // on renvoie
<<<<<<< Updated upstream
        Ok(Field { index, bytes, ptr })
=======
        Ok(Field { index, bytes })
>>>>>>> Stashed changes
    }

    pub fn add(&self, other: Field, modulo: Field) -> Result<Field, SyscallError> {
        // addition de self et other avec le modulo ( qui sera l'ordre de la courbe SECP256K1)
        // déclaration
<<<<<<< Updated upstream
        let mut index = 0_u32;
        let mut bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
        let ptr: *mut u8 = bytes.as_mut_ptr();

        unsafe {
            // on check si c'est lock
            match bindings::cx_bn_is_locked() {
                true => (), // locked
                false => return Err(SyscallError::InvalidState),
                _ => return Err(SyscallError::Unspecified),
            }

            // on alloue la mémoire pour le resultat

            match bindings::cx_bn_alloc(&mut index, N_BYTES) {
                bindings::CX_OK => (),
                bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
                bindings::CX_INVALID_PARAMETER_SIZE => return Err(SyscallError::InvalidParameter),
                _ => return Err(SyscallError::Unspecified),
            }

            // on fait l'addition

            match bindings::cx_bn_mod_add(index, self.index, other.index, modulo.index) {
                bindings::CX_OK => (),
                bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
                bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
                _ => return Err(SyscallError::Unspecified),
            }

            // on stocke le binaire
            match bindings::cx_bn_export(index, ptr, N_BYTES) {
                bindings::CX_OK => (),
                bindings::CX_INVALID_PARAMETER_VALUE => return Err(SyscallError::InvalidParameter),
                bindings::CX_INVALID_PARAMETER_SIZE => return Err(SyscallError::InvalidParameter),
                bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
                bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
                _ => return Err(SyscallError::Unspecified),
            }
        }

        // on renvoie le résultat
        Ok(Field { index, bytes, ptr })
    }

    pub fn show(&self) -> Result<(), SyscallError> {
        let hex = crate::utils::to_hex(&self.bytes).map_err(|_| SyscallError::Overflow)?;
        let m = from_utf8(&hex).map_err(|_| SyscallError::InvalidParameter)?;
=======
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

    pub fn show(&self) {
        let hex = utils::to_hex(&self.bytes)
            .map_err(|_| SyscallError::Overflow)
            .unwrap();
        let m = from_utf8(&hex)
            .map_err(|_| SyscallError::InvalidParameter)
            .unwrap();
>>>>>>> Stashed changes
        ui::MessageScroller::new(m).event_loop();
        Ok(())
    }
}
<<<<<<< Updated upstream
=======

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
        cx_ecpoint_init(&mut p, x, y);

        // on renvoie
        Ok(Point { p })
    }

    pub fn new_gen() -> Result<Point, SyscallError> {
        let mut ecpoint = bindings::cx_ecpoint_t::default();
        let p = cx_ecdomain_generator_bn(bindings::CX_CURVE_SECP256K1, &mut ecpoint)?;
        Ok(Point { p })
    }

    pub fn add(&self, other: Point) -> Result<Point, SyscallError> {
        // addition de self et other avec l'addition de la courbe elliptique
        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(SyscallError::InvalidState);
        }

        // on alloue la mémoire
        let mut p = cx_ecpoint_alloc(bindings::CX_CURVE_SECP256K1)?;

        // on fait l'addition
        cx_ecpoint_add(&mut p, &self.p, &other.p)?;

        // on renvoie le résultat
        Ok(Point { p })
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

    // les trois getters des coordonnées

    pub fn coords(&self) -> Result<(Field, Field), SyscallError> {
        let mut x_bytes = [0_u8; N_BYTES as usize];
        let mut y_bytes = [0_u8; N_BYTES as usize];

        cx_ecpoint_export(&self.p, &mut x_bytes, &mut y_bytes)?;

        Ok((Field::new_init(&x_bytes)?, Field::new_init(&y_bytes)?))
    }

    pub fn x_affine(&self) -> Result<Field, SyscallError> {
        let (x, _y) = self.coords()?;
        Ok(x)
    }

    pub fn y_affine(&self) -> Result<Field, SyscallError> {
        let (_x, y) = self.coords()?;
        Ok(y)
    }

    pub fn show(&self) -> Result<(), SyscallError> {
        let (x, y) = self.coords()?;
        x.show();
        y.show();
        Ok(())
    }
}
>>>>>>> Stashed changes
