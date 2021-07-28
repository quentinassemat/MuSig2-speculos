// FICHIER QUI GÈRE L'IMPLÉMENTATION DES DIFFÉRENTS TYPES DE DONNÉES POUR WRAPPER LES UNSAFE DU C
mod self::utils;

use core::str::from_utf8;
use nanos_sdk::bindings;
use nanos_sdk::ecc;
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
    pub index: u32,
    pub bytes: [u8 ; N_BYTES as usize],
    pub ptr: *mut u8,
}

impl Field {
    pub fn new() -> Result<Field, SyscallError> { // new avec init à 0
        // déclaration
        let index = 0_u32;
        let mut bytes: [u8 ; N_BYTES as usize] = [0 ; N_BYTES as usize];
        let ptr: *mut u8 = bytes.as_mut_ptr();

        // on check si c'est lock
        match bindings::cx_bn_locked() {
            bindings::CX_OK => (),
            bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
            _ => return Err(SyscallError::Unspecified),
        }

        // on alloue la mémoire
        match bindings::cx_bn_alloc_init(&mut index, N_BYTES, ptr, N_BYTES) {
            bindings::CX_OK => (),
            bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
            bindings::CX_INVALID_PARAMETER_SIZE => return Err(SyscallError::InvalidParameter),
            _ => return Err(SyscallError::Unspecified),
        }

        // on renvoie
        Ok(Field {index, bytes, ptr})
    }

    pub fn new_init(init: *const u8) -> Result<Field, SyscallError> { // init avec un pointeur vers un tableau de [u8 : N_BYTES = 32]
        // déclaration
        let index = 0_u32;
        let mut bytes: [u8 ; N_BYTES as usize] = [0 ; N_BYTES as usize];
        let ptr: *mut u8 = bytes.as_mut_ptr();

        // on check si c'est lock
        match bindings::cx_bn_locked() {
            bindings::CX_OK => (),
            bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
            _ => return Err(SyscallError::Unspecified),
        }

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

        // on renvoie
        Ok(Field {index, bytes, ptr})
    }

    pub fn add(&self, other: Field, modulo: Field) -> Result<Field, SyscallError> { // addition de self et other avec le modulo ( qui sera l'ordre de la courbe SECP256K1)
        // déclaration
        let mut index = 0_u32;
        let mut bytes: [u8 ; N_BYTES as usize] = [0 ; N_BYTES as usize];
        let ptr: *mut u8 = bytes.as_mut_ptr();
        
        // on check si c'est lock
        match bindings::cx_bn_locked() {
            bindings::CX_OK => (),
            bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
            _ => return Err(SyscallError::Unspecified),
        }

        // on alloue la mémoire pour le resultat
        unsafe {
            match bindings::cx_bn_alloc(&mut index, N_BYTES) {
                bindings::CX_OK => (),
                bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
                bindings::CX_INVALID_PARAMETER_SIZE => {
                    return Err(SyscallError::InvalidParameter)
                }
                _ => return Err(SyscallError::Unspecified),
            }
        }

        // on fait l'addition
        unsafe {
            match bindings::cx_bn_mod_add(index, self.index, other.index, modulo.index) {
                bindings::CX_OK => (),
                bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
                bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
                _ => return Err(SyscallError::Unspecified),
            }
        }

        // on stocke le binaire
        match bindings::cx_bn_export(index, sum_bytes_ptr, N_BYTES) {
            bindings::CX_OK => (),
            bindings::CX_INVALID_PARAMETER_VALUE => return Err(SyscallError::InvalidParameter),
            bindings::CX_INVALID_PARAMETER_SIZE => return Err(SyscallError::InvalidParameter),
            bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
            bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
            _ => return Err(SyscallError::Unspecified),
        }

        // on renvoie le résultat
        Ok(Field {index, bytes, ptr})
    }

    pub fn show(&self) {
        let hex = utils::to_hex(&self.bytes).map_err(|_| SyscallError::Overflow)?;
        let m = from_utf8(&hex).map_err(|_| SyscallError::InvalidParameter)?;
        ui::MessageScroller::new(m).event_loop();
    }
}