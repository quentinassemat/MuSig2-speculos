// FICHIER QUI GÈRE L'IMPLÉMENTATION DES DIFFÉRENTS TYPES DE DONNÉES POUR WRAPPER LES UNSAFE DU C
use crate::cx_helpers::*;
use crate::utils;
use core::str::from_utf8;
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
    pub index: CxBn,
    pub bytes: [u8 ; N_BYTES as usize],
}

impl Field {
    pub fn new() -> Result<Field, SyscallError> { // new avec init à 0
        // déclaration
        let bytes = [0u8; N_BYTES as usize];

        // on check si c'est lock
        if !cx_bn_is_locked() {
            return Err(SyscallError::InvalidState);
        }

        // on alloue la mémoire
        let index = cx_bn_alloc_init(N_BYTES, &bytes)?;

        // on renvoie
        Ok(Field {index, bytes})
    }

    pub fn new_init(init: &[u8]) -> Result<Field, SyscallError> { // init avec un pointeur vers un tableau de [u8 : N_BYTES = 32]

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
        Ok(Field {index, bytes})
    }

    pub fn add(&self, other: Field, modulo: Field) -> Result<Field, SyscallError> { // addition de self et other avec le modulo ( qui sera l'ordre de la courbe SECP256K1)
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
        Ok(Field {index, bytes})
    }

    pub fn show(&self) {
        let hex = utils::to_hex(&self.bytes).map_err(|_| SyscallError::Overflow).unwrap();
        let m = from_utf8(&hex).map_err(|_| SyscallError::InvalidParameter).unwrap();
        ui::MessageScroller::new(m).event_loop();
    }
}