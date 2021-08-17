// FICHIER QUI GÈRE L'IMPLÉMENTATION D'UN SIGNEUR POUR STOCKER LES DIFFÉRENTES ÉTAPES DE LA SIGNATURE

use crate::cx_helpers::*;
use crate::data_types::*;

use hex_literal::hex;

// WRAPPER AUTOUR DES TYPES UNSAFE :

// Struct simulant un signeur comme dans tools.py

//pt courbe elliptique : bindings::cx_ecpoint_t
//field : u32 qui envoie sur un tableau de u8
pub struct Signer {
    // éléments publiques
    pub public_key: PointBytes,

    //éléments secrets
    private_key: FieldBytes,
}

// On fait deux struct temporaire de signer pour les deux round de MuSig2 (mem opt)
pub struct Signer1 {
    // éléments publiques
    pub public_key: PointBytes,
    pub public_nonces: [PointBytes; NB_NONCES as usize],
    pub pubkeys: [PointBytes; NB_PARTICIPANT as usize],
    pub nonces: [[PointBytes; NB_NONCES as usize]; NB_PARTICIPANT as usize], //Vec[i][j] est le nonce j du signeur i

    //éléments secrets
    private_nonces: [FieldBytes; NB_NONCES as usize],
    private_key: FieldBytes,
}

pub struct Signer2 {
    // éléments publiques
    pub a: [FieldBytes; NB_PARTICIPANT as usize],
    pub selfa: FieldBytes,
    pub xtilde: PointBytes,
    pub r_nonces: [PointBytes; NB_NONCES as usize],
    pub b: FieldBytes,
    pub rsign: PointBytes,
    pub c: FieldBytes,
    pub selfsign: FieldBytes,
    pub sign: [FieldBytes; NB_PARTICIPANT as usize],

    //éléments secrets
    private_nonces: [FieldBytes; NB_NONCES as usize],
    private_key: FieldBytes,
}

impl Signer {
    // constructeur
    pub fn new() -> Result<Signer, CxSyscallError> {
        cx_bn_lock(N_BYTES, 0)?;

        //gen secret_key
        let private_key: Field = Field::new_rand()?;

        // on génère la clef publique
        let mut public_key = Point::new_gen()?;
        public_key.mul_scalar(private_key)?;

        // on libère la ram crypto, on chargera quand on aura besoin de calculer

        Ok(Signer {
            public_key : public_key.into_ram()?,
            private_key : private_key.into_ram()?,
        })
    }

    // GETTERS EN APDU EXPORT

    pub fn get_pubkey(&self) -> Result<[u8; 65], CxSyscallError> {
        Ok(self.public_key.export_apdu()?)
    }
}

impl Signer1 {
    pub fn new(s: &Signer) -> Result<Signer1, CxSyscallError> {
        let private_nonces: [FieldBytes; NB_NONCES as usize] = [FieldBytes::new()?; NB_NONCES as usize];

        let public_nonces: [PointBytes; NB_NONCES as usize] =
            [PointBytes::new_gen()?; NB_NONCES as usize];

        let public_key = s.public_key;
        let private_key = s.private_key;

        // let x1 = hex!("23cdc4924412d491d0ed13272372e945ddd9886c32592f8ac9b7b37dcd8adc7d");
        // let y1 = hex!("20d88572e9fdbe872c1dbfbdb9921cb8d17af04a63b65646aa7bc29f42d16f41");
        // let pk1: PointBytes = PointBytes::new_init(&x1, &y1)?;

        // let x2 = hex!("79717b8ad6bd8efa41af00e682d97004be32738b54a30d2a0141eb2c2590baa0");
        // let y2 = hex!("bffee15e85c9be9478e34e251baa3a2e11aef8269d8b1a695ceb7ff177185fd8");
        // let pk2: PointBytes = PointBytes::new_init(&x2, &y2)?;

        let pubkeys: [PointBytes ; NB_PARTICIPANT as usize] = [PointBytes::new_gen()?; NB_PARTICIPANT as usize]; 

        let nonces: [[PointBytes; NB_NONCES as usize]; NB_PARTICIPANT as usize] =
            [[PointBytes::new_gen()?; NB_NONCES as usize]; NB_PARTICIPANT as usize];

        Ok(Signer1 {
            public_key,
            public_nonces,
            pubkeys,
            nonces,
            private_nonces,
            private_key,
        })
    }

    //fonction de génération des nonces privées
    pub fn gen_private_nonces(&mut self) -> Result<(), CxSyscallError> {
        for i in 0..NB_NONCES {
            //génération aléatoire de nonces privés de la même manière que la clef privée
            // idem nonces puliques et clefs publiques
            let private_nonce = Field::new_rand()?;
            let mut public_nonce = Point::new_gen()?;
            public_nonce.mul_scalar(private_nonce)?;
            nanos_sdk::debug_print("private/public nonces : \n");
            self.private_nonces[i as usize] = private_nonce.into_ram()?;
            self.private_nonces[i as usize].debug_show()?;
            self.public_nonces[i as usize] = public_nonce.into_ram()?;
            self.public_nonces[i as usize].debug_show()?;
        }
        Ok(())
    }

    // GETTERS EN APDU EXPORT

    pub fn get_public_nonces(&self) -> Result<[[u8; 65]; NB_NONCES as usize], CxSyscallError> {
        let init: [u8; 65] = [0; 65];
        let mut pn: [[u8; 65]; NB_NONCES as usize] = [init; NB_NONCES as usize];
        for i in 0..NB_NONCES {
            pn[i as usize] = self.public_nonces[i as usize].export_apdu()?;
        }
        Ok(pn)
    }

    // FONCTIONS RECEPTION

    pub fn recep_nonces(&mut self, data: &[u8]) -> Result<(), CxSyscallError> {

        let ind_joueur = data[0];
        for i in 0..NB_NONCES {
            self.nonces[ind_joueur as usize][i as usize] = PointBytes::new_init(
                &data[(2 + i as usize + i as usize * 2 * N_BYTES as usize)
                    ..(2 + i as usize + (i as usize * 2 + 1) * N_BYTES as usize)],
                &data[(2 + i as usize + (i as usize * 2 + 1) * N_BYTES as usize)
                    ..(2 + i as usize + (i as usize * 2 + 2) * N_BYTES as usize)],
            )?;
            nanos_sdk::debug_print("nonces : \n");
            self.nonces[ind_joueur as usize][i as usize].debug_show()?;
        }
        Ok(())
    }

    pub fn recep_pubkeys(&mut self, data: &[u8]) -> Result<(), CxSyscallError> {
        for i in 0..NB_PARTICIPANT {
            self.pubkeys[i as usize] = PointBytes::new_init(
                &data[(1 + i as usize + i as usize * 2 * N_BYTES as usize)
                    ..(1 + i as usize + (i as usize * 2 + 1) * N_BYTES as usize)],
                &data[(1 + i as usize + (i as usize * 2 + 1) * N_BYTES as usize)
                    ..(1 + i as usize + (i as usize * 2 + 2) * N_BYTES as usize)],
            )?;
            nanos_sdk::debug_print("pubkeys : \n");
            self.pubkeys[i as usize].debug_show()?;
        }
        Ok(())
    }

    // calcul de la prochaine struct
    pub fn next_round(self) -> Result<Signer2, CxSyscallError> {

        nanos_sdk::debug_print("private key : \n");
        self.private_key.debug_show()?;

        nanos_sdk::debug_print("public key: \n");
        self.public_key.debug_show()?;
        // pour les calculs

        let mod_bytes: [u8; N_BYTES as usize] = hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"); // mod = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        let modulo: Field = Field::new_init(&mod_bytes)?;

        // calcul des r_nonces
        nanos_sdk::debug_print("r_nonces : \n");

        let mut r_nonces: [PointBytes; NB_NONCES as usize] = [PointBytes::new_gen()?; NB_NONCES as usize];

        for j in 0..NB_NONCES {
            let mut copy = self.nonces[0 as usize][j as usize];
            let mut temp = copy.into_crypto_ram()?;
            for i in 1..NB_PARTICIPANT {
                copy = self.nonces[i as usize][j as usize];
                let add = copy.into_crypto_ram()?;
                temp = temp.add(add)?;
                add.destroy()?;
            }
            r_nonces[j as usize] = temp.into_ram()?;
            r_nonces[j as usize].debug_show()?;

        }

        // calcul des ai
        nanos_sdk::debug_print("ai : \n");

        let mut a: [FieldBytes; NB_PARTICIPANT as usize] = [FieldBytes::new()?; NB_PARTICIPANT as usize];
        let mut selfa = FieldBytes::new()?;
        for i in 0..NB_PARTICIPANT {
            let mut hash = Hash::new()?;

            //on construit les bytes qui servent pour la hash
            let mut bytes: [u8; (NB_PARTICIPANT as usize + 1_usize) * N_BYTES as usize] =
                [0; (NB_PARTICIPANT as usize + 1_usize) * N_BYTES as usize];
            for j in 0..NB_PARTICIPANT {
                let fill = self.pubkeys[j as usize].x_bytes;
                for k in 0..N_BYTES {
                    bytes[(N_BYTES as usize * j as usize) + k as usize] = fill[k as usize];
                }
            }

            let fill = self.pubkeys[i as usize].x_bytes;
            for k in 0..N_BYTES {
                bytes[(N_BYTES as usize * NB_PARTICIPANT as usize) + k as usize] = fill[k as usize];
            }

            //on le met dans le hash
            hash.update(&bytes, bytes.len() as u32)?;
            let ai_bytes = hash.digest()?;

            a[i as usize] = FieldBytes::new_init(&ai_bytes)?;
            if self.pubkeys[i as usize] == self.public_key {
                selfa = FieldBytes::new_init(&ai_bytes)?;
                selfa.debug_show()?;
            }
            a[i as usize].debug_show()?;
        }

        // calcul du xtilde

        nanos_sdk::debug_print("xtilde : \n");

        let copy = self.pubkeys[0 as usize];
        let mut xtilde_crypto = copy.into_crypto_ram()?;
        let copy = a[0 as usize];
        let mul = copy.into_crypto_ram()?;
        xtilde_crypto.mul_scalar(mul)?;
        mul.destroy()?;
        for i in 1..NB_PARTICIPANT {
            let copy = self.pubkeys[i as usize];
            let mut add = copy.into_crypto_ram()?;
            let copy = a[i as usize];
            let ai = copy.into_crypto_ram()?;
            add.mul_scalar(ai)?;
            xtilde_crypto = xtilde_crypto.add(add)?;
            add.destroy()?;
            ai.destroy()?;
        }
        let xtilde = xtilde_crypto.into_ram()?;
        xtilde.debug_show()?;

        // calcul de b
        nanos_sdk::debug_print("b : \n");

        let mut b = FieldBytes::new()?;
        {
            let mut hash = Hash::new()?;

            //on construit les bytes qui servent pour le hash
            let mut bytes: [u8; (NB_NONCES as usize + 1_usize) * N_BYTES as usize
                + M.as_bytes().len()] =
                [0; (NB_NONCES as usize + 1_usize) * N_BYTES as usize + M.as_bytes().len()];
    
            let fill = xtilde.x_bytes;
            for k in 0..N_BYTES {
                bytes[k as usize] = fill[k as usize];
            }
            for j in 0..NB_NONCES {
                let fill = r_nonces[j as usize].x_bytes;
                for k in 0..N_BYTES {
                    bytes[((j as usize + 1) * N_BYTES as usize) + k as usize] = fill[k as usize];
                }
            }
            for k in 0..M.as_bytes().len() {
                bytes[(NB_NONCES as usize + 1_usize) * N_BYTES as usize + k as usize] =
                    M.as_bytes()[k as usize];
            }
            //on le met dans le hash
            hash.update(&bytes, bytes.len() as u32)?;
            let b_bytes: [u8; 32] = hash.digest()?;

            //On construit le Scalar qui corrrespond
            b = FieldBytes::new_init(&b_bytes)?;
        }
        b.debug_show()?;
        

        //calcul de rsign

        nanos_sdk::debug_print("rsign : \n");

        let mut rsign = PointBytes::new_gen()?;
        {
            let copy_rsign = r_nonces[0 as usize];
            let mut rsign_crypto = copy_rsign.into_crypto_ram()?;

            let b_copy = b;
            let mut temp_b: Field = b_copy.into_crypto_ram()?;
            let b_copy = b;
            let b_crypto = b_copy.into_crypto_ram()?;
            for j in 1..NB_NONCES {
                let copy = r_nonces[j as usize];
                let mut mul = copy.into_crypto_ram()?;
                mul.mul_scalar(temp_b)?;
                rsign_crypto = rsign_crypto.add(mul)?;
                temp_b = temp_b.mul(b_crypto, modulo)?;
                mul.destroy()?;
            }
            rsign = rsign_crypto.into_ram()?;

            //destroy
            temp_b.destroy()?;
            b_crypto.destroy()?;
        }
        rsign.debug_show()?;


        //calcul de c

        nanos_sdk::debug_print("c : \n");

        let mut c = FieldBytes::new()?;
        {
            let mut hash = Hash::new()?;
            let mut bytes: [u8; 2 * N_BYTES as usize + M.as_bytes().len()] =
                [0; 2 * N_BYTES as usize + M.as_bytes().len()];
            let fill = xtilde.x_bytes;
            for k in 0..N_BYTES {
                bytes[k as usize] = fill[k as usize];
            }
            let fill = rsign.x_bytes;
            for k in 0..N_BYTES {
                bytes[k as usize + N_BYTES as usize] = fill[k as usize];
            }
            for k in 0..M.as_bytes().len() {
                bytes[2 * N_BYTES as usize + k as usize] = M.as_bytes()[k as usize];
            }
            hash.update(&bytes, bytes.len() as u32)?;
            let c_bytes = hash.digest()?;
            c = FieldBytes::new_init(&c_bytes)?;
        }
        c.debug_show()?;

        //calcul de selfsign
        nanos_sdk::debug_print("selfsign : \n");

        let mut selfsign = FieldBytes::new()?;
        {
            let b_copy = b;
            let mut temp_b = b_copy.into_crypto_ram()?; 
            let b_copy = b;
            let b_crypto = b_copy.into_crypto_ram()?; 
            let mut copy = self.private_nonces[0 as usize];
            let mut temp = copy.into_crypto_ram()?;
            for j in 1..NB_NONCES {
                copy = self.private_nonces[j as usize];
                let mut mul = copy.into_crypto_ram()?;
                mul = mul.mul(temp_b, modulo)?;
                temp = temp.add(mul, modulo)?;
                temp_b = temp_b.mul(b_crypto, modulo)?;
            }
            let pk_copy = self.private_key;
            let sa_copy = selfa;
            let c_copy = c;
            let mut mul = c_copy.into_crypto_ram()?;
            mul = mul.mul(sa_copy.into_crypto_ram()?, modulo)?;
            mul = mul.mul(pk_copy.into_crypto_ram()?, modulo)?;
            selfsign = (mul.add(temp, modulo)?).into_ram()?;

            //destroy
            temp.destroy()?;
            temp_b.destroy()?;
            b_crypto.destroy()?;
        }

        selfsign.debug_show()?;

        //init de sign

        let sign = [FieldBytes::new()?; NB_PARTICIPANT as usize];

        //destroy
        modulo.destroy()?;

        Ok(Signer2 {
            a,
            selfa,
            xtilde,
            r_nonces,
            b,
            rsign,
            c,
            selfsign,
            sign,
            private_nonces: self.private_nonces,
            private_key: self.private_key,
        })
    }
}

impl Signer2 {
    pub fn get_sign(&self) -> Result<[u8; N_BYTES as usize], CxSyscallError> {
        Ok(self.selfsign.bytes)
    }

    pub fn recep_signs(&mut self, data: &[u8]) -> Result<(), CxSyscallError> {
        for i in 0..NB_PARTICIPANT {
            self.sign[i as usize] = FieldBytes::new_init(&data[(i as usize * N_BYTES as usize)
            ..((i as usize + 1_usize) * N_BYTES as usize)])?;
        }
        Ok(())
    }

    pub fn signature(&self) -> Result<FieldBytes, CxSyscallError> {
        let mod_bytes: [u8; N_BYTES as usize] =
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"); // mod = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        let modulo: Field = Field::new_init(&mod_bytes)?;

        let mut copy = self.sign[0 as usize];
        let mut sign_crypto = copy.into_crypto_ram()?;

        for i in 1..NB_PARTICIPANT {
            copy = self.sign[i as usize];
            sign_crypto = sign_crypto.add(copy.into_crypto_ram()?, modulo)?;
        }

        let signature = sign_crypto.into_ram()?;
        nanos_sdk::debug_print("signature : \n");
        signature.debug_show()?;

        //destroy
        modulo.destroy()?;
        Ok(signature)
    }

    //fonction de vérif :
    pub fn verif(&self) -> Result<bool, CxSyscallError> {
        let copy = self.signature()?;
        let mut signature_crypto = copy.into_crypto_ram()?;
        let mut left_crypto = Point::new_gen()?;
        left_crypto.mul_scalar(signature_crypto)?;
        let left = left_crypto.into_ram()?;

        let mut xtilde_copy = self.xtilde;
        let c_copy = self.c;
        let mut xtilde_crypto = xtilde_copy.into_crypto_ram()?;
        xtilde_crypto.mul_scalar(c_copy.into_crypto_ram()?)?;
        let rsign_copy = self.rsign;
        let mut right_crypto = rsign_copy.into_crypto_ram()?;
        right_crypto = right_crypto.add(xtilde_crypto)?;
        let right = right_crypto.into_ram()?;

        Ok(left == right)
    }
}
