// FICHIER QUI GÈRE L'IMPLÉMENTATION D'UN SIGNEUR POUR STOCKER LES DIFFÉRENTES ÉTAPES DE LA SIGNATURE

use crate::data_types::*;
use crate::cx_helpers::*;

use hex_literal::hex;


// WRAPPER AUTOUR DES TYPES UNSAFE :


// Struct simulant un signeur comme dans tools.py

//pt courbe elliptique : bindings::cx_ecpoint_t
//field : u32 qui envoie sur un tableau de u8
pub struct Signer {
    // éléments publiques
    pub public_key: Point,
    pub public_nonces: [Point; NB_NONCES as usize],
    pub pubkeys: [Point; NB_PARTICIPANT as usize],
    pub nonces: [[Point; NB_NONCES as usize]; NB_PARTICIPANT as usize], //Vec[i][j] est le nonce j du signeur i
    pub a: [Field; NB_PARTICIPANT as usize],
    pub selfa: Field,
    pub xtilde: Point,
    pub r_nonces: [Point; NB_NONCES as usize],
    pub b: Field,
    pub rsign: Point,
    pub c: Field,
    pub selfsign: Field,
    pub sign: [Field; NB_PARTICIPANT as usize],

    //éléments secrets
    private_key: Field,
    private_nonces: [Field; NB_NONCES as usize],
}

impl Signer {
    // constructeur
    pub fn new() -> Result<Signer, CxSyscallError> {
        cx_bn_lock(N_BYTES, 0)?; 

        //gen secret_key
        let mut private_key: Field = Field::new_rand()?;

        // on génère la clef publique
        let mut public_key = Point::new_gen()?;
        public_key.mul_scalar(private_key)?;

        let mut private_nonces: [Field; NB_NONCES as usize] = [Field::new()?; NB_NONCES as usize];

        let mut public_nonces: [Point; NB_NONCES as usize] =
            [Point::new_gen()?; NB_NONCES as usize];
        let mut pubkeys: [Point; NB_PARTICIPANT as usize] =
            [Point::new()?; NB_PARTICIPANT as usize]; // à init différemment quand on a les clefs publiques de tous les speculos
        let mut nonces: [[Point; NB_NONCES as usize]; NB_PARTICIPANT as usize] =
            [[Point::new()?; NB_NONCES as usize]; NB_PARTICIPANT as usize];

        let mut a: [Field; NB_PARTICIPANT as usize] = [Field::new()?; NB_PARTICIPANT as usize];

        let mut selfa = Field::new()?;

        let mut xtilde = Point::new()?;
        let mut r_nonces: [Point; NB_NONCES as usize] =
            [Point::new()?; NB_NONCES as usize];

        let mut b: Field = Field::new()?;

        let mut rsign: Point = Point::new()?;

        let mut c: Field = Field::new()?;

        let mut selfsign: Field = Field::new()?;

        let mut sign: [Field; NB_PARTICIPANT as usize] = [Field::new()?; NB_PARTICIPANT as usize];

        // // on libère la ram crypto, on chargera quand on aura besoin de calculer
        // public_key.clear_crypto_ram()?;
        // selfa.clear_crypto_ram()?;
        // xtilde.clear_crypto_ram()?;
        // b.clear_crypto_ram()?;
        // selfsign.clear_crypto_ram()?;
        // private_key.clear_crypto_ram()?;
        // for i in 0..NB_NONCES {
        //     public_nonces[i as usize].clear_crypto_ram()?;
        //     r_nonces[i as usize].clear_crypto_ram()?;
        //     private_nonces[i as usize].clear_crypto_ram()?;
        //     for j in 0..NB_PARTICIPANT {
        //         nonces[i as usize][j as usize].clear_crypto_ram()?;
        //     }
        // }
        // for i in 0..NB_PARTICIPANT {
        //     pubkeys[i as usize].clear_crypto_ram()?;
        //     a[i as usize].clear_crypto_ram()?;
        //     sign[i as usize].clear_crypto_ram()?;
        // }

        Ok(Signer {
            public_key,
            public_nonces,
            pubkeys,
            nonces,
            a,
            selfa,
            xtilde,
            r_nonces,
            b,
            rsign,
            c,
            selfsign,
            sign,
            private_key,
            private_nonces,
        })
    }

    //fonction de génération des nonces privées
    pub fn gen_private_nonces(&mut self) -> Result<(), CxSyscallError> {
        for i in 0..NB_NONCES {
            //génération aléatoire de nonces privés de la même manière que la clef privée
            // idem nonces puliques et clefs publiques

            self.private_nonces[i as usize] = Field::new_rand()?;
            self.private_nonces[i as usize].clear_crypto_ram()?;
            self.public_nonces[i as usize].mul_scalar(self.private_nonces[i as usize])?;
            self.public_nonces[i as usize].clear_crypto_ram()?;
        }
        Ok(())
    }

    // GETTERS EN APDU EXPORT 

    pub fn get_pubkey(&self) -> Result<[u8; 65], CxSyscallError> {
        Ok(self.public_key.export_apdu()?)
    }

    pub fn get_public_nonces(&self) -> Result<[[u8;65]; NB_NONCES as usize], CxSyscallError> {
        let init: [u8; 65] = [0; 65];
        let mut pn: [[u8; 65]; NB_NONCES as usize] = [init; NB_NONCES as usize];
        for i in 0..NB_NONCES {
            pn[i as usize] = self.public_nonces[i as usize].export_apdu()?;
        }
        Ok(pn)
        // Ok(self.public_nonces[usize].export_apdu()?)
    }

    // FONCTIONS RECEPTION

    pub fn recep_nonces(&mut self, data: &[u8]) -> Result<(), CxSyscallError> {
        let ind_joueur = data[0];
        for i in 0..NB_NONCES {
            self.nonces[ind_joueur as usize][i as usize] = Point::new_init(&data[(2 + i as usize + i as usize * 2 * N_BYTES as usize)..(2 + i as usize + (i as usize * 2 + 1) * N_BYTES as usize)], &data[(2 + i as usize + (i as usize * 2 + 1) * N_BYTES as usize)..(2 + i as usize + (i as usize * 2 + 2) * N_BYTES as usize)])?;
            self.nonces[ind_joueur as usize][i as usize].clear_crypto_ram()?;
        }
        Ok(())
    }

    //FONCTIONS DE CALCUL DU SIGNEUR

    //fonction calcul des ai
    pub fn a(&mut self) -> Result<[Field ; NB_PARTICIPANT as usize], CxSyscallError> {
        let mut a: [Field ; NB_PARTICIPANT as usize] = [Field::new()? ; NB_PARTICIPANT as usize];
        for i in 0..NB_PARTICIPANT {
            let mut hash = Hash::new()?;

            //on construit les bytes qui servent pour la hash
            let mut bytes: [u8 ; (NB_PARTICIPANT as usize + 1_usize) * N_BYTES as usize] = [0 ; (NB_PARTICIPANT as usize + 1_usize) * N_BYTES as usize];
            for j in 0..NB_PARTICIPANT {
                let x = self.pubkeys[j as usize].x_affine()?;
                let fill = x.bytes;
                for k in 0..N_BYTES {
                    bytes[(N_BYTES as usize * j as usize) + k as usize] = fill[k as usize];
                }
            }

            let x = self.pubkeys[i as usize].x_affine()?;
            let fill = x.bytes;
            for k in 0..N_BYTES {
                bytes[(N_BYTES as usize * NB_PARTICIPANT as usize ) + k as usize] = fill[k as usize];
            }

            //on le met dans le hash
            hash.update(&bytes, bytes.len() as u32)?;
            let ai_bytes = hash.digest()?;

            a[i as usize] = Field::new_init(&ai_bytes)?;
            if self.pubkeys[i as usize] == self.public_key {
                self.selfa = Field::new_init(&ai_bytes)?;
            }
        }
        Ok(a)
    }

    //fonction de calcul de x_tilde :
    pub fn xtilde(&self) -> Result<Point, CxSyscallError> {
        let mut xtilde = self.pubkeys[0 as usize];
        xtilde.mul_scalar(self.a[0 as usize])?;
        for i in 1..NB_PARTICIPANT {
            let mut add = self.pubkeys[i as usize];
            add.mul_scalar(self.a[i as usize])?;
            xtilde.add(add)?;
        }
        Ok(xtilde)
    }

    //fonction de calcul de r_nonces :
    pub fn r_nonces(&self) -> Result<[Point; NB_NONCES as usize], CxSyscallError> {
        let mut r_nonces: [Point; NB_NONCES as usize] = [Point::new()?; NB_NONCES as usize];
        for j in 0..NB_NONCES {
            let mut temp = self.nonces[0 as usize][j as usize];
            for i in 1..NB_PARTICIPANT {
                temp = temp.add(self.nonces[i as usize][j as usize])? ;
            }
            r_nonces[j as usize] = temp;
        }
        Ok(r_nonces)
    }

    //fonction de calcul de b :
    pub fn b(&self) -> Result<Field, CxSyscallError> {
        let b_bytes: [u8; N_BYTES as usize] =
        hex!("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001"); // = 1
        let b: Field = Field::new_init(&b_bytes)?;

        let mut hash = Hash::new()?;

        //on construit les bytes qui servent pour le hash
        let mut bytes: [u8; (NB_NONCES as usize + 1_usize) * N_BYTES as usize + M.as_bytes().len()] = [0 ; (NB_NONCES as usize + 1_usize) * N_BYTES as usize + M.as_bytes().len()];

        let x = self.xtilde.x_affine()?;
        let fill = x.bytes;
        for k in 0..N_BYTES {
            bytes[k as usize] = fill[k as usize];
        }
        
        for j in 0..NB_NONCES {
            let x = self.r_nonces[j as usize].x_affine()?;
            let fill = x.bytes;
            for k in 0..N_BYTES {
                bytes[( (j as usize + 1) * N_BYTES as usize) + k as usize] = fill[k as usize];
            }
        }

        for k in 0..M.as_bytes().len() {
            bytes[(NB_NONCES as usize + 1_usize) * N_BYTES as usize + k as usize] = M.as_bytes()[k as usize];
        }

        //on le met dans le hash
        hash.update(&bytes, bytes.len() as u32)?;
        let b_bytes: [u8; 32] = hash.digest()?;

        //On construit le Scalar qui corrrespond   
        let b = Field::new_init(&b_bytes)?;
        Ok(b)
    }

    //fonction de calcul de R:
    pub fn rsign(&self) -> Result<Point, CxSyscallError> {
        let mod_bytes: [u8; N_BYTES as usize] =
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"); // mod = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        let modulo: Field = Field::new_init(&mod_bytes)?;

        let mut rsign = self.r_nonces[0 as usize];
        let mut temp_b: Field = self.b;
        for j in 1..NB_NONCES {
            let mut mul = self.r_nonces[j as usize];
            mul.mul_scalar(temp_b)?;
            rsign = rsign.add(mul)?;
            temp_b = temp_b.mul(self.b, modulo)?;
        }
        Ok(rsign)
    }

    //fonction de calcul de c:
    pub fn c(&self) -> Result<Field, CxSyscallError> {
        let mut hash = Hash::new()?;
        let mut bytes: [u8; 2 * N_BYTES as usize + M.as_bytes().len()] = [0; 2 * N_BYTES as usize + M.as_bytes().len()];
        let x = self.xtilde.x_affine()?;
        let fill = x.bytes;
        for k in 0..N_BYTES {
            bytes[k as usize] = fill[k as usize];
        }
        let x = self.rsign.x_affine()?;
        let fill = x.bytes;
        for k in 0..N_BYTES {
            bytes[k as usize + N_BYTES as usize] = fill[k as usize];
        }
        for k in 0..M.as_bytes().len() {
            bytes[2 * N_BYTES as usize + k as usize] = M.as_bytes()[k as usize];
        }
        hash.update(&bytes, bytes.len() as u32)?;
        let c_bytes = hash.digest()?;
        let c = Field::new_init(&c_bytes)?;
        Ok(c)
    }

    //fonction de calcul de sign :
    pub fn selfsign(&self) -> Result<Field, CxSyscallError> {

        let mod_bytes: [u8; N_BYTES as usize] =
        hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"); // mod = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        let modulo: Field = Field::new_init(&mod_bytes)?;

        let mut temp_b: Field = self.b;
        let mut temp = self.private_nonces[0 as usize];
        for j in 1..NB_NONCES {
            temp = temp.add(self.private_nonces[j as usize].mul(temp_b, modulo)?, modulo)?;
            temp_b = temp_b.mul(self.b, modulo)?;
        }
        Ok((self.c.mul(self.selfa.mul(self.private_key, modulo)?, modulo)?).add(temp, modulo)?)
    }

    pub fn signature(&self) -> Result<Field, CxSyscallError> {
        let mod_bytes: [u8; N_BYTES as usize] =
        hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"); // mod = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        let modulo: Field = Field::new_init(&mod_bytes)?;

        let mut signature = self.sign[0 as usize];
        for i in 1..NB_PARTICIPANT {
            signature = signature.add(self.sign[i as usize], modulo)?;
        }
        Ok(signature)
    }

    //fonction de vérif :
    pub fn verif(&self) -> Result<bool, CxSyscallError> {
        let signature = self.signature()?;
        let mut gen = Point::new_gen()?;
        gen.mul_scalar(signature)?;
        let mut xtilde_copy = self.xtilde;
        xtilde_copy.mul_scalar(self.c)?;
        Ok(gen == self.rsign.add(xtilde_copy)?)
    }
}

