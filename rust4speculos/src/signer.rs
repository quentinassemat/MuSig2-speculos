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
    pub public_key: Point,

    //éléments secrets
    private_key: Field,
}

// On fait deux struct temporaire de signer pour les deux round de MuSig2 (mem opt)
pub struct Signer1 {
    // éléments publiques
    pub public_key: Point,
    pub public_nonces: [Point; NB_NONCES as usize],
    pub pubkeys: [Point; NB_PARTICIPANT as usize],
    pub nonces: [[Point; NB_NONCES as usize]; NB_PARTICIPANT as usize], //Vec[i][j] est le nonce j du signeur i

    //éléments secrets
    private_nonces: [Field; NB_NONCES as usize],
    private_key: Field,
}

pub struct Signer2 {
    // éléments publiques
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
    private_nonces: [Field; NB_NONCES as usize],
    private_key: Field,
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

        // on libère la ram crypto, on chargera quand on aura besoin de calculer

        Ok(Signer {
            public_key,
            private_key,
        })
    }

    // GETTERS EN APDU EXPORT

    pub fn get_pubkey(&self) -> Result<[u8; 65], CxSyscallError> {
        Ok(self.public_key.export_apdu()?)
    }
}

impl Signer1 {
    pub fn new(s: &Signer) -> Result<Signer1, CxSyscallError> {
        let mut private_nonces: [Field; NB_NONCES as usize] = [Field::new()?; NB_NONCES as usize];

        let mut public_nonces: [Point; NB_NONCES as usize] =
            [Point::new_gen()?; NB_NONCES as usize];

        let mut public_key = s.public_key;
        let mut private_key = s.private_key;

        let x1 = hex!("23cdc4924412d491d0ed13272372e945ddd9886c32592f8ac9b7b37dcd8adc7d");
        let y1 = hex!("20d88572e9fdbe872c1dbfbdb9921cb8d17af04a63b65646aa7bc29f42d16f41");
        let pk1: Point = Point::new_init(&x1, &y1)?;

        let x2 = hex!("79717b8ad6bd8efa41af00e682d97004be32738b54a30d2a0141eb2c2590baa0");
        let y2 = hex!("bffee15e85c9be9478e34e251baa3a2e11aef8269d8b1a695ceb7ff177185fd8");
        let pk2: Point = Point::new_init(&x2, &y2)?;

        // initialisation de la liste des clefs publiques à la main avec les deux spéculos pour simulé qu'on les as déjà
        let mut pubkeys: [Point; NB_PARTICIPANT as usize] = [pk1, pk2]; // à init différemment quand on a les clefs publiques de tous les speculos

        let mut nonces: [[Point; NB_NONCES as usize]; NB_PARTICIPANT as usize] =
            [[Point::new()?; NB_NONCES as usize]; NB_PARTICIPANT as usize];

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

            self.private_nonces[i as usize] = Field::new_rand()?;
            self.public_nonces[i as usize].mul_scalar(self.private_nonces[i as usize])?;
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
                
        // clear crypto ram

        for i in 0..NB_NONCES {
            self.public_nonces[i as usize].destroy()?;
        }

        let ind_joueur = data[0];
        for i in 0..NB_NONCES {
            self.nonces[ind_joueur as usize][i as usize] = Point::new_init(
                &data[(2 + i as usize + i as usize * 2 * N_BYTES as usize)
                    ..(2 + i as usize + (i as usize * 2 + 1) * N_BYTES as usize)],
                &data[(2 + i as usize + (i as usize * 2 + 1) * N_BYTES as usize)
                    ..(2 + i as usize + (i as usize * 2 + 2) * N_BYTES as usize)],
            )?;
        }
        Ok(())
    }

    // calcul de la prochaine struct
    pub fn next_round(self) -> Result<Signer2, CxSyscallError> {
        nanos_sdk::debug_print("debug1");
        // calcul des r_nonces
        let mut r_nonces: [Point; NB_NONCES as usize] = [Point::new()?; NB_NONCES as usize];

        for j in 0..NB_NONCES {
            let mut temp = self.nonces[0 as usize][j as usize];
            for i in 1..NB_PARTICIPANT {
                temp = temp.add(self.nonces[i as usize][j as usize])?;
            }
            r_nonces[j as usize] = temp;
        }

        nanos_sdk::debug_print("debug2");
        // clear crypto ram

        for i in 0..NB_PARTICIPANT {
            for j in 0..NB_NONCES {
                self.nonces[i as usize][j as usize].destroy()?;
            }
        }

        nanos_sdk::debug_print("debug3");

        // calcul des ai
        let mut a: [Field; NB_PARTICIPANT as usize] = [Field::new()?; NB_PARTICIPANT as usize];
        let mut selfa = Field::new()?;
        for i in 0..NB_PARTICIPANT {
            let mut hash = Hash::new()?;

            //on construit les bytes qui servent pour la hash
            let mut bytes: [u8; (NB_PARTICIPANT as usize + 1_usize) * N_BYTES as usize] =
                [0; (NB_PARTICIPANT as usize + 1_usize) * N_BYTES as usize];
            for j in 0..NB_PARTICIPANT {
                let x = (self.pubkeys[j as usize].x_affine()?).into_ram()?;
                let fill = x.bytes;
                for k in 0..N_BYTES {
                    bytes[(N_BYTES as usize * j as usize) + k as usize] = fill[k as usize];
                }
            }

            let x = (self.pubkeys[i as usize].x_affine()?).into_ram()?;
            let fill = x.bytes;
            for k in 0..N_BYTES {
                bytes[(N_BYTES as usize * NB_PARTICIPANT as usize) + k as usize] = fill[k as usize];
            }

            //on le met dans le hash
            hash.update(&bytes, bytes.len() as u32)?;
            let ai_bytes = hash.digest()?;

            a[i as usize] = Field::new_init(&ai_bytes)?;
            if self.pubkeys[i as usize] == self.public_key {
                selfa = Field::new_init(&ai_bytes)?;
            }
        }


        nanos_sdk::debug_print("debug4");

        // calcul du xtilde
        let mut xtilde = self.pubkeys[0 as usize];
        xtilde.mul_scalar(a[0 as usize])?;
        for i in 1..NB_PARTICIPANT {
            let mut add = self.pubkeys[i as usize];
            add.mul_scalar(a[i as usize])?;
            xtilde.add(add)?;
        }

        // clear crypto ram

        nanos_sdk::debug_print("debug5");

        for i in 0..NB_PARTICIPANT {
            self.pubkeys[i as usize].destroy()?;
        }

        // calcul de b
        let mut b = Field::new()?;
        {
            let mut hash = Hash::new()?;

            //on construit les bytes qui servent pour le hash
            let mut bytes: [u8; (NB_NONCES as usize + 1_usize) * N_BYTES as usize
                + M.as_bytes().len()] =
                [0; (NB_NONCES as usize + 1_usize) * N_BYTES as usize + M.as_bytes().len()];
    
            nanos_sdk::debug_print("debug6");
            let x = (xtilde.x_affine()?).into_ram()?;
            nanos_sdk::debug_print("debug61");
            let fill = x.bytes;
            for k in 0..N_BYTES {
                bytes[k as usize] = fill[k as usize];
            }
            nanos_sdk::debug_print("debug7");
            for j in 0..NB_NONCES {
                let x = (r_nonces[j as usize].x_affine()?).into_ram()?;
                let fill = x.bytes;
                for k in 0..N_BYTES {
                    bytes[((j as usize + 1) * N_BYTES as usize) + k as usize] = fill[k as usize];
                }
            }
            nanos_sdk::debug_print("debug8");
            for k in 0..M.as_bytes().len() {
                bytes[(NB_NONCES as usize + 1_usize) * N_BYTES as usize + k as usize] =
                    M.as_bytes()[k as usize];
            }
            nanos_sdk::debug_print("debug9");
            //on le met dans le hash
            hash.update(&bytes, bytes.len() as u32)?;
            let b_bytes: [u8; 32] = hash.digest()?;

            //On construit le Scalar qui corrrespond
            b = Field::new_init(&b_bytes)?;
        }
        

        //calcul de rsign
        let mut rsign = r_nonces[0 as usize];
        {
            let mod_bytes: [u8; N_BYTES as usize] = hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"); // mod = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
            let modulo: Field = Field::new_init(&mod_bytes)?;

            let mut temp_b: Field = b;
            for j in 1..NB_NONCES {
                let mut mul = r_nonces[j as usize];
                mul.mul_scalar(temp_b)?;
                rsign = rsign.add(mul)?;
                temp_b = temp_b.mul(b, modulo)?;
            }
        }


        nanos_sdk::debug_print("debug6");

        //calcul de c
        let mut c = Field::new()?;
        nanos_sdk::debug_print("debug60");
        {
            let mut hash = Hash::new()?;
            nanos_sdk::debug_print("debug60b");
            let mut bytes: [u8; 2 * N_BYTES as usize + M.as_bytes().len()] =
                [0; 2 * N_BYTES as usize + M.as_bytes().len()];
            nanos_sdk::debug_print("debug61");
            let x = (xtilde.x_affine()?).into_ram()?;
            let fill = x.bytes;
            for k in 0..N_BYTES {
                bytes[k as usize] = fill[k as usize];
            }
            nanos_sdk::debug_print("debug62");
            let x = (rsign.x_affine()?).into_ram()?;
            nanos_sdk::debug_print("debug63");
            let fill = x.bytes;
            for k in 0..N_BYTES {
                bytes[k as usize + N_BYTES as usize] = fill[k as usize];
            }
            for k in 0..M.as_bytes().len() {
                bytes[2 * N_BYTES as usize + k as usize] = M.as_bytes()[k as usize];
            }
            nanos_sdk::debug_print("debug64");
            hash.update(&bytes, bytes.len() as u32)?;
            let c_bytes = hash.digest()?;
            c = Field::new_init(&c_bytes)?;
        }
        nanos_sdk::debug_print("debug7");

        //init de sign et selfsign

        let sign = [Field::new()?; NB_PARTICIPANT as usize];
        let selfsign = Field::new()?;

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
        Ok((self
            .c
            .mul(self.selfa.mul(self.private_key, modulo)?, modulo)?)
        .add(temp, modulo)?)
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

    pub fn end_sign(self) -> Result<(), CxSyscallError> {
        for i in 0..NB_PARTICIPANT {
            self.a[i as usize].destroy()?;
            self.sign[i as usize].destroy()?;
        }
        for i in 0..NB_NONCES {
            self.private_nonces[i as usize].destroy()?;
            self.r_nonces[i as usize].destroy()?;
        }
        self.selfa.destroy()?;
        self.xtilde.destroy()?;
        self.b.destroy()?;
        self.rsign.destroy()?;
        self.c.destroy()?;
        self.selfsign.destroy()?;
        self.private_key.destroy()?;
        Ok(())
    }
}
