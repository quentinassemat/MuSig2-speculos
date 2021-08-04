// FICHIER QUI GÈRE L'IMPLÉMENTATION D'UN SIGNEUR POUR STOCKER LES DIFFÉRENTES ÉTAPES DE LA SIGNATURE
#![no_std]
#![no_main]

use data_types::*;
use crypto_helpers::*;

use core::str::from_utf8;

use nanos_sdk::bindings;
use nanos_sdk::buttons::ButtonEvent;
use nanos_sdk::ecc;
use nanos_sdk::io;
use nanos_sdk::io::SyscallError;
use nanos_ui::ui;

// CONSTANTES UTILES

pub const NB_NONCES: u32 = 3;
pub const NB_PARTICIPANT: u32 = 2;

pub const M: &str = "Alice donne 1 Bitcoin à Bob";


// WRAPPER AUTOUR DES TYPES UNSAFE :


// Struct simulant un signeur comme dans tools.py

//pt courbe elliptique : bindings::cx_ecpoint_t
//field : u32 qui envoie sur un tableau de u8
pub struct Signer {
    // éléments publiques
    pub public_key: Point,
    pub public_nonces: [Point; NB_NONCES],
    pub pubkeys: [Point; NB_PARTICIPANT],
    pub nonces: [[Point; NB_NONCES]; NB_PARTICIPANT], //Vec[i][j] est le nonce j du signeur i
    pub a: [Field; NB_PARTICIPANT],
    pub selfa: Field,
    pub xtilde: Point,
    pub r_nonces: [Point; NB_NONCES],
    pub b: Field,
    pub rsign: Field,
    pub c: Field,
    pub selfsign: Field,
    pub sign: [Field; NB_PARTICIPANT],

    //éléments secrets
    private_key: Field,
    private_nonces: [Field; NB_NONCES],
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

        let private_nonces: [Field; NB_NONCES] = [Field::new()?; NB_NONCES];

        let public_nonces: [Point; NB_NONCES] =
            [Point::new_gen()?; NB_NONCES];
        let pubkeys: [Point; NB_PARTICIPANT] =
            [Point::new()?; NB_PARTICIPANT];
        let nonces: [[Point; NB_NONCES]; NB_PARTICIPANT] =
            [[Point::new()?; NB_NONCES]; NB_PARTICIPANT];

        let a: [Field; NB_PARTICIPANT] = [Field::new()?; NB_PARTICIPANT];

        let selfa = Field::new()?;

        let xtilde = Point::new()?;
        let r_nonces: [Point; NB_NONCES] =
            [Point; NB_NONCES];

        let b: Field = Field::new()?;

        let rsign: Point = Point::new();

        let c: Field = Field::new();

        let selfsign: Field = Field::new();

        let sign: [Field; NB_PARTICIPANT] = [Field::new(); NB_PARTICIPANT];

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
    pub fn gen_r(&mut self) {
        for i in 0..NB_NONCES {
            //génération aléatoire de nonces privés de la même manière que la clef privée
            // idem nonces puliques et clefs publiques

            private_nonces[i] = Field::new_rand()?;
            public_nonces[i] = public_nonces[i].mul_scalar(private_nonces[i])?;
        }
    }

    //FONCTIONS DE CALCUL DU SIGNEUR

    //fonction calcul des ai
    pub fn a(&mut self) -> [Field ; NB_PARTICIPANT] {
        let mut a: [Field ; NB_PARTICIPANT] = [Field::new() ; NB_PARTICIPANT];
        for i in 0..NB_PARTICIPANT {
            let mut hash = Sha256::new();

            //on construit les bytes qui servent pour la hash
            let mut bytes: [u8 ; (NB_PARTICIPANT+1)*N_BYTES];
            for j in 0..NB_PARTICIPANT {
                bytes.extend(point_to_bytes_4hash(self.pubkeys[j as usize]));
            }
            bytes.extend(point_to_bytes_4hash(self.pubkeys[i as usize]));

            //on le met dans le hash
            hash.input(bytes.as_slice());
            let mut ai: [u8; 32] = [0; 32];
            hash.result(&mut ai);

            //On construit le Scalar qui corrrespond
            match ScalarBytes::try_from(&ai[..]) {
                Ok(ai_scal) => match Scalar::from_repr(ai_scal.into_bytes()) {
                    Some(x) => {
                        a.push(x);
                        if self.pubkeys[i as usize] == self.public_key {
                            self.selfa = x;
                        }
                    }
                    None => eprintln!("Erreur "),
                },
                Err(e) => eprintln!("Erreur : {:?}", e),
            }
        }
        a
    }

    // //fonction de calcul de x_tilde :
    // pub fn xtilde(&self) -> ProjectivePoint {
    //     let mut xtilde = ProjectivePoint::identity();
    //     for i in 0..NB_PARTICIPANT {
    //         xtilde = xtilde + (self.pubkeys[i as usize] * self.a[i as usize]);
    //     }
    //     xtilde
    // }

    // //fonction de calcul de r_nonces :
    // pub fn r_nonces(&self) -> Vec<ProjectivePoint> {
    //     let mut r_nonces: Vec<ProjectivePoint> = Vec::new();
    //     for j in 0..NB_NONCES {
    //         let mut temp = ProjectivePoint::identity();
    //         for i in 0..NB_PARTICIPANT {
    //             temp = temp + self.nonces[i as usize][j as usize];
    //         }
    //         r_nonces.push(temp);
    //     }
    //     r_nonces
    // }

    // //fonction de calcul de b :
    // pub fn b(&self) -> Scalar {
    //     let mut b = Scalar::one();
    //     let mut hash = Sha256::new();

    //     //on construit les bytes qui servent pour le hash
    //     let mut bytes: Vec<u8> = Vec::new();
    //     bytes.extend(point_to_bytes_4hash(self.xtilde));
    //     for j in 0..NB_NONCES {
    //         bytes.extend(point_to_bytes_4hash(self.r_nonces[j as usize]));
    //     }
    //     bytes.extend(M.bytes());

    //     //on le met dans le hash
    //     hash.input(bytes.as_slice());
    //     let mut bi: [u8; 32] = [0; 32];
    //     hash.result(&mut bi);

    //     //On construit le Scalar qui corrrespond
    //     match ScalarBytes::try_from(&bi[..]) {
    //         Ok(bi_scal) => match Scalar::from_repr(bi_scal.into_bytes()) {
    //             Some(x) => b = x,
    //             None => eprintln!("Erreur "),
    //         },
    //         Err(e) => eprintln!("Erreur : {:?}", e),
    //     }
    //     b
    // }

    // //fonction de calcul de R:
    // pub fn rsign(&self) -> ProjectivePoint {
    //     let mut rsign = ProjectivePoint::identity();
    //     let mut temp_b = Scalar::one();
    //     for j in 0..NB_NONCES {
    //         rsign = rsign + (self.r_nonces[j as usize] * (temp_b));
    //         temp_b = temp_b * self.b;
    //     }
    //     rsign
    // }

    // //fonction de calcul de c:
    // pub fn c(&self) -> Scalar {
    //     let mut hash = Sha256::new();
    //     let mut bytes: Vec<u8> = Vec::new();
    //     bytes.extend(point_to_bytes_4hash(self.xtilde));
    //     bytes.extend(point_to_bytes_4hash(self.rsign));
    //     bytes.extend(M.bytes());
    //     hash.input(bytes.as_slice());
    //     let mut b: [u8; 32] = [0; 32];
    //     hash.result(&mut b);
    //     let mut c = Scalar::zero();
    //     match ScalarBytes::try_from(&b[..]) {
    //         Ok(b_scal) => match Scalar::from_repr(b_scal.into_bytes()) {
    //             Some(x) => c = x,
    //             None => eprintln!("Erreur "),
    //         },
    //         Err(e) => eprintln!("Erreur : {:?}", e),
    //     }
    //     c
    // }

    // //fonction de calcul de sign :
    // pub fn selfsign(&self) -> Scalar {
    //     let mut temp = Scalar::zero();
    //     let mut temp_b = Scalar::one();
    //     for j in 0..NB_NONCES {
    //         temp = temp + (self.secret_list_r[j as usize] * temp_b);
    //         temp_b = temp_b * self.b;
    //     }
    //     (self.c * self.selfa * self.secret_key) + temp
    // }

    // pub fn signature(&self) -> Scalar {
    //     let mut signature = Scalar::zero();
    //     for i in 0..NB_PARTICIPANT {
    //         signature = signature + self.sign[i as usize];
    //     }
    //     println!("signature : {:?}", signature);
    //     signature
    // }

    // //fonction de vérif :
    // pub fn verif(&self) -> bool {
    //     let signature = self.signature();
    //     AffinePoint::from(ProjectivePoint::generator() * signature)
    //         == AffinePoint::from(self.rsign + (self.xtilde * self.c))
    // }

    // //fonction de debug
    // pub fn affich(&self) {
    //     println!("on va afficher tout les paramètres pour voir s'il y a un truc qui va pas");
    //     println!("public_key : {:?}", AffinePoint::from(self.public_key));
    //     println!("public_nonces : {:?}", self.public_nonces);
    //     println!("pubkeys : {:?}", self.pubkeys);
    //     println!("nonces : {:?}", self.nonces);
    //     println!("a: {:?}", self.a);
    //     println!("selfa : {:?}", self.selfa);
    //     println!("xtilde : {:?}", self.xtilde);
    //     println!("r_nonces : {:?}", self.r_nonces);
    //     println!("b : {:?}", self.b);
    //     println!("rsign : {:?}", self.rsign);
    //     println!("c : {:?}", self.c);
    //     println!("selfsign : {:?}", self.selfsign);
    //     println!("sign : {:?}", self.sign);
    //     println!("secret_key : {:?}", self.secret_key);
    //     println!("secret_list_r : {:?}", self.secret_list_r);
    // }
}

impl Default for Signer {
    fn default() -> Self {
        Self::new()
    }
}
