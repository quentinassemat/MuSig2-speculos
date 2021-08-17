use nanos_sdk::bindings;
use nanos_sdk::io::Reply;

// WRAPPERS AUTOUR DES MESSAGES D'ERREURS

#[derive(Debug)]
#[repr(u32)]
pub enum CxSyscallError {
    Locked = bindings::CX_LOCKED,
    Unlocked = bindings::CX_UNLOCKED,
    NotLocked = bindings::CX_NOT_LOCKED,
    InternalError = bindings::CX_INTERNAL_ERROR,
    InvalidParameterSize = bindings::CX_INVALID_PARAMETER_SIZE,
    InvalidParameterValue = bindings::CX_INVALID_PARAMETER_VALUE,
    InvalidParameter = bindings::CX_INVALID_PARAMETER,
    NotInvertible = bindings::CX_NOT_INVERTIBLE,
    Overflow = bindings::CX_OVERFLOW,
    MemoryFull = bindings::CX_MEMORY_FULL,
    NoResidue = bindings::CX_NO_RESIDUE,
    EcInfinitePoint = bindings::CX_EC_INFINITE_POINT,
    EcInvalidPoint = bindings::CX_EC_INVALID_POINT,
    EcInvalidCurve = bindings::CX_EC_INVALID_CURVE,
    Unspecified,
}

impl From<u32> for CxSyscallError {
    fn from(e: u32) -> CxSyscallError {
        match e {
            bindings::CX_LOCKED => CxSyscallError::Locked,
            bindings::CX_UNLOCKED => CxSyscallError::Unlocked,
            bindings::CX_NOT_LOCKED => CxSyscallError::NotLocked,
            bindings::CX_INTERNAL_ERROR => CxSyscallError::InternalError,
            bindings::CX_INVALID_PARAMETER_SIZE => CxSyscallError::InvalidParameterSize,
            bindings::CX_INVALID_PARAMETER_VALUE => CxSyscallError::InvalidParameterValue,
            bindings::CX_INVALID_PARAMETER => CxSyscallError::InvalidParameter,
            bindings::CX_NOT_INVERTIBLE => CxSyscallError::NotInvertible,
            bindings::CX_OVERFLOW => CxSyscallError::Overflow,
            bindings::CX_MEMORY_FULL => CxSyscallError::MemoryFull,
            bindings::CX_NO_RESIDUE => CxSyscallError::NoResidue,
            bindings::CX_EC_INFINITE_POINT => CxSyscallError::EcInfinitePoint,
            bindings::CX_EC_INVALID_POINT => CxSyscallError::EcInvalidPoint,
            bindings::CX_EC_INVALID_CURVE => CxSyscallError::EcInvalidCurve,
            _ => CxSyscallError::Unspecified,
        }
    }
}

impl From<CxSyscallError> for Reply {
    fn from(exc: CxSyscallError) -> Reply {
        Reply(0x6800 + exc as u16)
    }
}

impl CxSyscallError {
    pub fn show(&self) {
        match self {
            CxSyscallError::Locked => nanos_sdk::debug_print("Locked\n"),
            CxSyscallError::Unlocked => nanos_sdk::debug_print("Unlocked\n"),
            CxSyscallError::NotLocked => nanos_sdk::debug_print("NotLocked\n"),
            CxSyscallError::InternalError => nanos_sdk::debug_print("InternalError\n"),
            CxSyscallError::InvalidParameterSize => {
                nanos_sdk::debug_print("InvalidParameterSize\n")
            }
            CxSyscallError::InvalidParameterValue => {
                nanos_sdk::debug_print("InvalidParameterValue\n")
            }
            CxSyscallError::InvalidParameter => nanos_sdk::debug_print("InvalidParameter\n"),
            CxSyscallError::NotInvertible => nanos_sdk::debug_print("NotInvertible\n"),
            CxSyscallError::Overflow => nanos_sdk::debug_print("Overflow\n"),
            CxSyscallError::MemoryFull => nanos_sdk::debug_print("MemoryFull\n"),
            CxSyscallError::NoResidue => nanos_sdk::debug_print("NoResidue\n"),
            CxSyscallError::EcInfinitePoint => nanos_sdk::debug_print("EcInfinitePoint\n"),
            CxSyscallError::EcInvalidPoint => nanos_sdk::debug_print("EcInvalidPoint\n"),
            CxSyscallError::EcInvalidCurve => nanos_sdk::debug_print("EcInvalidCurve\n"),
            _ => nanos_sdk::debug_print("Unspecified\n"),
        }
    }
}

// WRAPPERS AUTOUR DES BIG NUMBERS DU SDK

#[derive(Clone, Copy)]
pub struct CxBn {
    pub x: u32,
}

impl CxBn {
    pub fn new() -> CxBn {
        CxBn { x: 0 }
    }
}

pub fn cx_bn_lock(word_nbytes: u32, flags: u32) -> Result<(), CxSyscallError> {
    let err = unsafe { bindings::cx_bn_lock(word_nbytes as u32, flags) };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_bn_lock\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(())
    }
}

pub fn cx_bn_unlock() -> Result<(), CxSyscallError> {
    let err = unsafe { bindings::cx_bn_unlock() };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_bn_unlock\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(())
    }
}

pub fn cx_bn_is_locked() -> bool {
    unsafe { bindings::cx_bn_is_locked() }
}

pub fn cx_bn_alloc(nbytes: u32) -> Result<CxBn, CxSyscallError> {
    let mut x = CxBn::new();
    let err = unsafe { bindings::cx_bn_alloc(&mut x.x, nbytes) };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_bn_alloc\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(x)
    }
}

pub fn cx_bn_alloc_init(nbytes: u32, value: &[u8]) -> Result<CxBn, CxSyscallError> {
    let mut x = CxBn::new();
    let err =
        unsafe { bindings::cx_bn_alloc_init(&mut x.x, nbytes, value.as_ptr(), value.len() as u32) };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_bn_alloc_init\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(x)
    }
}

pub fn cx_bn_export(x: CxBn, bytes: &mut [u8]) -> Result<(), CxSyscallError> {
    let err = unsafe { bindings::cx_bn_export(x.x, bytes.as_mut_ptr(), bytes.len() as u32) };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_bn_export\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(())
    }
}

pub fn cx_bn_mod_add(r: CxBn, a: CxBn, b: CxBn, n: CxBn) -> Result<(), CxSyscallError> {
    let err = unsafe { bindings::cx_bn_mod_add(r.x, a.x, b.x, n.x) };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_bn_mod_add\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(())
    }
}

pub fn cx_bn_mod_mul(r: CxBn, a: CxBn, b: CxBn, n: CxBn) -> Result<(), CxSyscallError> {
    let err = unsafe { bindings::cx_bn_mod_mul(r.x, a.x, b.x, n.x) };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_bn_mod_mul\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(())
    }
}

pub fn cx_bn_mod_pow_bn(r: CxBn, a: CxBn, b: CxBn, n: CxBn) -> Result<(), CxSyscallError> {
    let err = unsafe { bindings::cx_bn_mod_pow_bn(r.x, a.x, b.x, n.x) };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_bn_mod_pow_bn\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(())
    }
}

pub fn cx_bn_rand(x: CxBn) -> Result<(), CxSyscallError> {
    let err = unsafe { bindings::cx_bn_rand(x.x) };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_bn_rand\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(())
    }
}

pub fn cx_bn_destroy(mut x: CxBn) -> Result<(), CxSyscallError> {
    let err = unsafe { bindings::cx_bn_destroy(&mut x.x as *mut u32) };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_bn_destroy\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(())
    }
}

pub fn cx_bn_cmp(a: CxBn, b: CxBn, mut diff: i32) -> Result<(), CxSyscallError> {
    let err = unsafe { bindings::cx_bn_cmp(a.x, b.x, &mut diff as *mut i32) };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_bn_cmp\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(())
    }
}

// WRAPPERS AUTOUR DES EC POINT DU SDK

pub fn cx_ecpoint_alloc(
    cv: bindings::cx_curve_t,
) -> Result<bindings::cx_ecpoint_t, CxSyscallError> {
    let mut p = bindings::cx_ecpoint_t::default();
    let err = unsafe { bindings::cx_ecpoint_alloc(&mut p, cv) };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_ecpoint_alloc\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(p)
    }
}

pub fn cx_ecpoint_init(
    p: &mut bindings::cx_ecpoint_t,
    x: &[u8],
    y: &[u8],
) -> Result<(), CxSyscallError> {
    let err = unsafe {
        bindings::cx_ecpoint_init(
            p as *mut bindings::cx_ecpoint_t,
            x.as_ptr(),
            x.len() as u32,
            y.as_ptr(),
            y.len() as u32,
        )
    };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_ecpoint_init\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(())
    }
}

pub fn cx_ecpoint_add(
    r: &mut bindings::cx_ecpoint_t,
    p: &bindings::cx_ecpoint_t,
    q: &bindings::cx_ecpoint_t,
) -> Result<(), CxSyscallError> {
    let err = unsafe {
        bindings::cx_ecpoint_add(
            r as *mut bindings::cx_ecpoint_t,
            p as *const bindings::cx_ecpoint_t,
            q as *const bindings::cx_ecpoint_t,
        )
    };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_ecpoint_add\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(())
    }
}

pub fn cx_ecpoint_rnd_scalarmul_bn(
    p: &mut bindings::cx_ecpoint_t,
    k: CxBn,
) -> Result<(), CxSyscallError> {
    let err = unsafe { bindings::cx_ecpoint_rnd_scalarmul_bn(p, k.x) };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_ecpoint_rnd_scalarmul_bn\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(())
    }
}

pub fn cx_ecpoint_export(
    p: &bindings::cx_ecpoint_t,
    x: &mut [u8],
    y: &mut [u8],
) -> Result<(), CxSyscallError> {
    let err = unsafe {
        bindings::cx_ecpoint_export(
            p,
            x.as_mut_ptr(),
            x.len() as u32,
            y.as_mut_ptr(),
            y.len() as u32,
        )
    };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_ecpoint_export\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(())
    }
}

pub fn cx_ecdomain_generator_bn(
    cv: bindings::cx_curve_t,
    p: &mut bindings::cx_ecpoint_t,
) -> Result<bindings::cx_ecpoint_t, CxSyscallError> {
    let err = unsafe { bindings::cx_ecdomain_generator_bn(cv, p) };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_ecdomain_generator_bn\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(*p)
    }
}

pub fn cx_ecpoint_is_at_infinity(
    p: &mut bindings::cx_ecpoint_t,
    out: *mut bool,
) -> Result<(), CxSyscallError> {
    let err = unsafe { bindings::cx_ecpoint_is_at_infinity(p, out) };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_ecpoint_is_at_infinity\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(())
    }
}

pub fn cx_ecpoint_destroy(p: &mut bindings::cx_ecpoint_t) -> Result<(), CxSyscallError> {
    let err = unsafe { bindings::cx_ecpoint_destroy(p as *mut bindings::cx_ec_point_s) };
    if err != 0 {
        let cx_err: CxSyscallError = err.into();
        nanos_sdk::debug_print("err cx_ecpoint_destroy\n");
        cx_err.show();
        Err(cx_err)
    } else {
        Ok(())
    }
}
