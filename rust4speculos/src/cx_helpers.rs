use nanos_sdk::bindings;
use nanos_sdk::io::SyscallError;

#[derive(Clone, Copy)]
pub struct CxBn {
    pub x: u32,
}

impl CxBn {
    pub fn new() -> CxBn {
        CxBn { x: 0 }
    }
}

pub fn cx_bn_lock(word_nbytes: u32, flags: u32) -> Result<(), SyscallError> {
    let err = unsafe { bindings::cx_bn_lock(word_nbytes as u32, flags) };
    if err != 0 {
        Err(err.into())
    } else {
        Ok(())
    }
}

pub fn cx_bn_unlock() -> Result<(), SyscallError> {
    let err = unsafe { bindings::cx_bn_unlock() };
    if err != 0 {
        Err(err.into())
    } else {
        Ok(())
    }
}

pub fn cx_bn_is_locked() -> bool {
    unsafe { bindings::cx_bn_is_locked() }
}

pub fn cx_bn_alloc(nbytes: u32) -> Result<CxBn, SyscallError> {
    let mut x = CxBn::new();
    let err = unsafe { bindings::cx_bn_alloc(&mut x.x, nbytes) };
    if err != 0 {
        Err(err.into())
    } else {
        Ok(x)
    }
}

pub fn cx_bn_alloc_init(nbytes: u32, value: &[u8]) -> Result<CxBn, SyscallError> {
    let mut x = CxBn::new();
    let err =
        unsafe { bindings::cx_bn_alloc_init(&mut x.x, nbytes, value.as_ptr(), value.len() as u32) };
    if err != 0 {
        Err(err.into())
    } else {
        Ok(x)
    }
}

pub fn cx_bn_export(x: CxBn, bytes: &mut [u8]) -> Result<(), SyscallError> {
    let err = unsafe { bindings::cx_bn_export(x.x, bytes.as_mut_ptr(), bytes.len() as u32) };
    if err != 0 {
        Err(err.into())
    } else {
        Ok(())
    }
}

pub fn cx_bn_mod_add(r: CxBn, a: CxBn, b: CxBn, n: CxBn) -> Result<(), SyscallError> {
    let err = unsafe { bindings::cx_bn_mod_add(r.x, a.x, b.x, n.x) };
    if err != 0 {
        Err(err.into())
    } else {
        Ok(())
    }
}

pub fn cx_bn_mod_mul(r: CxBn, a: CxBn, b: CxBn, n: CxBn) -> Result<(), SyscallError> {
    let err = unsafe { bindings::cx_bn_mod_mul(r.x, a.x, b.x, n.x) };
    if err != 0 {
        Err(err.into())
    } else {
        Ok(())
    }
}

pub fn cx_bn_mod_pow_bn(r: CxBn, a: CxBn, b: CxBn, n: CxBn) -> Result<(), SyscallError> {
    let err = unsafe { bindings::cx_bn_mod_pow_bn(r.x, a.x, b.x, n.x) };
    if err != 0 {
        Err(err.into())
    } else {
        Ok(())
    }
}

pub fn cx_ecpoint_alloc(cv: bindings::cx_curve_t) -> Result<bindings::cx_ecpoint_t, SyscallError> {
    let mut p = bindings::cx_ecpoint_t::default();
    let err = unsafe { bindings::cx_ecpoint_alloc(&mut p, cv) };
    if err != 0 {
        Err(err.into())
    } else {
        Ok(p)
    }
}

pub fn cx_ecpoint_init(
    p: &mut bindings::cx_ecpoint_t,
    x: &[u8],
    y: &[u8],
) -> Result<(), SyscallError> {
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
        Err(err.into())
    } else {
        Ok(())
    }
}

pub fn cx_ecpoint_add(
    r: &mut bindings::cx_ecpoint_t,
    p: &bindings::cx_ecpoint_t,
    q: &bindings::cx_ecpoint_t,
) -> Result<(), SyscallError> {
    let err = unsafe {
        bindings::cx_ecpoint_add(
            r as *mut bindings::cx_ecpoint_t,
            p as *const bindings::cx_ecpoint_t,
            q as *const bindings::cx_ecpoint_t,
        )
    };
    if err != 0 {
        Err(err.into())
    } else {
        Ok(())
    }
}

pub fn cx_ecpoint_rnd_scalarmul_bn(
    p: &mut bindings::cx_ecpoint_t,
    k: CxBn,
) -> Result<(), SyscallError> {
    let err = unsafe { bindings::cx_ecpoint_rnd_scalarmul_bn(p, k.x) };
    if err != 0 {
        Err(err.into())
    } else {
        Ok(())
    }
}

pub fn cx_ecpoint_export(
    p: &bindings::cx_ecpoint_t,
    x: &mut [u8],
    y: &mut [u8],
) -> Result<(), SyscallError> {
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
        Err(err.into())
    } else {
        Ok(())
    }
}

pub fn cx_ecdomain_generator_bn(
    cv: bindings::cx_curve_t,
    p: &mut bindings::cx_ecpoint_t,
) -> Result<bindings::cx_ecpoint_t, SyscallError> {
    let err = unsafe { bindings::cx_ecdomain_generator_bn(cv, p) };
    if err != 0 {
        Err(err.into())
    } else {
        Ok(*p)
    }
}
