use crate::cryptography::internal_crypto_types::{
    PrivateEncKey, PublicEncKey, UnifiedPublicEncKey,
};
use crate::client::c_buffer::{ DynamicBuffer, };
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::hybrid_ml_kem;
use aes_prng::AesRng;

#[repr(C)]
pub struct CSPrivateEncKeyMlKem512(pub(crate) PrivateEncKey<ml_kem::MlKem512>);

#[repr(C)]
pub struct CSPublicEncKeyMlKem512(pub(crate) PublicEncKey<ml_kem::MlKem512>);

#[no_mangle]
pub unsafe extern "C" fn TKMS_ml_kem_pke_keygen(out_keys: *mut *mut CSPrivateEncKeyMlKem512) -> std::os::raw::c_int {
    let mut rng = AesRng::from_random_seed();
    //let mut rng = AesRng::from_entropy();
    let (dk, _ek) = hybrid_ml_kem::keygen::<ml_kem::MlKem512, _>(&mut rng);
    let keys = CSPrivateEncKeyMlKem512(PrivateEncKey(dk));

    *out_keys = Box::into_raw(Box::new(keys));

    0
}

#[no_mangle]
pub unsafe extern "C" fn TKMS_ml_kem_pke_get_pk(sk: &CSPrivateEncKeyMlKem512, out_public_key: *mut *mut CSPublicEncKeyMlKem512) -> std::os::raw::c_int {
    let public_key = CSPublicEncKeyMlKem512(PublicEncKey(sk.0 .0.encapsulation_key().clone()));
    *out_public_key = Box::into_raw(Box::new(public_key));
    
    0
}

#[no_mangle]
pub unsafe extern "C" fn TKMS_ml_kem_pke_pk_to_u8vec(
    pk: &CSPublicEncKeyMlKem512,
    result: *mut DynamicBuffer,
) -> std::os::raw::c_int {
    crate::client::c_utils::catch_panic(|| {
        let mut enc_key_buf = Vec::new();
        let _ct = tfhe::safe_serialization::safe_serialize(
            &UnifiedPublicEncKey::MlKem512(pk.0.clone()),
            &mut enc_key_buf,
            SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        
        let buffer = DynamicBuffer::from(enc_key_buf);
        *result = buffer.into();
    })
}

#[no_mangle]
pub unsafe extern "C" fn TKMS_ml_kem_pke_sk_to_u8vec(
    sk: &CSPrivateEncKeyMlKem512,
    result: *mut DynamicBuffer,
) -> std::os::raw::c_int {
    crate::client::c_utils::catch_panic(|| {
        let v = bc2wrap::serialize(&sk.0).unwrap();
        
        let buffer = DynamicBuffer::from(v);
        *result = buffer.into();
    })
}
