use std::ffi::{ CStr };
use std::os::raw::c_char;
use std::collections::HashMap;

use crate::cryptography::internal_crypto_types::{ PrivateEncKey, PublicEncKey, UnifiedPublicEncKey };
use crate::client::c_buffer::{ DynamicBuffer, DynamicBufferView };
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::hybrid_ml_kem;
use crate::cryptography::internal_crypto_types::{ PrivateSigKey, PublicSigKey };
use bc2wrap::{ deserialize };
use aes_prng::AesRng;

use kms_grpc::kms::v1::FheParameter;

use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use threshold_fhe::execution::tfhe_internals::parameters::BC_PARAMS_SNS;

#[repr(C)]
pub struct PrivateEncKeyMlKem512(pub(crate) PrivateEncKey<ml_kem::MlKem512>);

#[repr(C)]
pub struct PublicEncKeyMlKem512(pub(crate) PublicEncKey<ml_kem::MlKem512>);

#[no_mangle]
pub unsafe extern "C" fn TKMS_ml_kem_pke_keygen(
    out_keys: *mut *mut PrivateEncKeyMlKem512
) -> std::os::raw::c_int {
    let mut rng = AesRng::from_random_seed();
    //let mut rng = AesRng::from_entropy();
    let (dk, _ek) = hybrid_ml_kem::keygen::<ml_kem::MlKem512, _>(&mut rng);
    let keys = PrivateEncKeyMlKem512(PrivateEncKey(dk));

    *out_keys = Box::into_raw(Box::new(keys));

    0
}

#[no_mangle]
pub unsafe extern "C" fn TKMS_ml_kem_pke_get_pk(
    sk: &PrivateEncKeyMlKem512, 
    out_public_key: *mut *mut PublicEncKeyMlKem512
) -> std::os::raw::c_int {
    let public_key = PublicEncKeyMlKem512(PublicEncKey(sk.0 .0.encapsulation_key().clone()));
    *out_public_key = Box::into_raw(Box::new(public_key));
    
    0
}

#[no_mangle]
pub unsafe extern "C" fn TKMS_ml_kem_pke_pk_to_u8vec(
    pk: &PublicEncKeyMlKem512,
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
    sk: &PrivateEncKeyMlKem512,
    result: *mut DynamicBuffer,
) -> std::os::raw::c_int {
    crate::client::c_utils::catch_panic(|| {
        let v = bc2wrap::serialize(&sk.0).unwrap();
        
        let buffer = DynamicBuffer::from(v);
        *result = buffer.into();
    })
}

#[no_mangle]
pub unsafe extern "C" fn TKMS_u8vec_to_ml_kem_pke_pk(
    buffer_view: DynamicBufferView,
    result: *mut *mut PublicEncKeyMlKem512
) -> std::os::raw::c_int {
    crate::client::c_utils::catch_panic(|| {
        crate::client::c_utils::check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let key =
            tfhe::safe_serialization::safe_deserialize::<UnifiedPublicEncKey>(
                std::io::Cursor::new(buffer_view.as_slice()),
                SAFE_SER_SIZE_LIMIT,
            )
            .map(|x| PublicEncKeyMlKem512(x.unwrap_ml_kem_512()))
            .unwrap();

        *result = Box::into_raw(Box::new(key));
    })
}

#[no_mangle]
pub unsafe extern "C" fn TKMS_u8vec_to_ml_kem_pke_sk(
    buffer_view: DynamicBufferView,
    result: *mut *mut PrivateEncKeyMlKem512
) -> std::os::raw::c_int {
    crate::client::c_utils::catch_panic(|| {
        crate::client::c_utils::check_ptr_is_non_null_and_aligned(result).unwrap();

        *result = std::ptr::null_mut();

        let key =
            deserialize::<PrivateEncKey<ml_kem::MlKem512>>(buffer_view.as_slice())
            .map(PrivateEncKeyMlKem512)
            .unwrap();

        *result = Box::into_raw(Box::new(key));
    })
}

#[repr(C)]
pub struct ServerIdAddr {
    id: u32,
    addr: alloy_primitives::Address,
}

#[no_mangle]
pub unsafe extern "C" fn TKMS_new_server_id_addr(
    id: u32, 
    cs_addr: *const c_char,
    result: *mut *mut ServerIdAddr
) -> ::std::os::raw::c_int {
    crate::client::c_utils::catch_panic(|| {
        crate::client::c_utils::check_ptr_is_non_null_and_aligned(cs_addr).unwrap();

        let addr = CStr::from_ptr(cs_addr).to_str().unwrap();
        
        let parsed_addr = 
            alloy_primitives::Address::parse_checksummed(addr, None)
            .unwrap();
        
        let server_id_addr = ServerIdAddr { id, addr: parsed_addr };

        *result = Box::into_raw(Box::new(server_id_addr));
    })
}

pub enum ServerIdentities {
    Pks(HashMap<u32, PublicSigKey>),
    Addrs(HashMap<u32, alloy_primitives::Address>),
}

impl ServerIdentities {
    pub fn len(&self) -> usize {
        match &self {
            ServerIdentities::Pks(vec) => vec.len(),
            ServerIdentities::Addrs(vec) => vec.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub struct Client {
    pub(crate) server_identities: ServerIdentities,
    pub(crate) client_address: alloy_primitives::Address,
    pub(crate) client_sk: Option<PrivateSigKey>,
    pub(crate) params: DKGParams,
    pub(crate) decryption_mode: DecryptionMode,
}

#[no_mangle]
pub unsafe extern "C" fn TKMS_new_client(
    cs_server_addrs: *const *mut ServerIdAddr,
    server_addrs_len32: u32,
    //server_addrs: Vec<&ServerIdAddr>,
    cs_client_address_hex: *const c_char,
    cs_fhe_parameter: *const c_char,
    result: *mut *mut Client
) -> ::std::os::raw::c_int {
    crate::client::c_utils::catch_panic(|| {
        console_error_panic_hook::set_once();

        let client_address_hex = CStr::from_ptr(cs_client_address_hex).to_str().unwrap();
        let fhe_parameter = CStr::from_ptr(cs_fhe_parameter).to_str().unwrap();

        let params = match FheParameter::from_str_name(fhe_parameter) {
            Some(choice) => {
                let p: crate::cryptography::internal_crypto_types::WrappedDKGParams = choice.into();
                *p
            }
            None => BC_PARAMS_SNS,
        };

        let client_address = 
            alloy_primitives::Address::parse_checksummed(client_address_hex, None)
            .unwrap();

        let server_addrs_len = usize::try_from(server_addrs_len32).unwrap();
        let server_addrs = std::slice::from_raw_parts(cs_server_addrs, server_addrs_len);
        let addrs_hash_map = HashMap::from_iter(
            server_addrs
                .into_iter()
                .map(|id_addr| ((*(*id_addr)).id, (*(*id_addr)).addr)),
        );

        if server_addrs_len != addrs_hash_map.len() {
            return Err("some server IDs have duplicate keys").unwrap();
        }

        let server_identities = ServerIdentities::Addrs(addrs_hash_map);

        let client =
            Client {
                server_identities,
                client_address,
                client_sk: None,
                params,
                decryption_mode: DecryptionMode::default(),
        };

        *result = Box::into_raw(Box::new(client));
    })
}



macro_rules! impl_destroy_on_type {
    ($wrapper_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            #[doc = "ptr can be null (no-op in that case)"]
            pub unsafe extern "C" fn [<TKMS_ $wrapper_type:snake _destroy>](
                ptr: *mut $wrapper_type,
            ) -> ::std::os::raw::c_int {
                $crate::client::c_utils::catch_panic(|| {
                    if (!ptr.is_null()) {
                        $crate::client::c_utils::check_ptr_is_non_null_and_aligned(ptr).unwrap();
                        drop(Box::from_raw(ptr));
                    }
                })
            }
        }
    };
}

impl_destroy_on_type!(ServerIdAddr);
impl_destroy_on_type!(PrivateEncKeyMlKem512);
impl_destroy_on_type!(PublicEncKeyMlKem512);
impl_destroy_on_type!(Client);
