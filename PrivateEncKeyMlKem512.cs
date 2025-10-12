using System;
using System.Runtime.InteropServices;

namespace RelayerSDK;

public sealed class PrivateEncKeyMlKem512 : KMSHandle
{
    private PrivateEncKeyMlKem512(nint handle) : base(handle)
    {
    }

    public override void Dispose()
    {
    }
    
    public static PrivateEncKeyMlKem512 Generate()
    {
        SafeNativeMethods.TKMS_ml_kem_pke_keygen(out nint private_key); // TODO: free private key?
        return new PrivateEncKeyMlKem512(private_key);
    }

    public byte[] GetPublicKeyData()
    {
        SafeNativeMethods.TKMS_ml_kem_pke_get_pk(Handle, out nint public_key); // TODO: free public key?

        int error = SafeNativeMethods.TKMS_ml_kem_pke_pk_to_u8vec(public_key, out SafeNativeMethods.DynamicBuffer buffer);
        if (error != 0)
            throw new FheException(error);

        return SafeNativeMethods.DynamicBuffer_ToArray(buffer);
    }

    public byte[] GetPrivateKeyData()
    {
        int error = SafeNativeMethods.TKMS_ml_kem_pke_sk_to_u8vec(Handle, out SafeNativeMethods.DynamicBuffer buffer);
        if (error != 0)
            throw new FheException(error);

        return SafeNativeMethods.DynamicBuffer_ToArray(buffer);
    }

}
