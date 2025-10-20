using System;
using System.Runtime.InteropServices;

namespace RelayerSDK;

public sealed class PrivateEncKeyMlKem512 : KMSHandle
{
    private PrivateEncKeyMlKem512(nint handle) : base(handle)
    {
    }

    protected override void DestroyHandle(nint handle) =>
        SafeNativeMethods.TKMS_PrivateEncKeyMlKem512_destroy(handle);
    
    public static PrivateEncKeyMlKem512 Generate()
    {
        SafeNativeMethods.TKMS_ml_kem_pke_keygen(out nint private_key);
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

    public static unsafe PrivateEncKeyMlKem512 Deserialize(byte[] data)
    {
        fixed (byte* ptr = data)
        {
            var buffer_view = new SafeNativeMethods.DynamicBufferView
            {
                pointer = new nint(ptr),
                length = data.Length,
            };

            return new PrivateEncKeyMlKem512(Oper1n(SafeNativeMethods.TKMS_u8vec_to_ml_kem_pke_sk, buffer_view));
        }
    }
}
