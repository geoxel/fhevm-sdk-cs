using System;
using System.Runtime.InteropServices;

namespace RelayerSDK;

public sealed class PublicEncKeyMlKem512 : KMSHandle
{
    private PublicEncKeyMlKem512(nint handle) : base(handle)
    {
    }

    protected override void DestroyHandle(nint handle) =>
        SafeNativeMethods.TKMS_PublicEncKeyMlKem512_destroy(handle);

    public static unsafe PublicEncKeyMlKem512 Deserialize(byte[] data)
    {
        fixed (byte* ptr = data)
        {
            var buffer_view = new SafeNativeMethods.DynamicBufferView
            {
                pointer = new nint(ptr),
                length = data.Length,
            };

            return new PublicEncKeyMlKem512(Oper1n(SafeNativeMethods.TKMS_u8vec_to_ml_kem_pke_pk, buffer_view));
        }
    }
}
