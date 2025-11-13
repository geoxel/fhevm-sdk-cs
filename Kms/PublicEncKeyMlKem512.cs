namespace FhevmSDK.Kms;

public sealed class PublicEncKeyMlKem512 : KmsHandle
{
    private PublicEncKeyMlKem512(nint handle) : base(handle)
    {
    }

    protected override void DestroyHandle(nint handle) =>
        SafeNativeMethods.TKMS_PublicEncKeyMlKem512_destroy(handle);

    public static PublicEncKeyMlKem512 FromPrivateKey(PrivateEncKeyMlKem512 privateKey) =>
        new PublicEncKeyMlKem512(Oper1n(SafeNativeMethods.TKMS_ml_kem_pke_get_pk, privateKey.Handle));

    public byte[] Serialize()
    {
        CheckError(SafeNativeMethods.TKMS_ml_kem_pke_pk_to_u8vec(Handle, out SafeNativeMethods.DynamicBuffer buffer));

        using DynamicBuffer dynamicbuffer = new(buffer);

        return dynamicbuffer.ToArray();
    }

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
