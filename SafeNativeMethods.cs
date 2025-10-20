using System;
using System.Runtime.InteropServices;

namespace RelayerSDK;

internal static partial class SafeNativeMethods
{
#if OS_WINDOWS
    private const string LibraryPrefix = "";
    private const string LibraryExtension = ".dll";
#elif OS_LINUX
    private const string LibraryPrefix = "lib";
    private const string LibraryExtension = ".so";
#elif OS_MACOS
    private const string LibraryPrefix = "lib";
    private const string LibraryExtension = ".dylib";
#else
#error Unsupported platform
#endif

    private const string LibraryPath = "kms/target/release/" + LibraryPrefix + "kms_lib" + LibraryExtension;

    [LibraryImport(LibraryPath)]
    public static partial int TKMS_ml_kem_pke_keygen(out nint keys);

    [LibraryImport(LibraryPath)]
    public static partial int TKMS_ml_kem_pke_get_pk(nint keys, out nint public_key);

    [LibraryImport(LibraryPath)]
    public static partial int TKMS_ml_kem_pke_pk_to_u8vec(nint public_key, out DynamicBuffer buffer);
    [LibraryImport(LibraryPath)]
    public static partial int TKMS_ml_kem_pke_sk_to_u8vec(nint keys, out DynamicBuffer buffer);

    [LibraryImport(LibraryPath)]
    public static partial int TKMS_u8vec_to_ml_kem_pke_pk(DynamicBufferView buffer_view, out nint key);
    [LibraryImport(LibraryPath)]
    public static partial int TKMS_u8vec_to_ml_kem_pke_sk(DynamicBufferView buffer_view, out nint key);

    [LibraryImport(LibraryPath, EntryPoint = "TKMS_public_enc_key_ml_kem512_destroy")]
    public static partial int TKMS_PublicEncKeyMlKem512_destroy(nint key);
    [LibraryImport(LibraryPath, EntryPoint = "TKMS_private_enc_key_ml_kem512_destroy")]
    public static partial int TKMS_PrivateEncKeyMlKem512_destroy(nint key);

    [LibraryImport(LibraryPath, EntryPoint = "TKMS_new_server_id_addr")]
    public static partial int TKMS_NewServerIdAddr(
        uint id,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string addr,
        out nint out_server_id_addr);

    [LibraryImport(LibraryPath, EntryPoint = "TKMS_server_id_addr_destroy")]
    public static partial int TKMS_ServerIdAddr_destroy(nint server_id_addr);

    [LibraryImport(LibraryPath, EntryPoint = "TKMS_new_client")]
    public static partial int TKMS_NewClient(
        nint server_addrs,
        int server_addrs_len,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string client_address_hex,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string fhe_parameter,
        out nint out_client);

    [StructLayout(LayoutKind.Sequential)]
    public struct DynamicBufferView
    {
        public nint pointer;
        public nint length;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct DynamicBuffer
    {
        public nint pointer;
        public nint length;
        public nint destructor;
    };

    internal static byte[] DynamicBuffer_ToArray(DynamicBuffer buffer)
    {
        try
        {
            const int MaxArraySize = 0x7FFFFFC7;
            if (buffer.length > MaxArraySize)
                throw new FheException(1); // TODO: use a better error code

            var result = new byte[(int)buffer.length];
            Marshal.Copy(buffer.pointer, result, 0, result.Length);
            return result;
        }
        finally
        {
            DynamicBuffer_Destroy(ref buffer);
        }
    }

    [LibraryImport(LibraryPath, EntryPoint = "destroy_dynamic_buffer")]
    public static partial int DynamicBuffer_Destroy(ref DynamicBuffer buffer);
}
