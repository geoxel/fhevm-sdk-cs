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
