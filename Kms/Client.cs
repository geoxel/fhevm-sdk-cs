namespace FhevmSDK.Kms;

public sealed class Client : KmsHandle
{
    private Client(nint handle) : base(handle)
    {
    }

    protected override void DestroyHandle(nint handle) =>
        SafeNativeMethods.TKMS_Client_destroy(handle);

    public static unsafe Client Create(ServerIdAddr[] serverAddresses, string clientAddress, string fheParameter)
    {
        nint[] serverAddressesHandles = serverAddresses.Select(a => a.Handle).ToArray();
        fixed (nint* ptr = serverAddressesHandles)
        {
            SafeNativeMethods.TKMS_NewClient(new nint(ptr), serverAddressesHandles.Length, clientAddress, fheParameter, out nint handle);
            return new Client(handle);
        }
    }
}
