namespace RelayerSDK.Kms;

public sealed class ServerIdAddr : KmsHandle
{
    public int Id { get; }
    public string Address { get; }

    private ServerIdAddr(nint handle, int id, string addr) : base(handle)
    {
        Id = id;
        Address = addr;
    }

    protected override void DestroyHandle(nint handle) =>
        SafeNativeMethods.TKMS_ServerIdAddr_destroy(handle);

    public static ServerIdAddr Create(int id, string addr)
    {
        SafeNativeMethods.TKMS_NewServerIdAddr(id, addr, out nint handle);

        return new ServerIdAddr(handle, id, addr);
    }
}
