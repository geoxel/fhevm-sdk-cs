using System;
using System.Runtime.InteropServices;

namespace RelayerSDK;

public sealed class ServerIdAddr : KMSHandle
{
    private ServerIdAddr(nint handle) : base(handle)
    {
    }

    protected override void DestroyHandle(nint handle) =>
        SafeNativeMethods.TKMS_ServerIdAddr_destroy(handle);

    public static ServerIdAddr Create(uint id, string addr)
    {
        SafeNativeMethods.TKMS_NewServerIdAddr(id, addr, out nint handle);

        return new ServerIdAddr(handle);
    }
}
