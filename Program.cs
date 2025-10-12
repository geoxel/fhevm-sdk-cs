using System;
using System.Diagnostics;
using System.Globalization;

namespace RelayerSDK;

public static class Program
{
    public static void Main()
    {
        Console.WriteLine("Hi relayer.");

        PrivateEncKeyMlKem512 private_key = PrivateEncKeyMlKem512.Generate();

        byte[] serialized_private_key = private_key.GetPrivateKeyData();
        Console.WriteLine("private key len = " + serialized_private_key.Length);
        Console.WriteLine(Convert.ToHexString(serialized_private_key));

        byte[] serialized_public_key = private_key.GetPublicKeyData();
        Console.WriteLine("public key len = " + serialized_public_key.Length);
        Console.WriteLine(Convert.ToHexString(serialized_public_key));

        Console.WriteLine("Bye relayer.");
    }
}
