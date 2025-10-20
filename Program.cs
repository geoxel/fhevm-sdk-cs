using System;
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;

namespace RelayerSDK;

public static class Program
{
    public static async Task Main()
    {
        // RelayerKeys relayerKeys =
        //     await RelayerKeys.ReadFromUrl("https://relayer.testnet.zama.cloud/v1/keyurl")
        //     ?? throw new InvalidOperationException();
        // Console.WriteLine(JsonSerializer.Serialize(relayerKeys, new JsonSerializerOptions { WriteIndented = true }));

        Console.WriteLine("Hi relayer.");

        using PrivateEncKeyMlKem512 private_key = PrivateEncKeyMlKem512.Generate();

        byte[] serialized_private_key = private_key.GetPrivateKeyData();
        Console.WriteLine("private key len = " + serialized_private_key.Length);
        Console.WriteLine(Convert.ToHexString(serialized_private_key));

        byte[] serialized_public_key = private_key.GetPublicKeyData();
        Console.WriteLine("public key len = " + serialized_public_key.Length);
        Console.WriteLine(Convert.ToHexString(serialized_public_key));

        using PublicEncKeyMlKem512 pppkkk = PublicEncKeyMlKem512.Deserialize(serialized_public_key);
        SafeNativeMethods.TKMS_PublicEncKeyMlKem512_destroy(pppkkk.Handle);

        using var serverIdAddr = ServerIdAddr.Create(id: 1, addr: "0x17853A630aAe15AED549B2B874de08B73C0F59c5");

        using Network network = new(); 
      
        const string keyUrlBase = "https://relayer.testnet.zama.cloud";
        Network.Result res = await network.GetKeysFromRelayer(keyUrlBase, publicKeyId: null);
      
        Console.WriteLine("Bye relayer2.");
    }
}
