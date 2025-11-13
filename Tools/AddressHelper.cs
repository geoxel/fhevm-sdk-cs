using Nethereum.Util;

namespace RelayerSDK.Tools;

public static class AddressHelper
{
    // cf. https://docs.ethers.org/v5/api/utils/address/#utils-computeAddress
    // IsAddress("0x8ba1f109551bd432803012645ac136ddd64dba72") = true
    // IsAddress("XE65GB6LDNXYOFTX0NSV3FUWKOWIXAMJK36") = true
    // IsAddress("I like turtles.") = false
    public static bool IsAddress(string addr)
    {
        addr = Helpers.Ensure0xPrefix(addr);

        var addressUtil = new AddressUtil();

        return addressUtil.IsValidEthereumAddressHexFormat(addr);
    }

    // cf. https://docs.ethers.org/v5/api/utils/address/#utils-getAddress
    public static string GetChecksumAddress(string addr)
    {
        addr = Helpers.Ensure0xPrefix(addr);

        var addressUtil = new AddressUtil();

        // Validate the address
        bool isValid = addressUtil.IsValidEthereumAddressHexFormat(addr);
        if (!isValid)
            throw new InvalidOperationException("invalid address");

        // // Validate checksummed format
        // bool isChecksumValid = addressUtil.IsChecksumAddress(addr);
        // if (!isChecksumValid)
        //     throw new InvalidOperationException("invalid checksum");

        // Convert / normalize to checksum address (like ethers.utils.getAddress)
        string checksumAddress = addressUtil.ConvertToChecksumAddress(addr);

        return checksumAddress;
    }
}
