using Nethereum.ABI.EIP712;
using Nethereum.Signer;
using FhevmSDK.Tools;

namespace FhevmSDK;

public static class Eip712
{
    public static TypedData<Domain> Create(
        FhevmConfig fhevmConfig,
        string publicKey,
        string[] contractAddresses,
        DateTimeOffset startTime,
        int durationDays,
        string? delegatedAccount = null)
    {
        if (delegatedAccount != null && !AddressHelper.IsAddress(delegatedAccount))
            throw new InvalidDataException("Invalid delegated account.");

        if (!AddressHelper.IsAddress(fhevmConfig.VerifyingContractAddress))
            throw new InvalidDataException("Invalid verifying contract address.");

        if (!contractAddresses.All(AddressHelper.IsAddress))
            throw new InvalidDataException("A contract address is invalid");

        const string extraData = "0x00";

        MemberDescription[] eip712DomainTypes =
        [
            new MemberDescription { Name = "name", Type = "string" },
            new MemberDescription { Name = "version", Type = "string" },
            new MemberDescription { Name = "chainId", Type = "uint256" },
            new MemberDescription { Name = "verifyingContract", Type = "address" },
        ];

        Domain domain = new()
        {
            Name = "Decryption",
            Version = "1",
            ChainId = fhevmConfig.ChainId,
            VerifyingContract = fhevmConfig.VerifyingContractAddress,
        };

        MemberDescription[] messageTypes =
        [
            new MemberDescription { Name = "publicKey", Type = "bytes" },
            new MemberDescription { Name = "contractAddresses", Type = "address[]" },
            new MemberDescription { Name = "contractsChainId", Type = "uint256" },
            new MemberDescription { Name = "startTimestamp", Type = "uint256" },
            new MemberDescription { Name = "durationDays", Type = "uint256" },
            new MemberDescription { Name = "extraData", Type = "bytes" },
        ];

        MemberValue[] messageValues =
        [
            new MemberValue { TypeName = "bytes", Value = Helpers.Ensure0xPrefix(publicKey) }, // publicKey
            new MemberValue { TypeName = "address[]", Value = contractAddresses }, // contractAddresses
            new MemberValue { TypeName = "uint256", Value = fhevmConfig.ChainId }, // contractsChainId
            new MemberValue { TypeName = "uint256", Value = Helpers.DataTimeToTimestamp(startTime) },
            new MemberValue { TypeName = "uint256", Value = durationDays }, // durationDays
            new MemberValue { TypeName = "bytes", Value = extraData }, // extraData 
        ];

        // Thanks to https://github.com/Nethereum/Nethereum/blob/master/tests/Nethereum.Signer.UnitTests/Eip712TypedDataSignerTest.cs

        if (delegatedAccount != null)
        {
            return new TypedData<Domain>
            {
                Domain = domain,
                Types = new Dictionary<string, MemberDescription[]>
                {
                    ["EIP712Domain"] = eip712DomainTypes,
                    ["DelegatedUserDecryptRequestVerification"] = [.. messageTypes, new MemberDescription { Name = "delegatedAccount", Type = "address" }],
                },
                PrimaryType = "DelegatedUserDecryptRequestVerification",
                Message = [.. messageValues, new MemberValue { TypeName = "address", Value = delegatedAccount }], // delegatedAccount
            };
        }

        return new TypedData<Domain>
        {
            Domain = domain,
            Types = new Dictionary<string, MemberDescription[]>
            {
                ["EIP712Domain"] = eip712DomainTypes,
                ["UserDecryptRequestVerification"] = messageTypes,
            },
            PrimaryType = "UserDecryptRequestVerification",
            Message = messageValues,
        };
    }
}
