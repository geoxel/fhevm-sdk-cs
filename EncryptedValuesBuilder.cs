using Fhe;
using Nethereum.Util;
using Nethermind.Int256; // https://github.com/NethermindEth/int256/tree/main
using RelayerSDK.Tools;
using System.Globalization;

namespace RelayerSDK;

public sealed class EncryptedValuesBuilder : IDisposable
{
    private readonly CompactCiphertextListBuilder _builder;

    private int _valueCount;
    private int _bitCount;
    private readonly List<FheValueType> _valueTypes = new();

    public EncryptedValuesBuilder(CompactPublicKeyInfo compactPublicKey)
    {
        _builder = CompactCiphertextListBuilder.Create(compactPublicKey.PublicKey);
    }

    public void Dispose()
    {
        _builder.Dispose();
    }

    private void CheckLimit(FheValueType valueType)
    {
        int addedBits = FheValueHelper.GetBitCount(valueType);

        if (_bitCount + addedBits > 2048)
            throw new InvalidOperationException("Packing more than 2048 bits in a single input ciphertext is not supported");

        if (_valueCount + 1 > 256)
            throw new InvalidOperationException("Packing more than 256 variables in a single input ciphertext is not supported");

        _bitCount += addedBits;
        ++_valueCount;
        _valueTypes.Add(valueType);
    }

    internal IReadOnlyList<FheValueType> GetValueTypes() =>
        _valueTypes;

    public EncryptedValuesBuilder PushBool(bool value)
    {
        CheckLimit(FheValueType.Bool);
        _builder.PushBool(value);
        return this;
    }

    public EncryptedValuesBuilder PushU8(byte value)
    {
        CheckLimit(FheValueType.UInt8);
        _builder.PushU8(value);
        return this;
    }

    public EncryptedValuesBuilder PushU16(ushort value)
    {
        CheckLimit(FheValueType.UInt16);
        _builder.PushU16(value);
        return this;
    }

    public EncryptedValuesBuilder PushU32(uint value)
    {
        CheckLimit(FheValueType.UInt32);
        _builder.PushU32(value);
        return this;
    }

    public EncryptedValuesBuilder PushU64(ulong value)
    {
        CheckLimit(FheValueType.UInt64);
        _builder.PushU64(value);
        return this;
    }

    public EncryptedValuesBuilder PushU128(UInt128 value)
    {
        CheckLimit(FheValueType.UInt128);
        _builder.PushU128(value);
        return this;
    }

    public EncryptedValuesBuilder PushU256(UInt256 value)
    {
        CheckLimit(FheValueType.UInt256);
        _builder.PushU256(value);
        return this;
    }

    public EncryptedValuesBuilder PushAddress(string value)
    {
        if (!AddressHelper.IsAddress(value))
            throw new InvalidDataException("Invalid address");

        CheckLimit(FheValueType.Address);
        _builder.Push160(UInt256.Parse(Helpers.Remove0xIfAny(value), NumberStyles.HexNumber));
        return this;
    }

    /*
        public EncryptedValuesBuilder PushBytes64(ReadOnlySpan<byte> value)
        {
            if (value.Length != 64)
                throw new InvalidDataException("Invalid Span length, should be 64");

            CheckLimit(FheValueType.Bytes64);
            //const bigIntValue = bytesToBigInt(value);
            builder.push_u512(bigIntValue);

            return this;
        }

        public EncryptedValuesBuilder PushBytes128(ReadOnlySpan<byte> value)
        {
            if (value.Length != 128)
                throw new InvalidDataException("Invalid Span length, should be 128");

            checkLimit(FheValueType.Bytes128);
            //const bigIntValue = bytesToBigInt(value);
            builder.push_u1024(bigIntValue);

            return this;
        }

        public EncryptedValuesBuilder PushBytes256(ReadOnlySpan<byte> value)
        {
            if (value.Length != 256)
                throw new InvalidDataException("Invalid Span length, should be 256");

            CheckLimit(FheValueType.Bytes256);
            //const bigIntValue = bytesToBigInt(value);
            builder.push_u2048(bigIntValue);

            return this;
        }
    */

    internal byte[] Encrypt(
        PublicParamsInfo publicParams,
        string aclContractAddress,
        ulong chainId,
        string contractAddress,
        string userAddress)
    {
        byte[] auxData =
        [
            .. Convert.FromHexString(Helpers.Remove0xIfAny(contractAddress)),
            .. Convert.FromHexString(Helpers.Remove0xIfAny(userAddress)),
            .. Convert.FromHexString(Helpers.Remove0xIfAny(aclContractAddress)),
            .. Convert.FromHexString($"{chainId:X64}"),
        ];

        using var provenCompactCiphertextList = ProvenCompactCiphertextList.BuildWithProof(
            _builder,
            publicParams.PublicParams,
            auxData,
            ZkComputeLoad.Verify);

        return provenCompactCiphertextList.SafeSerialize();
    }
}
