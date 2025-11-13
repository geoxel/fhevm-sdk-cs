using Nethereum.ABI;
using Nethereum.ABI.EIP712;
using Nethereum.Contracts;
using Nethereum.Signer;
using Nethereum.Signer.EIP712;
using Nethereum.Web3;
using Nethereum.Web3.Accounts;
using Nethereum.Hex.HexTypes;

using FhevmSDK.Kms;
using FhevmSDK.Tools;
using System.CommandLine;
using System.CommandLine.Parsing;
using System.Configuration.Assemblies;
using System.Numerics;
using System.Text.Json;
using System.Reflection.Metadata;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace FhevmSDK;

public static class CounterClient
{
    private static IReadOnlyList<string>? _kmsSigners;
    private static int _kmsSignersThreshold;

    private static IReadOnlyList<string>? _coprocessorSigners;
    private static int _coprocessorSignersThreshold;

    private static string? _ethPrivateKey;
    private static string? _infuraApiKey;

    public static Config ReadConfig()
    {
        string configFilename = "Config.json";

        Console.WriteLine($"Reading config from file {configFilename}...");

        Config config =
            JsonSerializer.Deserialize<Config>(File.ReadAllText(configFilename))
            ?? throw new InvalidDataException("Invalid json config file.");

        config.FHECounterContractAddress = Helpers.Ensure0xPrefix(config.FHECounterContractAddress ?? "");
        if (!AddressHelper.IsAddress(config.FHECounterContractAddress))
            throw new InvalidDataException("Invalid contract address: {config.FHECounterContractAddress}");

        if (!AddressHelper.IsAddress(config.UserAddress ?? ""))
            throw new InvalidDataException($"Invalid user address: {config.UserAddress}");

        _ethPrivateKey = config.EthPrivateKey;
        if (string.IsNullOrWhiteSpace(_ethPrivateKey))
        {
            Console.Write("Enter the ETH private key: ");
            _ethPrivateKey = ConsoleReadPassword.Read();
        }
        _ethPrivateKey = _ethPrivateKey.Trim();
        if (_ethPrivateKey.Length != 64)
            throw new InvalidDataException("Invalid ETH private key.");

        _infuraApiKey = config.InfuraApiKey;
        if (string.IsNullOrWhiteSpace(_infuraApiKey))
        {
            Console.Write("Enter the Infura API key: ");
            _infuraApiKey = ConsoleReadPassword.Read();
        }
        _infuraApiKey = _infuraApiKey.Trim();

        return config;
    }

    private static Web3 CreateWeb3(FhevmConfig fhevmConfig)
    {
        Account account = new(_ethPrivateKey!);

        string rpcUrl = $"{fhevmConfig.InfuraUrl}/{_infuraApiKey}";

        Web3 web3 = new(account, rpcUrl);
        web3.TransactionManager.DefaultGas = new BigInteger(500_000);

        return web3;
    }

    private static async Task<(IReadOnlyList<string> kmsSigners, int kmsSignersThreshold)> GetKMSSigners(FhevmConfig fhevmConfig)
    {
        if (_kmsSigners == null)
        {
            const string KmsVerifierAbi =
            @"[
                {
                    'constant': true,
                    'inputs': [],
                    'name': 'getKmsSigners',
                    'outputs': [ { 'name': '', 'type': 'address[]' } ],
                    'type': 'function'
                },
                {
                    'constant': true,
                    'inputs': [],
                    'name': 'getThreshold',
                    'outputs': [ { 'name': '', 'type': 'uint256' } ],
                    'type': 'function'
                }
            ]";

            Web3 web3 = CreateWeb3(fhevmConfig);

            Contract contract = web3.Eth.GetContract(KmsVerifierAbi, fhevmConfig.KmsContractAddress);

            Function getKmsSignersFunction = contract.GetFunction("getKmsSigners");
            Function getThresholdFunction = contract.GetFunction("getThreshold");

            _kmsSigners = await getKmsSignersFunction.CallAsync<List<string>>();
            _kmsSignersThreshold = await getThresholdFunction.CallAsync<int>();
        }

        return (_kmsSigners, _kmsSignersThreshold);
    }

    private static async Task<(IReadOnlyList<string> coprocessorSigners, int coprocessorSignersThreshold)> GetCoprocessorSigners(FhevmConfig fhevmConfig)
    {
        if (_coprocessorSigners == null)
        {
            const string InputVerifierAbi =
            @"[
                {
                    'constant': true,
                    'inputs': [],
                    'name': 'getCoprocessorSigners',
                    'outputs': [ { 'name': '', 'type': 'address[]' } ],
                    'type': 'function'
                },
                {
                    'constant': true,
                    'inputs': [],
                    'name': 'getThreshold',
                    'outputs': [ { 'name': '', 'type': 'uint256' } ],
                    'type': 'function'
                }
            ]";

            Web3 web3 = CreateWeb3(fhevmConfig);

            Contract contract = web3.Eth.GetContract(InputVerifierAbi, fhevmConfig.InputVerifierContractAddress);

            Function getCoprocessorSignersFunction = contract.GetFunction("getCoprocessorSigners");
            Function getThresholdFunction = contract.GetFunction("getThreshold");

            _coprocessorSigners = await getCoprocessorSignersFunction.CallAsync<List<string>>();
            _coprocessorSignersThreshold = await getThresholdFunction.CallAsync<int>();
        }

        return (_coprocessorSigners, _coprocessorSignersThreshold);
    }

    private static Contract GetFHECounterContract(Config config, FhevmConfig fhevmConfig)
    {
        const string FHECounterAbi =
        @"[
            {
                'constant': false,
                'inputs': [
                    { 'name': 'inputEuint32', 'internalType': 'externalEint32', 'type': 'bytes32' },
                    { 'name': 'inputProof',   'internalType': 'bytes',          'type': 'bytes'   }
                ],
                'name': 'increment',
                'outputs': [],
                'type': 'function'
            },
            {
                'constant': false,
                'inputs': [
                    { 'name': 'inputEuint32', 'internalType': 'externalEint32', 'type': 'bytes32' },
                    { 'name': 'inputProof',   'internalType': 'bytes',          'type': 'bytes'   }
                ],
                'name': 'decrement',
                'outputs': [],
                'type': 'function'
            },
            {
                'constant': true,
                'inputs': [],
                'name': 'getCount',
                'outputs': [ { 'name': '', 'internalType': 'euint32', 'type': 'bytes32' } ],
                'type': 'function'
            }
        ]";

        Web3 web3 = CreateWeb3(fhevmConfig);

        return web3.Eth.GetContract(FHECounterAbi, config.FHECounterContractAddress);
    }

    public static async Task<byte[]> RetrieveCurrentFHECounterHandle(Contract contract)
    {
        Function getCountFunction = contract.GetFunction("getCount");

        return await getCountFunction.CallAsync<byte[]>();
    }

    public static (string localPublicKey, string localPrivateKey) GenerateKeyPair()
    {
        using PrivateEncKeyMlKem512 privateKey = PrivateEncKeyMlKem512.Generate();
        using PublicEncKeyMlKem512 publicKey = PublicEncKeyMlKem512.FromPrivateKey(privateKey);

        return
        (
            localPublicKey: Convert.ToHexString(publicKey.Serialize()),
            localPrivateKey: Convert.ToHexString(privateKey.Serialize())
        );
    }

    public static async Task PrintFHECounterHandle(Config config, FhevmConfig fhevmConfig)
    {
        Console.WriteLine($"Retrieving FHECounter contract {config.FHECounterContractAddress}...");

        Contract contract = GetFHECounterContract(config, fhevmConfig);

        byte[] counterHandleBytes = await RetrieveCurrentFHECounterHandle(contract);
        string counterHandle = Helpers.To0xHexString(counterHandleBytes);

        Console.WriteLine($"Counter handle: {counterHandle} (encrypted type: {HandleHelper.GetValueType(counterHandle)})");
    }

    public static async Task DecryptFHECounterValue(Config config, FhevmConfig fhevmConfig)
    {
        Console.WriteLine($"Retrieving FHECounter contract {config.FHECounterContractAddress}...");

        Contract contract = GetFHECounterContract(config, fhevmConfig);

        byte[] counterHandleBytes = await RetrieveCurrentFHECounterHandle(contract);
        string counterHandle = Helpers.To0xHexString(counterHandleBytes);

        Console.WriteLine("Generating key pair...");

        (string localPublicKey, string localPrivateKey) = GenerateKeyPair();

        Console.WriteLine("Creating EIP-712 typed data...");

        var now = DateTimeOffset.Now;

        TypedData<Domain> typedData = Eip712.Create(
            fhevmConfig,
            localPublicKey,
            contractAddresses: [config.FHECounterContractAddress],
            startTime: now,
            durationDays: 365,
            delegatedAccount: null);

        Console.WriteLine("Signing EIP-712 typed data...");

        var signer = Eip712TypedDataSigner.Current;
        var ethPrivateKey = new EthECKey(_ethPrivateKey!);

        string eip712Signature = signer.SignTypedDataV4(typedData, ethPrivateKey);

        Console.WriteLine($"EIP-712 signature: {eip712Signature}");

        Console.WriteLine("Retrieving KMS signers...");

        (IReadOnlyList<string> kmsSigners, int kmsSignersThreshold) = await GetKMSSigners(fhevmConfig);

        Console.WriteLine("Decrypting handle...");

        using UserDecrypt decrypt = new(fhevmConfig, kmsSigners);

        HandleContractPair[] handleContractPairs =
        [
            new HandleContractPair
            {
                Handle = counterHandle,
                ContractAddress = config.FHECounterContractAddress,
            },
        ];

        Dictionary<string, object> result = await decrypt.Decrypt(
            handleContractPairs,
            localPrivateKey,
            localPublicKey,
            eip712Signature,
            contractAddresses: [config.FHECounterContractAddress],
            config.UserAddress,
            startTime: now,
            durationDays: 365);

        object value = result[counterHandle];

        Console.WriteLine("Success:");

        Console.WriteLine($"Counter handle: {counterHandle} (encrypted type: {HandleHelper.GetValueType(counterHandle)})");
        Console.WriteLine($"Counter value : {value} (C# type: {value.GetType()})");
    }

    public static async Task AddToFHECounter(Config config, FhevmConfig fhevmConfig, int value)
    {
        Console.WriteLine("Retrieving keys from Zama server...");

        using var fhevmKeys = new FhevmKeys();
        FhevmKeys.Keys keys = await fhevmKeys.GetOrDownload(fhevmConfig.RelayerUrl);

        Console.WriteLine($"Encrypting input value ({Math.Abs(value)})...");

        string contractAddress = config.FHECounterContractAddress;
        string userAddress = config.UserAddress;

        (IReadOnlyList<string> coprocessorSigners, int coprocessorSignersThreshold) = await GetCoprocessorSigners(fhevmConfig);

        using EncryptedValuesBuilder builder = new(keys.CompactPublicKeyInfo);
        builder.PushU32((uint)Math.Abs(value));

        FhevmEncryptedValues encryptedValues = await FhevmEncrypter.Encrypt(
            fhevmConfig,
            builder,
            keys.PublicParamsInfo,
            coprocessorSigners,
            coprocessorSignersThreshold,
            contractAddress,
            userAddress);

        Console.WriteLine($"Encrypted input value handle: {encryptedValues.Handles[0]}");
        Console.WriteLine($"Encrypted input value proof: {encryptedValues.InputProof}");

        Console.WriteLine($"Retrieving FHECounter contract {config.FHECounterContractAddress}...");

        Contract contract = GetFHECounterContract(config, fhevmConfig);

        string functionName = value >= 0 ? "increment" : "decrement";

        Console.WriteLine($"Calling {functionName}() function...");

        Function inc_dec_Function = contract.GetFunction(functionName);

        Nethereum.RPC.Eth.DTOs.TransactionReceipt txReceipt = await inc_dec_Function.SendTransactionAndWaitForReceiptAsync(
            config.UserAddress,
            CancellationToken.None,
            Convert.FromHexString(Helpers.Remove0xIfAny(encryptedValues.Handles[0])),
            Convert.FromHexString(Helpers.Remove0xIfAny(encryptedValues.InputProof)));

        Console.WriteLine($"Transaction hash: {txReceipt.TransactionHash}");
        Console.WriteLine($"Block number: {txReceipt.BlockNumber}");
        Console.WriteLine($"Gas used: {txReceipt.GasUsed}");

        byte[] counterHandleBytes = await RetrieveCurrentFHECounterHandle(contract);
        string counterHandle = Helpers.To0xHexString(counterHandleBytes);

        Console.WriteLine($"New FHE Counter handle: {counterHandle}");
    }

    public static async Task<int> Main(string[] args)
    {
        FhevmSepoliaConfig fhevmConfig = new();

        Config config;
        try
        {
            config = ReadConfig();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            return 1;
        }

        RootCommand rootCommand = new("Simple THECounter client app on Sepolia");

        Option<int> valueOption = new("--value")
        {
            Description = "Value to add or substract from the FHE counter",
            Required = true,
        };

        Command printCounterHandleCommand = new("print-counter-handle", "Print the FHE counter handle.");
        Command decryptCounterValueCommand = new("decrypt-counter-value", "Decrypt and print FHE counter value.");
        Command incrementCommand = new("increment", "Increment counter.") { valueOption };
        Command decrementCommand = new("decrement", "Decrement counter.") { valueOption };

        rootCommand.Subcommands.Add(printCounterHandleCommand);
        rootCommand.Subcommands.Add(decryptCounterValueCommand);
        rootCommand.Subcommands.Add(incrementCommand);
        rootCommand.Subcommands.Add(decrementCommand);

        printCounterHandleCommand.SetAction(async _ => await PrintFHECounterHandle(config, fhevmConfig));
        decryptCounterValueCommand.SetAction(async _ => await DecryptFHECounterValue(config, fhevmConfig));
        incrementCommand.SetAction(async parseResult => await AddToFHECounter(config, fhevmConfig, parseResult.GetValue(valueOption)));
        decrementCommand.SetAction(async parseResult => await AddToFHECounter(config, fhevmConfig, -parseResult.GetValue(valueOption)));

        ParseResult parseResult = rootCommand.Parse(args);
        return parseResult.Invoke();
    }
}
