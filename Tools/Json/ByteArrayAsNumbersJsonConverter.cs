using System.Text.Json;
using System.Text.Json.Serialization;

namespace FhevmSDK.Tools.Json;

public class ByteArrayAsNumbersJsonConverter : JsonConverter<byte[]>
{
    public override byte[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        List<byte> bytes = new();
        while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
            bytes.Add(reader.GetByte());

        return bytes.ToArray();
    }

    public override void Write(Utf8JsonWriter writer, byte[] value, JsonSerializerOptions options)
    {
        writer.WriteStartArray();

        foreach (byte b in value)
            writer.WriteNumberValue(b);

        writer.WriteEndArray();
    }
}
