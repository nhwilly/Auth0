using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Components.Authorization;

namespace SharedAuth
{
    public class CustomAuthStateJsonConverter : JsonConverter<CustomAuthenticationStateData>
    {
        public override bool CanConvert(Type type)
        {
            return type.IsAssignableFrom(typeof(AuthenticationStateData));
        }

        public override CustomAuthenticationStateData Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.StartObject)
            {
                throw new JsonException("Token type is not JsonTokenType.StartObject. Is this even valid Json?");
            }
            if (JsonDocument.TryParseValue(ref reader, out var doc))
            {
                if (doc.RootElement.TryGetProperty("CustomStateData", out var type))
                {
                    var typeValue = type.GetString();
                    var rootElement = doc.RootElement.GetRawText();

                    return typeValue switch
                    {
                        "true" => JsonSerializer.Deserialize<CustomAuthenticationStateData>(rootElement, options)!,
                        "false" => JsonSerializer.Deserialize<CustomAuthenticationStateData>(rootElement, options)!,
                        _ => throw new JsonException($"{typeValue} has not been mapped to a custom type yet!")
                    };
                }

                throw new JsonException("Failed to extract type property, it might be missing?");
            }

            throw new JsonException("Failed to parse JsonDocument");

        }
        public override void Write(Utf8JsonWriter writer, CustomAuthenticationStateData value, JsonSerializerOptions options)
        {
            throw new NotImplementedException();
        }
    }
    public class CustomAuthStateJsonConverter2 : JsonConverter<AuthenticationStateData>
    {
        public override bool CanConvert(Type type)
        {
            return type.IsAssignableFrom(typeof(AuthenticationStateData));
        }

        public override AuthenticationStateData Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.StartObject)
            {
                throw new JsonException("Token type is not JsonTokenType.StartObject. Is this even valid Json?");
            }
            if (JsonDocument.TryParseValue(ref reader, out var doc))
            {
                if (doc.RootElement.TryGetProperty("CustomStateData", out var type))
                {
                    var typeValue = type.GetString();
                    var rootElement = doc.RootElement.GetRawText();

                    return typeValue switch
                    {
                        "true" => JsonSerializer.Deserialize<AuthenticationStateData>(rootElement, options)!,
                        "false" => JsonSerializer.Deserialize<AuthenticationStateData>(rootElement, options)!,
                        _ => throw new JsonException($"{typeValue} has not been mapped to a custom type yet!")
                    };
                }

                throw new JsonException("Failed to extract type property, it might be missing?");
            }

            throw new JsonException("Failed to parse JsonDocument");

        }
        public override void Write(Utf8JsonWriter writer, AuthenticationStateData value, JsonSerializerOptions options)
        {
            throw new NotImplementedException();
        }
    }
}