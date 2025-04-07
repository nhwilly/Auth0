using Microsoft.AspNetCore.Components.Authorization;

namespace SharedAuth;

public class IdentityData
{
  public required string AuthenticationType { get; init; } = string.Empty;
  public bool IsAuthenticated { get; init; } 
  public required string Name { get; init; } = string.Empty;
  public List<ClaimDto> Claims { get; init; } = [];
}

public class ClaimDto
{
  public required string Type { get; init; } = string.Empty;
  public required string Value { get; init; } = string.Empty;
  public required string Issuer { get; init; } = string.Empty;
  
}