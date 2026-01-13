using VpnCore.Crypto;

Console.WriteLine("BeyondVPN CLI diagnostics");
var kex = KeyExchange.Generate();
Console.WriteLine($"Public key: {Convert.ToBase64String(kex.PublicKey)}");
