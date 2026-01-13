namespace VpnCore.Protocol
{
    public enum MessageType : byte
    {
        Hello = 1,
        Auth = 2,
        KeyExchange = 3,
        Policy = 4,
        Routes = 5,
        Data = 6,
        Ping = 7,
        Pong = 8,
        Rekey = 9,
        Error = 10
    }
}
