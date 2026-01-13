using System;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace VpnCore.Crypto
{
    public static class Kdf
    {
        public static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length)
        {
            var prk = HmacSha256(salt, ikm);
            var okm = new byte[length];
            var hashLen = 32;
            var n = (int)Math.Ceiling(length / (double)hashLen);
            var t = Array.Empty<byte>();
            var offset = 0;

            for (var i = 1; i <= n; i++)
            {
                var hmac = new HMac(new Sha256Digest());
                hmac.Init(new KeyParameter(prk));
                hmac.BlockUpdate(t, 0, t.Length);
                hmac.BlockUpdate(info, 0, info.Length);
                hmac.Update((byte)i);
                t = new byte[hmac.GetMacSize()];
                hmac.DoFinal(t, 0);

                var toCopy = Math.Min(hashLen, length - offset);
                Array.Copy(t, 0, okm, offset, toCopy);
                offset += toCopy;
            }

            return okm;
        }

        private static byte[] HmacSha256(byte[] key, byte[] data)
        {
            var hmac = new HMac(new Sha256Digest());
            hmac.Init(new KeyParameter(key));
            hmac.BlockUpdate(data, 0, data.Length);
            var output = new byte[hmac.GetMacSize()];
            hmac.DoFinal(output, 0);
            return output;
        }
    }
}
