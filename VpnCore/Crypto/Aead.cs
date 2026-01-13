using System;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace VpnCore.Crypto
{
    public sealed class Aead
    {
        private readonly byte[] _key;

        public Aead(byte[] key)
        {
            if (key.Length != 32)
            {
                throw new ArgumentException("Key must be 32 bytes for ChaCha20-Poly1305.", nameof(key));
            }

            _key = key;
        }

        public byte[] Encrypt(ulong nonce, byte[] plaintext, byte[] aad)
        {
            var cipher = new ChaCha20Poly1305();
            var parameters = new AeadParameters(new KeyParameter(_key), 128, NonceFromCounter(nonce), aad);
            cipher.Init(true, parameters);
            var output = new byte[cipher.GetOutputSize(plaintext.Length)];
            var len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            cipher.DoFinal(output, len);
            return output;
        }

        public byte[] Decrypt(ulong nonce, byte[] ciphertext, byte[] aad)
        {
            var cipher = new ChaCha20Poly1305();
            var parameters = new AeadParameters(new KeyParameter(_key), 128, NonceFromCounter(nonce), aad);
            cipher.Init(false, parameters);
            var output = new byte[cipher.GetOutputSize(ciphertext.Length)];
            var len = cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, output, 0);
            cipher.DoFinal(output, len);
            return output;
        }

        private static byte[] NonceFromCounter(ulong nonce)
        {
            var bytes = new byte[12];
            var counter = BitConverter.GetBytes(nonce);
            if (BitConverter.IsLittleEndian)
            {
                Array.Copy(counter, 0, bytes, 4, 8);
            }
            else
            {
                Array.Reverse(counter);
                Array.Copy(counter, 0, bytes, 4, 8);
            }
            return bytes;
        }

        public static byte[] GenerateKey()
        {
            var key = new byte[32];
            new SecureRandom().NextBytes(key);
            return key;
        }
    }
}
