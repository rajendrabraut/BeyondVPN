using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace VpnCore.Crypto
{
    public sealed class KeyExchange
    {
        private readonly X25519PrivateKeyParameters _privateKey;
        public byte[] PublicKey { get; }

        private KeyExchange(X25519PrivateKeyParameters privateKey)
        {
            _privateKey = privateKey;
            PublicKey = privateKey.GeneratePublicKey().GetEncoded();
        }

        public static KeyExchange Generate()
        {
            var random = new SecureRandom();
            var privateKey = new X25519PrivateKeyParameters(random);
            return new KeyExchange(privateKey);
        }

        public byte[] DeriveSharedKey(byte[] peerPublicKey)
        {
            var peer = new X25519PublicKeyParameters(peerPublicKey, 0);
            var agreement = new X25519Agreement();
            agreement.Init(_privateKey);
            var shared = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(peer, shared, 0);
            return shared;
        }
    }
}
