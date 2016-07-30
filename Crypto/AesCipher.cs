using System;
using System.Security.Cryptography;

namespace MaplePacketLib.Crypto {
    public sealed class AesCipher {
        private readonly ICryptoTransform crypto;

        public AesCipher(byte[] aesKey) {
            if (aesKey == null) {
                throw new ArgumentNullException(nameof(aesKey));
            } else if (aesKey.Length != 32) {
                throw new ArgumentOutOfRangeException("Key length needs to be 32");
            }

            var aes = new RijndaelManaged {
                Key = aesKey,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.PKCS7
            };

            using (aes) {
                crypto = aes.CreateEncryptor();
            }
        }

        internal void Transform(byte[] data, byte[] iv) {
            byte[] morphKey = new byte[16];
            int remaining = data.Length;
            int start = 0;
            int length = 0x5B0;

            while (remaining > 0) {
                for (int i = 0; i < 16; i++) {
                    morphKey[i] = iv[i % 4];
                }

                if (remaining < length) {
                    length = remaining;
                }

                for (int index = start; index < start + length; index++) {
                    if ((index - start) % 16 == 0) {
                        crypto.TransformBlock(morphKey, 0, 16, morphKey, 0);
                    }

                    data[index] ^= morphKey[(index - start) % 16];
                }

                start += length;
                remaining -= length;
                length = 0x5B4;
            }
        }
    }
}
