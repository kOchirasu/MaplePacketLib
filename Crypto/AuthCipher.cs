using System;
using System.Threading;
using MaplePacketLib.Tools;

namespace MaplePacketLib.Crypto {
    public static class AuthCipher {
        private const short PRIMARY_LENGTH = 4;
        private const short SECONDARY_LENGTH = 16;

        private static int rngSeed = Environment.TickCount;

        private static readonly ThreadLocal<Random> rng =
            new ThreadLocal<Random>(() => new Random(Interlocked.Increment(ref rngSeed)));

        private static readonly uint[] xorTable = {
            0x040FC1578, 0x0113B6C1F, 0x08389CA19, 0x0E2196CD8,
            0x074901489, 0x04AAB1566, 0x07B8C12A0, 0x00018FFCD,
            0x0CCAB704B, 0x07B5A8C0F, 0x0AA13B891, 0x0DE419807,
            0x012FFBCAE, 0x05F5FBA34, 0x010F5AC99, 0x0B1C1DD01
        };

        private static unsafe void Encrypt(byte[] buffer, uint seed) {
            uint prev = 0;
            fixed (byte* ptr = buffer) {
                for (int i = 0; i < buffer.Length - 3; i += 4) {
                    uint temp = seed ^ prev ^ xorTable[i / 4 % 16];
                    prev = *(uint*) (ptr + i);
                    *(uint*) (ptr + i) ^= temp;
                }
            }
        }

        private static unsafe void Decrypt(byte[] buffer, uint seed) {
            uint prev = 0;
            fixed (byte* ptr = buffer) {
                for (int i = 0; i < buffer.Length - 3; i += 4) {
                    *(uint*) (ptr + i) ^= seed ^ prev ^ xorTable[i / 4 % 16];
                    prev = *(uint*) (ptr + i);
                }
            }
        }

        internal static byte[] WriteHeader(short header, byte[] code, byte[] data) {
            uint seed = (uint) rng.Value.Next();
            Encrypt(data, seed);

            var pw = new PacketWriter();
            pw.WriteShortBigEndian((short) (SECONDARY_LENGTH + data.Length));
            pw.WriteShortBigEndian(header);
            pw.WriteBytes(0x18, 0x00);
            pw.WriteShortBigEndian((short) (SECONDARY_LENGTH - PRIMARY_LENGTH + data.Length));
            pw.WriteBytes(0x02, 0x00);
            pw.WriteShortBigEndian((short) data.Length);
            pw.WriteIntBigEndian((int) seed);
            pw.WriteBytes(code);
            pw.WriteBytes(data);

            return pw.ToArray();
        }

        internal static unsafe byte[] ReadHeader(byte[] packet) {
            fixed (byte* ptr = packet) {
                // 10 useless bytes
                short length = (short) (*(ptr + 10) << 8 | *(ptr + 11));
                uint seed = (uint) (*(ptr + 12) << 24 | *(ptr + 13) << 16 | *(ptr + 14) << 8 | *(ptr + 15));
                // 4 useless bytes
                byte[] data = new byte[length];
                Buffer.BlockCopy(packet, PRIMARY_LENGTH + SECONDARY_LENGTH, data, 0, length);
                Decrypt(data, seed);

                return data;
            }
        }
    }
}
