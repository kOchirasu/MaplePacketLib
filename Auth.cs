using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using MaplePacketLib.Crypto;
using MaplePacketLib.Tools;

namespace MaplePacketLib {
    internal static class Auth {
        private const short AUTH_1 = 0x33;
        private const short AUTH_2 = 0x2D;
        private const short AUTH_3 = 0x35;
        private const ushort AUTH_PORT = 47611;

        private static readonly byte[] authKey1 = { 0x1D, 0x6A, 0x20, 0xCE };
        private static readonly byte[] authKey2 = { 0xEB, 0x29, 0x72, 0x32 };
        private static readonly byte[] authKey3 = { 0xF7, 0xDD, 0xB3, 0x35 };

        private static readonly IPAddress[] authIps = {
            IPAddress.Parse("208.85.110.164"),
            IPAddress.Parse("208.85.110.166"),
            IPAddress.Parse("208.85.110.169"),
            IPAddress.Parse("208.85.110.170"),
            IPAddress.Parse("208.85.110.171")
        };

        private static int rngSeed = Environment.TickCount;

        private static readonly ThreadLocal<Random> rng =
            new ThreadLocal<Random>(() => new Random(Interlocked.Increment(ref rngSeed)));

        private static readonly ThreadLocal<byte[]> buffer = new ThreadLocal<byte[]>(() => new byte[1024]);

        public static string GetAuth(string username, string password) {
            string auth = string.Empty;
            for (int i = 1; i <= 3; ++i) {
                var authSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                authSocket.Connect(authIps, AUTH_PORT);
                switch (i) {
                    case 1:
                        authSocket.Send(AuthFirst(username, password));
                        int length = authSocket.Receive(buffer.Value);
                        if (length == 0) {
                            i = 3; // Skip the rest of the auths
                            Debug.WriteLine("Invalid username or password");
                        } else {
                            auth = ParseAuth(buffer.Value);
                        }
                        break;
                    case 2:
                        authSocket.Send(AuthSecond(auth));
                        authSocket.Receive(buffer.Value);
                        break;
                    case 3:
                        authSocket.Send(AuthThird(auth));
                        authSocket.Receive(buffer.Value);
                        break;
                    default:
                        Debug.WriteLine(i + " isn't even a valid auth sequence.");
                        break;
                }
                authSocket.Shutdown(SocketShutdown.Both);
                authSocket.Close();
            }

            return auth;
        }

        private static byte[] AuthFirst(string user, string pass) {
            var data = new PacketWriter();
            data.WriteInt(8);
            data.WriteUnicodeString(user);
            data.WriteUnicodeString(pass);
            data.WriteBytes(0x00, 0x00, 0x13, 0x22, 0x00, 0x02, 0x01, 0x00);
            data.WriteZero(10);
            data.WriteUnicodeString(GetRandomString(23)); // 23 Random characters (Length 46 as unicode)
            data.WriteInt(1);
            data.WriteZero(2);

            return AuthCipher.WriteHeader(AUTH_1, authKey1, data.ToArray());
        }

        private static byte[] AuthSecond(string auth) {
            var data = new PacketWriter();
            data.WriteUnicodeString(auth);

            return AuthCipher.WriteHeader(AUTH_2, authKey2, data.ToArray());
        }

        private static byte[] AuthThird(string auth) {
            var data = new PacketWriter();
            data.WriteInt(2);
            data.WriteUnicodeString(auth);
            data.WriteBytes(0x13, 0x22, 0x00, 0x02);

            return AuthCipher.WriteHeader(AUTH_3, authKey3, data.ToArray());
        }

        private static string ParseAuth(byte[] packet) {
            byte[] data = AuthCipher.ReadHeader(packet);
            var pr = new PacketReader(data);
            pr.Skip(10);

            return pr.ReadUnicodeString();
        }

        // Generates a random alphanumeric string
        private static string GetRandomString(int length) {
            const string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_~";
            var result = new StringBuilder(length);
            for (int i = 0; i < length; ++i) {
                result.Append(characters[rng.Value.Next(characters.Length)]);
            }
            return result.ToString();
        }
    }
}
