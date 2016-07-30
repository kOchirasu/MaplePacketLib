using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using MaplePacketLib.Crypto;

namespace MaplePacketLib {
    public sealed class Connector {
        private readonly IPAddress ip;
        private readonly short port;
        private readonly AesCipher aesCipher;

        public event EventHandler<Session> OnConnected;
        public event EventHandler<SocketError> OnError;

        public Connector(IPAddress ip, short port, AesCipher aesCipher) {
            this.ip = ip;
            this.port = port;
            this.aesCipher = aesCipher;
        }

        public void Connect(int timeout = 13000) {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.DontLinger, true);
            var iar = socket.BeginConnect(ip, port, EndConnect, socket);
            iar.AsyncWaitHandle.WaitOne(timeout, true);
            if (!socket.Connected) {
                socket.Close(); //Do I want to close the client?
                throw new SocketException(10060); //Connection timeout
            }
        }

        private void EndConnect(IAsyncResult iar) {
            var socket = iar.AsyncState as Socket;

            try {
                socket.EndConnect(iar);
                if (socket.Connected) {
                    var session = new Session(socket, SessionType.CLIENT, aesCipher);
                    OnConnected?.Invoke(this, session);
                    session.Start(null);
                } else {
                    Connect(); // Failed to connect. Try again
                }
            } catch (SocketException ex) {
                OnError?.Invoke(this, ex.SocketErrorCode);
            }
        }
    }
}
