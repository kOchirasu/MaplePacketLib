namespace MaplePacketLib {
    public sealed class ServerInfo {
        public short Version { get; set; }
        public string Subversion { get; set; }
        public byte[] SIV { get; set; }
        public byte[] RIV { get; set; }
        public byte Locale { get; set; }
    }
}
