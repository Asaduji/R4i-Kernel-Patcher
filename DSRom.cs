namespace R4i_Kernel_Patcher
{
    internal class DSRom
    {
        private readonly byte[] _data;
        public int Arm9Offset { get; private set; }
        public int Arm9EntryAddress { get; private set; }
        public int Arm9Size { get; private set; }
        public int Arm7Offset { get; private set; }
        public int Arm7EntryAddress { get; private set; }
        public int Arm7Size { get; private set; }
        public DSRom(byte[] data)
        {
            _data = data;

            ParseHeader();
        }

        private void ParseHeader()
        {
            Arm9Offset = _data[0x20] | (_data[0x21] << 8) | (_data[0x22] << 16) | (_data[0x23] << 24);
            Arm9EntryAddress = _data[0x24] | (_data[0x25] << 8) | (_data[0x26] << 16) | (_data[0x27] << 24);
            Arm9Size = _data[0x2C] | (_data[0x2D] << 8) | (_data[0x2E] << 16) | (_data[0x2F] << 24);

            Arm7Offset = _data[0x30] | (_data[0x31] << 8) | (_data[0x32] << 16) | (_data[0x33] << 24);
            Arm7EntryAddress = _data[0x34] | (_data[0x35] << 8) | (_data[0x36] << 16) | (_data[0x37] << 24);
            Arm7Size = _data[0x3C] | (_data[0x3D] << 8) | (_data[0x3E] << 16) | (_data[0x3F] << 24);
        }

        public Span<byte> GetArm9Data()
        {
            return _data.AsSpan(Arm9Offset, Arm9Size);
        }

        public Span<byte> GetArm7Data()
        {
            return _data.AsSpan(Arm7Offset, Arm7Size);
        }

        public byte[] GetRomData()
        {
            return _data;
        }
    }
}
