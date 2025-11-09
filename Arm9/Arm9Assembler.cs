using System.Numerics;

namespace R4i_Kernel_Patcher.Arm9
{
    internal class Arm9Assembler
    {
        private readonly List<byte> _buffer = [];

        //Maybe a bit hacky?
        public static bool TryGetImm(uint value, out byte imm8, out byte rotations)
        {
            for (var r = 0; r < 16; r++)
            {
                var rotated = BitOperations.RotateLeft(value, 2 * r);

                if ((rotated & 0xFFFFFF00) == 0)
                {
                    imm8 = (byte)rotated;
                    rotations = (byte)r;
                    return true;
                }
            }

            imm8 = 0;
            rotations = 0;
            return false;
        }

        public static List<int> GetImmValues(int value)
        {
            var values = new List<int>();

            while (value != 0)
            {
                for (var i = 0; i < 4; i++)
                {
                    var currentValue = value & (0xFF << (i * 8));

                    if (currentValue != 0)
                    {
                        values.Add(currentValue);

                        value &= ~currentValue;

                        break;
                    }
                }
            }

            return values;
        }

        public void Mov(Arm9Register to, Arm9Register from)
        {
            _buffer.Add((byte)from);
            _buffer.Add((byte)((byte)to << 4));
            _buffer.Add(0xA0);
            _buffer.Add(0xE1);
        }

        public void Mov(Arm9Register to, int value)
        {
            if (!TryGetImm((uint)value, out var imm8, out var rotate))
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Invalid immediate value");
            }

            _buffer.Add(imm8);
            _buffer.Add((byte)((rotate & 0x0F) | ((byte)to << 4)));
            _buffer.Add(0xA0);
            _buffer.Add(0xE3);
        }

        public void Add(Arm9Register to, Arm9Register from, int value)
        {
            if (!TryGetImm((uint)value, out var imm8, out var rotate))
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Invalid immediate value");
            }

            _buffer.Add(imm8);
            _buffer.Add((byte)((rotate & 0x0F) | ((byte)to << 4)));
            _buffer.Add((byte)(((byte)from & 0x0F) | (0x80)));
            _buffer.Add(0xE2);
        }

        public void Add(Arm9Register to, Arm9Register from, Arm9Register value)
        {
            _buffer.Add((byte)value);
            _buffer.Add((byte)((byte)to << 4));
            _buffer.Add((byte)(((byte)from & 0x0F) | (0x80)));
            _buffer.Add(0xE0);
        }

        public void Sub(Arm9Register to, Arm9Register from, int value)
        {
            if (!TryGetImm((uint)value, out var imm8, out var rotate))
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Invalid immediate value");
            }

            _buffer.Add(imm8);
            _buffer.Add((byte)((rotate & 0x0F) | ((byte)to << 4)));
            _buffer.Add((byte)(((byte)from & 0x0F) | (0x40)));
            _buffer.Add(0xE2);
        }

        public void Sub(Arm9Register to, Arm9Register from, Arm9Register value)
        {
            _buffer.Add((byte)value);
            _buffer.Add((byte)((byte)to << 4));
            _buffer.Add((byte)(((byte)from & 0x0F) | (0x40)));
            _buffer.Add(0xE0);
        }

        public void Push(Arm9Register[] registers)
        {
            var registerBits = GetRegisterBits(registers);

            _buffer.Add((byte)(registerBits & 0xFF));
            _buffer.Add((byte)((registerBits >> 8) & 0xFF));
            _buffer.Add(0x2D);
            _buffer.Add(0xE9);
        }

        public void Pop(Arm9Register[] registers)
        {
            var registerBits = GetRegisterBits(registers);

            _buffer.Add((byte)(registerBits & 0xFF));
            _buffer.Add((byte)((registerBits >> 8) & 0xFF));
            _buffer.Add(0xBD);
            _buffer.Add(0xE8);
        }

        public void Nop()
        {
            Mov(Arm9Register.R0, Arm9Register.R0);
        }

        public void Strb(Arm9Register to, Arm9Register from, byte value)
        {
            _buffer.Add(value);
            _buffer.Add((byte)((byte)to << 4));
            _buffer.Add((byte)(((byte)from & 0x0F) | (0xC0)));
            _buffer.Add(0xE5);
        }

        public void Blx(Arm9Register to)
        {
            _buffer.Add((byte)(((byte)to & 0x0F) | (0x30)));
            _buffer.Add(0xFF);
            _buffer.Add(0x2F);
            _buffer.Add(0xE1);
        }

        public void Bx(Arm9Register to)
        {
            _buffer.Add((byte)(((byte)to & 0x0F) | (0x10)));
            _buffer.Add(0xFF);
            _buffer.Add(0x2F);
            _buffer.Add(0xE1);
        }

        public void MovWord(Arm9Register to, int value)
        {
            var immValues = GetImmValues(value);

            Mov(to, immValues[0]);
            for (var i = 1; i < immValues.Count; i++)
            {
                Add(to, to, immValues[i]);
            }
        }

        public void B(int from, int to)
        {
            var offset = (to - (from + 8)) / 4;

            _buffer.Add((byte)offset);
            _buffer.Add((byte)(offset >> 8));
            _buffer.Add((byte)(offset >> 16));
            _buffer.Add(0xEA);
        }

        private static ushort GetRegisterBits(Arm9Register[] registers)
        {
            var registerBits = (ushort)0;

            foreach (var register in registers)
            {
                var registerBit = 1 << (byte)register;
                registerBits |= (ushort)registerBit;
            }

            return registerBits;
        }

        public byte[] GetBuffer()
        {
            return [.. _buffer];
        }
    }
}
