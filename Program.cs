using System.Runtime.InteropServices;
using System.Text.Json;
using R4i_Kernel_Patcher.Arm9;
using R4i_Kernel_Patcher.Patches;

namespace R4i_Kernel_Patcher
{
    internal class Program
    {
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNameCaseInsensitive = true
        };

        static void Main(string[] args)
        {
#if DEBUG
            args =
            [
                "R4.dat",
                "R4_patched.dat"
            ];
#endif
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: R4i_Kernel_Patcher <input_file> <output_file>");
                return;
            }

            var inputFileName = args[0];
            var outputFileName = args[1];
            var workingDir = Directory.GetCurrentDirectory();
            var inputFilePath = Path.Combine(workingDir, inputFileName);
            var outputFilePath = Path.Combine(workingDir, outputFileName);
            var patchSettingsFilePath = Path.Combine(workingDir, "patch_settings.json");

            if (!File.Exists(inputFilePath))
            {
                Console.WriteLine($"Input file '{inputFileName}' does not exist");

                return;
            }

            if (!File.Exists(patchSettingsFilePath))
            {
                Console.WriteLine($"Patch settings file 'patch_settings.json' does not exist");

                return;
            }

            var patchSettingsJson = File.ReadAllText(patchSettingsFilePath);
            var patchSettings = JsonSerializer.Deserialize<PatchSettings>(patchSettingsJson, _jsonOptions);

            if (patchSettings is null)
            {
                Console.WriteLine("Failed to deserialize patch settings");

                return;
            }

            Console.WriteLine("https://github.com/Asaduji/R4i-Kernel-Patcher");

            var kernelData = File.ReadAllBytes(inputFilePath);
            var kernelRom = new DSRom(kernelData);
            var patchedRom = new DSRom([.. kernelData]);

            if (!ApplyArm9Patches(kernelRom, patchedRom, patchSettings))
            {
                Console.WriteLine("Failed to apply ARM9 patches");
                return;
            }

            if (!ApplyArm7Patches(kernelRom, patchedRom, patchSettings))
            {
                Console.WriteLine("Failed to apply ARM7 patches");
                return;
            }

            File.WriteAllBytes(outputFilePath, patchedRom.GetRomData());

            Console.WriteLine($"Patched kernel saved to '{outputFileName}'");
        }

        private static bool ApplyArm9Patches(DSRom srcRom, DSRom patchedRom, PatchSettings patchSettings)
        {
            Console.WriteLine("Applying ARM9 patches...");

            var arm9PatchInfo = patchSettings.Arm9PatchInfo;
            var extraPatches = patchSettings.ExtraPatches;
            var srcData = srcRom.GetArm9Data();
            var patchedData = patchedRom.GetArm9Data();

            //Shellcode for second arm9 crc
            var assembler = new Arm9Assembler();

            //push r0-r12, r14
            assembler.Push([
                Arm9Register.R0,
                Arm9Register.R1,
                Arm9Register.R2,
                Arm9Register.R3,
                Arm9Register.R4,
                Arm9Register.R5,
                Arm9Register.R6,
                Arm9Register.R7,
                Arm9Register.R8,
                Arm9Register.R9,
                Arm9Register.R10,
                Arm9Register.R11,
                Arm9Register.R12,
                Arm9Register.R14
            ]);

            //store 100525c
            //mov r0, 01000000h
            //add r0, r0, 5200h
            //add r0, r0, 5ch
            assembler.MovWord(Arm9Register.R0, arm9PatchInfo.CRCStrhAddr);

            //NOP crc write 100525c
            //mov r1, 00h
            //strb r1, [r0, 00h]
            //strb r1, [r0, 01h]
            //mov r1, 0A0h
            //strb r1, [r0, 02h]
            //mov r1, 0E1h
            //strb r1, [r0, 03h]
            assembler.Mov(Arm9Register.R1, 0x00);
            assembler.Strb(Arm9Register.R1, Arm9Register.R0, 0x00);
            assembler.Strb(Arm9Register.R1, Arm9Register.R0, 0x01);
            assembler.Mov(Arm9Register.R1, 0xA0);
            assembler.Strb(Arm9Register.R1, Arm9Register.R0, 0x02);
            assembler.Mov(Arm9Register.R1, 0xE1);
            assembler.Strb(Arm9Register.R1, Arm9Register.R0, 0x03);

            //store 100526c
            //mov r0, 01000000h
            //add r0, r0, 5200h
            //add r0, r0, 6ch
            assembler.MovWord(Arm9Register.R0, arm9PatchInfo.CRCBltAddr);

            //NOP blt at 100526c
            //mov r1, 00h
            //strb r1, [r0, 00h]
            //strb r1, [r0, 01h]
            //mov r1, 0A0h
            //strb r1, [r0, 02h]
            //mov r1, 0E1h
            //strb r1, [r0, 03h]
            assembler.Mov(Arm9Register.R1, 0x00);
            assembler.Strb(Arm9Register.R1, Arm9Register.R0, 0x00);
            assembler.Strb(Arm9Register.R1, Arm9Register.R0, 0x01);
            assembler.Mov(Arm9Register.R1, 0xA0);
            assembler.Strb(Arm9Register.R1, Arm9Register.R0, 0x02);
            assembler.Mov(Arm9Register.R1, 0xE1);
            assembler.Strb(Arm9Register.R1, Arm9Register.R0, 0x03);

            //CRCs stored at 02350000
            //mov r0, 02000000h
            //add r0, r0, 350000h
            assembler.MovWord(Arm9Register.R0, arm9PatchInfo.CRCDataAddr);

            //crcs src 208F4F0
            //mov r1, 02000000h
            //add r1, r1, 08F000h
            //add r1, r1, 04F0h
            var crcDataSourceOffset = PatternScanner.FindPattern(srcData, arm9PatchInfo.CRCPatchDataSourcePattern);

            if (crcDataSourceOffset < 0)
            {
                Console.WriteLine("Failed to find CRC data source pattern");
                return false;
            }

            Console.WriteLine($"CRC data source offset 0x{crcDataSourceOffset:X}");

            assembler.MovWord(Arm9Register.R1, srcRom.Arm9EntryAddress + crcDataSourceOffset);

            //size of crc data 0x1D0
            //mov r2, 1d0h
            assembler.Mov(Arm9Register.R2, 0x1D0);

            //memcpy 0205e4b8
            //mov r11, 02000000h
            //add r11, r11, 05e000h
            //add r11, r11, 04b0h
            //add r11, r11, 08h
            var memcpyOffset = PatternScanner.FindPattern(srcData, arm9PatchInfo.MemcpyPattern);

            if (memcpyOffset < 0)
            {
                Console.WriteLine("Failed to find memcpy pattern");
                return false;
            }

            Console.WriteLine($"memcpy offset 0x{memcpyOffset:X}");

            assembler.MovWord(Arm9Register.R11, srcRom.Arm9EntryAddress + memcpyOffset);

            //blx r11
            assembler.Blx(Arm9Register.R11);

            //pop r0-r12, r14
            assembler.Pop([
                Arm9Register.R0,
                Arm9Register.R1,
                Arm9Register.R2,
                Arm9Register.R3,
                Arm9Register.R4,
                Arm9Register.R5,
                Arm9Register.R6,
                Arm9Register.R7,
                Arm9Register.R8,
                Arm9Register.R9,
                Arm9Register.R10,
                Arm9Register.R11,
                Arm9Register.R12,
                Arm9Register.R14
            ]);

            //bx r3
            assembler.Bx(Arm9Register.R3);

            var shellcode = assembler.GetBuffer();

            var crcPatchStoreOffset = PatternScanner.FindPattern(srcData, arm9PatchInfo.CRCPatchStorePattern);

            if (crcPatchStoreOffset < 0)
            {
                Console.WriteLine("Failed to find CRC patch store pattern");

                return false;
            }

            Console.WriteLine($"CRC patch store offset 0x{crcPatchStoreOffset:X}");

            shellcode.CopyTo(patchedData.Slice(crcPatchStoreOffset, shellcode.Length));

            //Calculate crcs
            var crcs = new byte[0x1D0];

            // This is needed to get the correct CRCs, on runtime it's set by the kernel
            patchedData[0x4E140] = 0xED;

            for (var i = 0; i < 0xE8; i++)
            {
                var crc = CalculateCRC(patchedData.Slice(i * 0x800, 0x800));
                crcs[i * 2] = (byte)(crc & 0xFF);
                crcs[i * 2 + 1] = (byte)(crc >> 8);
            }

            patchedData[0x4E140] = 0x00;

            crcs.CopyTo(patchedData.Slice(crcDataSourceOffset, crcs.Length));

            //Patch branch to shellcode
            var crcPatchBranchOffset = PatternScanner.FindPattern(srcData, arm9PatchInfo.CRCPatchBranchPattern);

            if (crcPatchBranchOffset < 0)
            {
                Console.WriteLine("Failed to find CRC patch branch pattern");
                return false;
            }

            var branchAssembler = new Arm9Assembler();
            branchAssembler.B(srcRom.Arm9EntryAddress + crcPatchBranchOffset, srcRom.Arm9EntryAddress + crcPatchStoreOffset);

            var branchPatchBytes = branchAssembler.GetBuffer();
            branchPatchBytes.CopyTo(patchedData.Slice(crcPatchBranchOffset, branchPatchBytes.Length));

            Console.WriteLine("Secondary CRC patched");

            foreach (var extraPatch in extraPatches)
            {
                var patchOffset = PatternScanner.FindPattern(srcData, extraPatch.Pattern);

                if (patchOffset < 0)
                {
                    Console.WriteLine($"Failed to find extra patch pattern for patch '{extraPatch.Name}'");
                    return false;
                }

                var patchByteStr = extraPatch.PatchBytes.Split(' ');
                var patchBytes = new byte[patchByteStr.Length];

                for (var i = 0; i < patchByteStr.Length; i++)
                {
                    patchBytes[i] = Convert.ToByte(patchByteStr[i], 16);
                }

                patchBytes.CopyTo(patchedData.Slice(patchOffset, extraPatch.PatchBytes.Length));

                Console.WriteLine($"Applied extra patch '{extraPatch.Name}' at offset 0x{patchOffset:X}");
            }

            Console.WriteLine("ARM9 patches applied successfully");

            return true;
        }

        private static bool ApplyArm7Patches(DSRom srcRom, DSRom patchedRom, PatchSettings patchSettings)
        {
            Console.WriteLine("Applying ARM7 patches...");

            var arm7PatchInfo = patchSettings.Arm7PatchInfo;
            var srcData = srcRom.GetArm7Data();
            var srcArm9Data = srcRom.GetArm9Data();
            var patchedData = patchedRom.GetArm7Data();

            var crcAreaOffset = PatternScanner.FindPattern(srcArm9Data, arm7PatchInfo.CRCAreaPattern);

            if (crcAreaOffset < 0)
            {
                Console.WriteLine("Failed to find CRC area pattern");
                return false;
            }

            var arm9Crc = DecodeUShort((ushort)(srcArm9Data[crcAreaOffset + 4] | (srcArm9Data[crcAreaOffset + 5] << 8)));
            var arm7Crc = DecodeUShort((ushort)(srcArm9Data[crcAreaOffset + 6] | (srcArm9Data[crcAreaOffset + 7] << 8)));

            Console.WriteLine($"CRCS: ARM9: 0x{arm9Crc:X} ARM7: 0x{arm7Crc:X}");

            var arm9CrcEor1Offset = PatternScanner.FindPattern(srcData, arm7PatchInfo.Arm9CRCEor1Pattern);

            if (arm9CrcEor1Offset < 0)
            {
                Console.WriteLine("Failed to find ARM9 CRC EOR1 pattern");
                return false;
            }

            //nop
            patchedData[arm9CrcEor1Offset] = 0xC0;
            patchedData[arm9CrcEor1Offset + 1] = 0x46;

            var arm9CrcEor2Offset = PatternScanner.FindPattern(srcData, arm7PatchInfo.Arm9CRCEor2Pattern);

            if (arm9CrcEor2Offset < 0)
            {
                Console.WriteLine("Failed to find ARM9 CRC EOR2 pattern");
                return false;
            }

            //nop
            patchedData[arm9CrcEor2Offset] = 0xC0;
            patchedData[arm9CrcEor2Offset + 1] = 0x46;

            var arm9CrcLsrOffset = PatternScanner.FindPattern(srcData, arm7PatchInfo.Arm9CRCLsrPattern);

            if (arm9CrcLsrOffset < 0)
            {
                Console.WriteLine("Failed to find ARM9 CRC LSR pattern");
                return false;
            }

            //nop
            patchedData[arm9CrcLsrOffset] = 0xC0;
            patchedData[arm9CrcLsrOffset + 1] = 0x46;

            var arm9CrcAddOffset = PatternScanner.FindPattern(srcData, arm7PatchInfo.Arm9CRCAddPattern);

            if (arm9CrcAddOffset < 0)
            {
                Console.WriteLine("Failed to find ARM9 CRC ADD pattern");
                return false;
            }

            //nop
            patchedData[arm9CrcAddOffset] = 0xC0;
            patchedData[arm9CrcAddOffset + 1] = 0x46;

            var arm9CrcValueOffset = PatternScanner.FindPattern(srcData, arm7PatchInfo.Arm9CRCValuePattern);

            patchedData[arm9CrcValueOffset] = (byte)(arm9Crc & 0xFF);
            patchedData[arm9CrcValueOffset + 1] = (byte)(arm9Crc >> 8);

            Console.WriteLine("Patched ARM9 CRC");

            var arm7CrcEor1Offset = PatternScanner.FindPattern(srcData, arm7PatchInfo.Arm7CRCEor1Pattern);

            if (arm7CrcEor1Offset < 0)
            {
                Console.WriteLine("Failed to find ARM7 CRC EOR1 pattern");
                return false;
            }

            //nop
            patchedData[arm7CrcEor1Offset] = 0xC0;
            patchedData[arm7CrcEor1Offset + 1] = 0x46;

            var arm7CrcEor2Offset = PatternScanner.FindPattern(srcData, arm7PatchInfo.Arm7CRCEor2Pattern);

            if (arm7CrcEor2Offset < 0)
            {
                Console.WriteLine("Failed to find ARM7 CRC EOR2 pattern");
                return false;
            }

            //nop
            patchedData[arm7CrcEor2Offset] = 0xC0;
            patchedData[arm7CrcEor2Offset + 1] = 0x46;

            var arm7CrcAddOffset = PatternScanner.FindPattern(srcData, arm7PatchInfo.Arm7CRCAddPattern);

            if (arm7CrcAddOffset < 0)
            {
                Console.WriteLine("Failed to find ARM7 CRC ADD pattern");
                return false;
            }

            //nop
            patchedData[arm7CrcAddOffset] = 0xC0;
            patchedData[arm7CrcAddOffset + 1] = 0x46;

            var arm7CrcValueOffset = PatternScanner.FindPattern(srcData, arm7PatchInfo.Arm7CRCValuePattern);

            if (arm7CrcValueOffset < 0)
            {
                Console.WriteLine("Failed to find ARM7 CRC VALUE pattern");
                return false;
            }

            patchedData[arm7CrcValueOffset] = (byte)(arm7Crc & 0xFF);
            patchedData[arm7CrcValueOffset + 1] = (byte)(arm7Crc >> 8);

            Console.WriteLine("Patched ARM7 CRC");

            Console.WriteLine("ARM7 patches applied successfully");

            return true;
        }

        //0x02014588
        private static ushort DecodeUShort(ushort value)
        {
            var r0 = (uint)value;
            var r5 = 0u;
            var r12 = 0u;
            var r3 = r0 & 0xFFu;
            var r2 = ~0xFFu;
            var r4 = r3 | r2;
            var r1 = ~0x4u;
            r3 = r4 & 0x1u;
            var lr = r1 | (r3 << 2);
            r2 = r4 << 4;
            r3 = r4 & 0x2u;
            r12 = (r12 & ~0x2u) | r3;
            r2 &= 0x80u;
            r3 = r4 << 5;
            lr = (lr & ~0x80u) | r2;
            r1 = r12 & ~0x80u;
            r3 &= 0x80u;
            r12 = r1 | r3;
            r2 = lr & ~0x1u;
            r3 = r4 << 27;
            lr = r2 | (r3 >> 31);
            r1 = r5 & ~0xFFu;
            r2 = r4 << 25;
            r3 = r4 >> 4;
            r12 &= ~0x1u;
            r5 = r1 | (r0 >> 8);
            r12 |= (r2 >> 31);
            r1 = lr & ~0x2u;
            r3 &= 0x2u;
            lr = r3 | r1;
            r2 = r4 >> 3;
            r3 = r5 & 0x1u;
            r1 = r12 & ~0x40u;
            r12 = r1 | (r3 << 6);
            r0 = lr & ~0x10u;
            r2 &= 0x10u;
            r3 = r5 << 2;
            lr = r2 | r0;
            r1 = r12 & ~0x20u;
            r3 &= 0x20u;
            r2 = r5 << 2;
            r12 = r3 | r1;
            r0 = lr & ~0x8u;
            r2 &= 0x8u;
            r3 = r5 >> 2;
            lr = r2 | r0;
            r1 = r12 & ~0x4u;
            r3 &= 0x4u;
            r2 = r5 << 3;
            r12 = r3 | r1;
            r0 = lr & ~0x20u;
            r2 &= 0x20u;
            r3 = r5 >> 1;
            lr = r2 | r0;
            r3 &= 0x10u;
            r1 = r5 >> 1;
            r12 &= ~0x10u;
            r12 = r3 | r12;
            r1 &= 0x40u;
            r2 = r5 >> 3;
            lr &= ~0x40u;
            lr |= r1;
            r0 = r12 & ~0x8u;
            r2 &= 0x8u;
            r12 = r2 | r0;

            return (ushort)(((lr & 0xFFu) << 8) | (r12 & 0xFFu));
        }

        private static ushort CalculateCRC(ReadOnlySpan<byte> data)
        {
            var table = MemoryMarshal.Cast<byte, ushort>(CRC_TABLE);

            var crc = (ushort)0u;

            foreach (var b in data)
            {
                var index = (byte)(b ^ crc);
                crc = (ushort)(table[index] ^ (crc >> 8));
            }

            return crc;
        }

        private static readonly byte[] CRC_TABLE = [
            0x00, 0x00, 0xC1, 0xC0, 0x81, 0xC1, 0x40, 0x01, 0x01, 0xC3, 0xC0, 0x03,
            0x80, 0x02, 0x41, 0xC2, 0x01, 0xC6, 0xC0, 0x06, 0x80, 0x07, 0x41, 0xC7,
            0x00, 0x05, 0xC1, 0xC5, 0x81, 0xC4, 0x40, 0x04, 0x01, 0xCC, 0xC0, 0x0C,
            0x80, 0x0D, 0x41, 0xCD, 0x00, 0x0F, 0xC1, 0xCF, 0x81, 0xCE, 0x40, 0x0E,
            0x00, 0x0A, 0xC1, 0xCA, 0x81, 0xCB, 0x40, 0x0B, 0x01, 0xC9, 0xC0, 0x09,
            0x80, 0x08, 0x41, 0xC8, 0x01, 0xD8, 0xC0, 0x18, 0x80, 0x19, 0x41, 0xD9,
            0x00, 0x1B, 0xC1, 0xDB, 0x81, 0xDA, 0x40, 0x1A, 0x00, 0x1E, 0xC1, 0xDE,
            0x81, 0xDF, 0x40, 0x1F, 0x01, 0xDD, 0xC0, 0x1D, 0x80, 0x1C, 0x41, 0xDC,
            0x00, 0x14, 0xC1, 0xD4, 0x81, 0xD5, 0x40, 0x15, 0x01, 0xD7, 0xC0, 0x17,
            0x80, 0x16, 0x41, 0xD6, 0x01, 0xD2, 0xC0, 0x12, 0x80, 0x13, 0x41, 0xD3,
            0x00, 0x11, 0xC1, 0xD1, 0x81, 0xD0, 0x40, 0x10, 0x01, 0xF0, 0xC0, 0x30,
            0x80, 0x31, 0x41, 0xF1, 0x00, 0x33, 0xC1, 0xF3, 0x81, 0xF2, 0x40, 0x32,
            0x00, 0x36, 0xC1, 0xF6, 0x81, 0xF7, 0x40, 0x37, 0x01, 0xF5, 0xC0, 0x35,
            0x80, 0x34, 0x41, 0xF4, 0x00, 0x3C, 0xC1, 0xFC, 0x81, 0xFD, 0x40, 0x3D,
            0x01, 0xFF, 0xC0, 0x3F, 0x80, 0x3E, 0x41, 0xFE, 0x01, 0xFA, 0xC0, 0x3A,
            0x80, 0x3B, 0x41, 0xFB, 0x00, 0x39, 0xC1, 0xF9, 0x81, 0xF8, 0x40, 0x38,
            0x00, 0x28, 0xC1, 0xE8, 0x81, 0xE9, 0x40, 0x29, 0x01, 0xEB, 0xC0, 0x2B,
            0x80, 0x2A, 0x41, 0xEA, 0x01, 0xEE, 0xC0, 0x2E, 0x80, 0x2F, 0x41, 0xEF,
            0x00, 0x2D, 0xC1, 0xED, 0x81, 0xEC, 0x40, 0x2C, 0x01, 0xE4, 0xC0, 0x24,
            0x80, 0x25, 0x41, 0xE5, 0x00, 0x27, 0xC1, 0xE7, 0x81, 0xE6, 0x40, 0x26,
            0x00, 0x22, 0xC1, 0xE2, 0x81, 0xE3, 0x40, 0x23, 0x01, 0xE1, 0xC0, 0x21,
            0x80, 0x20, 0x41, 0xE0, 0x01, 0xA0, 0xC0, 0x60, 0x80, 0x61, 0x41, 0xA1,
            0x00, 0x63, 0xC1, 0xA3, 0x81, 0xA2, 0x40, 0x62, 0x00, 0x66, 0xC1, 0xA6,
            0x81, 0xA7, 0x40, 0x67, 0x01, 0xA5, 0xC0, 0x65, 0x80, 0x64, 0x41, 0xA4,
            0x00, 0x6C, 0xC1, 0xAC, 0x81, 0xAD, 0x40, 0x6D, 0x01, 0xAF, 0xC0, 0x6F,
            0x80, 0x6E, 0x41, 0xAE, 0x01, 0xAA, 0xC0, 0x6A, 0x80, 0x6B, 0x41, 0xAB,
            0x00, 0x69, 0xC1, 0xA9, 0x81, 0xA8, 0x40, 0x68, 0x00, 0x78, 0xC1, 0xB8,
            0x81, 0xB9, 0x40, 0x79, 0x01, 0xBB, 0xC0, 0x7B, 0x80, 0x7A, 0x41, 0xBA,
            0x01, 0xBE, 0xC0, 0x7E, 0x80, 0x7F, 0x41, 0xBF, 0x00, 0x7D, 0xC1, 0xBD,
            0x81, 0xBC, 0x40, 0x7C, 0x01, 0xB4, 0xC0, 0x74, 0x80, 0x75, 0x41, 0xB5,
            0x00, 0x77, 0xC1, 0xB7, 0x81, 0xB6, 0x40, 0x76, 0x00, 0x72, 0xC1, 0xB2,
            0x81, 0xB3, 0x40, 0x73, 0x01, 0xB1, 0xC0, 0x71, 0x80, 0x70, 0x41, 0xB0,
            0x00, 0x50, 0xC1, 0x90, 0x81, 0x91, 0x40, 0x51, 0x01, 0x93, 0xC0, 0x53,
            0x80, 0x52, 0x41, 0x92, 0x01, 0x96, 0xC0, 0x56, 0x80, 0x57, 0x41, 0x97,
            0x00, 0x55, 0xC1, 0x95, 0x81, 0x94, 0x40, 0x54, 0x01, 0x9C, 0xC0, 0x5C,
            0x80, 0x5D, 0x41, 0x9D, 0x00, 0x5F, 0xC1, 0x9F, 0x81, 0x9E, 0x40, 0x5E,
            0x00, 0x5A, 0xC1, 0x9A, 0x81, 0x9B, 0x40, 0x5B, 0x01, 0x99, 0xC0, 0x59,
            0x80, 0x58, 0x41, 0x98, 0x01, 0x88, 0xC0, 0x48, 0x80, 0x49, 0x41, 0x89,
            0x00, 0x4B, 0xC1, 0x8B, 0x81, 0x8A, 0x40, 0x4A, 0x00, 0x4E, 0xC1, 0x8E,
            0x81, 0x8F, 0x40, 0x4F, 0x01, 0x8D, 0xC0, 0x4D, 0x80, 0x4C, 0x41, 0x8C,
            0x00, 0x44, 0xC1, 0x84, 0x81, 0x85, 0x40, 0x45, 0x01, 0x87, 0xC0, 0x47,
            0x80, 0x46, 0x41, 0x86, 0x01, 0x82, 0xC0, 0x42, 0x80, 0x43, 0x41, 0x83,
            0x00, 0x41, 0xC1, 0x81, 0x81, 0x80, 0x40, 0x40
        ];
    }
}
