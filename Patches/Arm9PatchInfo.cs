namespace R4i_Kernel_Patcher.Patches
{
    public class Arm9PatchInfo
    {
        public string MemcpyPattern { get; set; } = string.Empty;

        //Secondary arm9 crc stuff
        public int CRCStrhAddr { get; set; } = 0x100525c;
        public int CRCBltAddr { get; set; } = 0x100526c;
        public int CRCDataAddr { get; set; } = 0x02350000;
        public string CRCPatchStorePattern { get; set; } = string.Empty;
        public string CRCPatchDataSourcePattern { get; set; } = string.Empty;
        public string CRCPatchBranchPattern { get; set; } = string.Empty;
    }
}
