namespace R4i_Kernel_Patcher.Patches
{
    internal class Arm7PatchInfo
    {
        public string CRCAreaPattern { get; set; } = string.Empty;

        //Arm9 crc
        public string Arm9CRCEor1Pattern { get; set; } = string.Empty;
        public string Arm9CRCEor2Pattern { get; set; } = string.Empty;
        public string Arm9CRCLsrPattern { get; set; } = string.Empty;
        public string Arm9CRCAddPattern { get; set; } = string.Empty;
        public string Arm9CRCValuePattern { get; set; } = string.Empty;

        //Arm7 crc
        public string Arm7CRCEor1Pattern { get; set; } = string.Empty;
        public string Arm7CRCEor2Pattern { get; set; } = string.Empty;
        public string Arm7CRCAddPattern { get; set; } = string.Empty;
        public string Arm7CRCValuePattern { get; set; } = string.Empty;
    }
}
