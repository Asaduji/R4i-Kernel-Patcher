namespace R4i_Kernel_Patcher.Patches
{
    internal class PatchSettings
    {
        public Arm9PatchInfo Arm9PatchInfo { get; set; } = new();
        public Arm7PatchInfo Arm7PatchInfo { get; set; } = new();
        public ExtraPatchInfo[] ExtraPatches { get; set; } = [];
    }
}
