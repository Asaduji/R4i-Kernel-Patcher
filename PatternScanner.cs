namespace R4i_Kernel_Patcher
{
    internal static class PatternScanner
    {
        public static int FindPattern(ReadOnlySpan<byte> data, string pattern)
        {
            var patternValues = pattern.Split(' ');
            var patternBytes = new byte?[patternValues.Length];

            if (patternBytes.Length < 1)
            {
                return -1;
            }

            for (var i = 0; i < patternValues.Length; i++)
            {
                if (patternValues[i] == "??")
                {
                    patternBytes[i] = null;

                    continue;
                }

                patternBytes[i] = Convert.ToByte(patternValues[i], 16);
            }

            for (var i = 0; i <= data.Length - patternBytes.Length; i++)
            {
                var found = true;
                for (var j = 0; j < patternBytes.Length; j++)
                {
                    if (patternBytes[j].HasValue && data[i + j] != patternBytes[j]!.Value)
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    return i;
                }
            }
            return -1;
        }
    }
}
