using System;
using System.Collections.ObjectModel;
using System.Text;

namespace SHA256_libraries
{
    public static class Util
    {

        public static string ArrayToString(ReadOnlyCollection<byte> arrBytes)
        {
            StringBuilder stringBuilder = new StringBuilder(arrBytes.Count*2);
            for (int i = 0; i < arrBytes.Count; ++i)
            {
                stringBuilder.AppendFormat("{0:x2}", arrBytes[i]);
            }

            return stringBuilder.ToString();
        }
    }
}
