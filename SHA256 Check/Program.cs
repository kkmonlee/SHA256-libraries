using System.Collections.ObjectModel;
using System.IO;
using SHA256_libraries;


namespace SHA256_Check
{
    class Program
    {
        static void Main(string[] args)
        {
            ReadOnlyCollection<byte> hashBytes = Sha256.HashFile(File.OpenRead(@"foo.bin"));

            System.Console.Out.WriteLine("{0}", Util.ArrayToString(hashBytes));
        }
    }
}
