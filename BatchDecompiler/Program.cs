using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Threading;

namespace BatchDecompiler
{
    class Program
    {
        static void Main(string[] args)
        {
            var idaPath = @"d:\IDA75";
            var symchk = @"c:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe";
            var drivers = Directory.EnumerateFiles(@"d:\drivers", "*.sys").ToList();
            var sympath = @"srv*c:\symbols*https://msdl.microsoft.com/download/symbols";
            int progress = 0;
            //for(var index = 0; index < drivers.Count; index++ )
            Parallel.ForEach(drivers, new ParallelOptions
            {
                MaxDegreeOfParallelism = 12,
            },
            (driver, state, index) =>
            {
                //var driver = drivers[index];
                Interlocked.Increment(ref progress);
                var peFile = new PeNet.PeFile(driver);
                string ida, cmdLine, symLine = $"\"{driver}\" /s {sympath}";
                Console.WriteLine($"[{progress}/{drivers.Count}] symshk " + symLine);
                Process.Start(new ProcessStartInfo
                {
                    FileName = symchk,
                    Arguments = symLine,
                    UseShellExecute = false,
                }).WaitForExit();
                // https://www.hexacorn.com/blog/2019/07/04/batch-decompilation-with-ida-hex-rays-decompiler/
                if (peFile.Is64Bit)
                {
                    ida = Path.Combine(idaPath, "idat64.exe");
                    cmdLine = $"-A -Ohexx64:-new:\"{Path.GetFileNameWithoutExtension(driver)}\".c:ALL \"{driver}\"";
                }
                else
                {
                    ida = Path.Combine(idaPath, "idat.exe");
                    cmdLine = $"-A -Ohexrays:-new:\"{Path.GetFileNameWithoutExtension(driver)}\".c:ALL \"{driver}\"";
                }
                Console.WriteLine($"[{progress}/{drivers.Count}] {ida} {cmdLine}");
                Process.Start(new ProcessStartInfo
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    Arguments = cmdLine,
                    FileName = ida
                }).WaitForExit();
            }
            );
        }
    }
}
