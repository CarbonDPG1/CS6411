using System;
using System.IO;
using System.Management.Automation;

namespace DirWatcher
{
    class Program
    {
        static void Main(string[] args)
        {
            /*
             * This is an extremely inefficient way of monitoring a directory for changes. There was a proposed API change made to Microsoft under Issue #25967 on Github.
             * Found here: https://github.com/dotnet/runtime/issues/25967
             * Notably, we only need to monitor files capable of being executed by direct access to a webpage. 
             * Eg: PHP (Server side execution), ASP, ASPX, CGI, PY and RB.
             * Other file types that execute clientside (JS for example) can be ignored.
             * However, while the API is marked as "Approved", attempts at utilizing the new API have failed. 
             * Microsoft's current API Documentation can be found here: https://docs.microsoft.com/en-us/dotnet/api/system.io.filesystemwatcher.filter?view=netcore-3.1
            */
            using (FileSystemWatcher watcher = new FileSystemWatcher())
            {
                string gitRepo = @"C:\Users\Michael\Desktop\DirWatch";
                watcher.Path = gitRepo;
                watcher.NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName;
                watcher.Filter = "*.*"; // Highly inefficient...
                watcher.Changed += OnChanged;
                watcher.Created += OnChanged;
                watcher.EnableRaisingEvents = true;

                while (Console.Read() != 'q') ;
               
            }


        }
        private static void OnChanged(object source, FileSystemEventArgs e)
        {
            Console.WriteLine("File changed");
            // Specify what is done when a file is changed, created
            var fileName = e.Name;
            Console.WriteLine(fileName);
            int extIndex = fileName.LastIndexOf('.');
            Console.WriteLine(extIndex);
            String extension = null;
            Console.WriteLine(fileName.Length);

            //An index of -1 indicates the character wasn't found...
            if (extIndex > 0) {
                for (int i = extIndex; i < fileName.Length; i++) {
                    //Console.WriteLine("Index: " + i);
                    //Console.WriteLine("Current Letter: " + fileName[i]);
                    Console.Out.Flush();
                    extension += String.Concat(fileName[i]);
                }
            }
            bool valid = extension.Contains("txt") || extension.Contains("asp") || extension.Contains("ps1") || extension.Contains("php") || extension.Contains("py");

            if (valid) {
                // Get file hash
                PowerShell ps = PowerShell.Create();
                ps.AddCommand("Get-FileHash");
                ps.AddCommand("Path").AddParameter(e.FullPath);
                ps.AddCommand("Algorithm").AddParameter("SHA1");
                var results = ps.Invoke();

                Console.WriteLine(results);
                Console.Out.Flush();

                // Upload to VirusTotal (or other platform)

            }
            Console.WriteLine($"File: {e.FullPath} {e.ChangeType}");
        }
    }
}
