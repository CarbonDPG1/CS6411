using System;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Diagnostics;

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
             * Eg: PHP (Server side execution), ASP, ASPX, CGI. "https://devops/maliciousScript.aspx"
             * Other misc scripts (Powershell, Ruby, Python, etc)
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
                //watcher.Changed += OnChanged;
                watcher.Created += OnChanged;
                watcher.EnableRaisingEvents = true;

                while (Console.Read() != 'q') ;

            }


        }
        private static void OnChanged(object source, FileSystemEventArgs e)
        {
            String cmd = "curl --request POST --URL \"https://www.virustotal.com/vtapi/v2/file/scan\" --form \"apikey=fdf825c37d11a14426bf70d9eb0c20400fcf76dc03c4fe827e2234cb8f38bfc4\" --form \"file=@" + e.FullPath + "\"";
            Console.WriteLine(cmd);
            Console.WriteLine("File changed");
            // Specify what is done when a file is changed, created
            var fileName = e.Name;
            Console.WriteLine(fileName);
            int extIndex = fileName.LastIndexOf('.');
            //Console.WriteLine(extIndex);
            String extension = null;
            //Console.WriteLine(fileName.Length);

            //An index of -1 indicates the character wasn't found...
            if (extIndex > 0)
            {
                for (int i = extIndex; i < fileName.Length; i++)
                {
                    //Console.WriteLine("Index: " + i);
                    //Console.WriteLine("Current Letter: " + fileName[i]);
                    Console.Out.Flush();
                    extension += String.Concat(fileName[i]);
                }
            }
            bool valid = extension.Contains("pl") || extension.Contains("jpg") || extension.Contains("ps1") || extension.Contains("php") || extension.Contains("py");

            if (valid)
            {
                // Get file hash
                /*
                PowerShell shell = PowerShell.Create();
                shell.AddCommand("get-filehash");
                shell.AddParameter("Path", e.FullPath);
                shell.AddParameter("Algorithm", "SHA1");
                var results = shell.Invoke();
                */

                Process powershell = new Process();
                powershell.StartInfo.FileName = "powershell.exe";
                powershell.StartInfo.Arguments = "Get-FileHash -Algorithm SHA1 -Path " + "\'" + e.FullPath + "\'";
                powershell.Start();
                
                Process VTScan = new Process();
                VTScan.StartInfo.UseShellExecute = false;
                VTScan.StartInfo.RedirectStandardOutput = true;
                Console.WriteLine("Stopped here?");
                Console.Out.Flush();
                VTScan.StartInfo.FileName = "powershell.exe";
                Console.WriteLine("CMD Started");
                Console.Out.Flush();
                VTScan.StartInfo.Arguments = "cmd /c curl --URL \"https://www.virustotal.com/vtapi/v2/file/scan\" --form \"apikey=fdf825c37d11a14426bf70d9eb0c20400fcf76dc03c4fe827e2234cb8f38bfc4\" --form \"file=@" + e.FullPath + "\"";
                Console.WriteLine("Args loaded");
                Console.Out.Flush();
                VTScan.Start();
                Console.WriteLine("POST Request sent");
                Console.Out.Flush();
                

            }
            Console.Out.Flush();
            //Console.WriteLine($"File: {e.FullPath} {e.ChangeType}");
        }
    }
}
