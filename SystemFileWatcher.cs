using System;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Net.Http.Headers;


namespace Program
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
            Console.WriteLine("Application Started - Monitoring FileSystem");
            using (FileSystemWatcher watcher = new FileSystemWatcher())
            {

                string gitRepo = @"C:\Users\michael.redbourne\DirWatch";
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

                StringBuilder format;
                using (FileStream fs = new FileStream(e.FullPath, FileMode.Open))
                using (BufferedStream bs = new BufferedStream(fs)) {
                    using (SHA1Managed sha1 = new SHA1Managed()) {
                        byte[] hash = sha1.ComputeHash(bs);
                        format = new StringBuilder(2 * hash.Length);
                        foreach (byte b in hash) {
                            format.AppendFormat("{0:X2}", b);
                        }
                    }
                }
                Console.WriteLine(format);

                Process VTScan = new Process();
                VTScan.StartInfo.UseShellExecute = false;
                VTScan.StartInfo.RedirectStandardOutput = true;
                VTScan.StartInfo.CreateNoWindow = true;
                VTScan.StartInfo.FileName = "powershell.exe";
                VTScan.StartInfo.Arguments = "cmd /c curl --URL \"https://www.virustotal.com/vtapi/v2/file/scan\" --form \"apikey=fdf825c37d11a14426bf70d9eb0c20400fcf76dc03c4fe827e2234cb8f38bfc4\" --form \"file=@" + e.FullPath + "\"";
                Console.WriteLine("VT Executed!");

                Process EventCreate = new Process();
                EventCreate.StartInfo.UseShellExecute = false;
                EventCreate.StartInfo.FileName = "powershell.exe";
                //EventCreate.StartInfo.Arguments = "cmd /c \"EventCreate /T Information /ID 99 /L Application /SO CloudScanner /D \"File created in directory: \"" + e.FullPath + "\". VT Link: virustotal.com/gui/file/\"";
                EventCreate.StartInfo.Arguments = "cmd /c \"EventCreate /T Information /ID 99 /L Application /SO CloudScanner /D \'virustotal.com/gui/file/" + format + "\'\"";
                Console.WriteLine("cmd /c \"EventCreate /T Information /ID 99 /L Application /SO CloudScanner /D \'virustotal.com/gui/file/" + format + "\'\"");
                EventCreate.Start();
                Console.WriteLine("Event Created!");
                
                /* Handling VT Scan Output - Maybe required (probably not?) */
                int lineCount = 0;
                StringBuilder output = new StringBuilder();
                VTScan.OutputDataReceived += new DataReceivedEventHandler((sender, e) =>
                {
                    // Prepend line numbers to each line of the output.
                    if (!String.IsNullOrEmpty(e.Data))
                    {
                        lineCount++;
                        output.Append("\n[" + lineCount + "]: " + e.Data);
                    }
                });
                VTScan.Start();
                VTScan.BeginOutputReadLine();
                Console.WriteLine("Command Executed");

                try
                {
                    FileStream fs = File.Open("C:\\Users\\michael.redbourne\\temp.txt", FileMode.OpenOrCreate, FileAccess.Write);
                    StreamWriter sw = new StreamWriter(fs);
                    sw.WriteLine(output);
                    sw.Flush();
                    sw.Close();
                }
                catch (IOException ioe) {
                    Console.WriteLine(ioe);
                }

                VTScan.WaitForExit();
                VTScan.Close();
                
                
                Console.Out.Flush();


            }
            Console.Out.Flush();
            //Console.WriteLine($"File: {e.FullPath} {e.ChangeType}");
        }
    }
}
