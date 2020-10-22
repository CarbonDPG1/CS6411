/*
* Authors: Michael Redbourne, Tristan Carrier
* Course: CS 6411
* University: University of New Brunswick
* Purpose: Monitor File System for changes to Azure DevOps Repo.
*   Execute PoSh to gather hash information and upload to Threat Intelligence platforms for information
*   If no information found, upload file for review.
*   Fire custom Windows Event (CMD) if malicious results are returned. Otherwise, fire different custom event.
*   XPath Query using IBM's WinCollect Agent for import to QRadar CE. 
*   Custom Rule Engine (CRE) to detect when a malicious event is fired.
*/

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
                string gitRepo = @"<path here>";
                watcher.Path = gitRepo;
                watcher.NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName;
                watcher.Filter = "*.*"; // Highly inefficient...

                watcher.Changed += OnChanged;
                watcher.Created += OnChanged;                
                
            }


        }
        private static void OnChanged(object source, FileSystemEventArgs e)
        {
            // Specify what is done when a file is changed, created
            string fileName = e.Name;
            string fullPath = e.FullPath;
            int extIndex = fileName.LastIndexOf('.');
            string extension = null;

            //An index of -1 indicates the character wasn't found...
            if (extIndex > 0) {
                for (int i = extIndex; extIndex <= fileName.Length; i++) {
                    extension = String.Concat(fileName[i]);

                }
            }
            bool valid = extension.Contains("aspx") || extension.Contains("asp") || extension.Contains("ps1") || extension.Contains("php") || extension.Contains("py");

            if () {
                // Get file hash
                PowerShell ps = PowerShell.Create();
                ps.AddCommand("Get-FileHash");
                ps.AddParameter(fullPath);
                ps.Invoke();

                // Upload to VirusTotal (or other platform)


            }
            Console.WriteLine($"File: {e.FullPath} {e.ChangeType}");
        }
    }
}
