using CommandLine;
using CredentialManagement;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace wsl_kinit
{
    /// <summary>
    /// Run a kinit using a secret from WSL. Secret (password) is looked up from the generic
    /// credentials on the machine.
    /// </summary>
    class Program
    {
        class Options
        {
            [Value(0, HelpText = "Credential we should kinit agains", Required =true)]
            public string credential { get; set; }

            [Option('l', Default = false, HelpText = "List the credentials after acquiring them")]
            public bool ListCredentials { get; set; }
        }

        static void Main(string[] args)
        {
            // Parse the options
            var r = Parser.Default.ParseArguments<Options>(args)
                .WithParsed(o => DefineKinit(o.credential, o.ListCredentials));
        }

        /// <summary>
        /// Does the work of actually doing the kinit
        /// </summary>
        /// <param name="credential"></param>
        private static void DefineKinit(string credential, bool doList)
        {
            // First job - fetch the credentials from the cache.
            var info = SplitCredential(credential);
            var sclist = new CredentialSet(info[1]);
            var passwordInfo = sclist.Load().Where(c => c.Username == info[0]).FirstOrDefault();
            if (passwordInfo == null)
            {
                throw new ArgumentException(string.Format("Please create a generic windows credential with '{0}' as the target address, '{1}' as the username, and the password for krb5 authentication.", info[1], info[0]));
            }

            // Now, write the temp file that contains everything we have to execute.
            // Use funny construct here ot make sure the file is deleted when we are done, no matter what.
            var tmp = new FileInfo(Path.GetTempFileName());
            try
            {
                // Create the file.
                using (var writer = tmp.CreateText())
                {
                    writer.NewLine = "\n";
                    writer.WriteLine($"kinit -f {credential} << MYEOF");
                    writer.WriteLine($"{passwordInfo.Password}");
                    writer.WriteLine("MYEOF");
                    if (doList)
                    {
                        writer.WriteLine("klist");
                    }
                }

                // Execute the command
                RunBashFile(tmp.FullName);
            }
            finally
            {
                // Make sure to remove the file so a password isn't left hanging around.
                tmp.Refresh();
                if (tmp.Exists)
                {
                    tmp.Delete();
                }
            }            
        }

        /// <summary>
        /// Runs a bash command.
        /// </summary>
        /// <param name="fullName"></param>
        private static void RunBashFile(string fullName)
        {
            var p = new Process();

            var tmp_win_path = Path.GetTempFileName();
            p.StartInfo.FileName = FindBash();
            p.StartInfo.Arguments =  ConvertPathToWSL(fullName) + " &> " + ConvertPathToWSL(tmp_win_path);

            p.StartInfo.WorkingDirectory = ConvertPathToWSL(Directory.GetCurrentDirectory());
            p.StartInfo.LoadUserProfile = true;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.UseShellExecute = true;
            p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;

            p.Start();
            p.WaitForExit();

            var ret = p.ExitCode;
            var sr = new StreamReader(tmp_win_path);

            while (!sr.EndOfStream)
                Console.WriteLine(sr.ReadLine());

            sr.Close();
            File.Delete(tmp_win_path);

            Environment.Exit(ret);
        }

        static string FindBash()
        {
            var path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(@"%windir%\SysWow64\bash.exe"));
            if (File.Exists(path))
                return path;

            path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(@"%windir%\sysnative\bash.exe"));
            if (File.Exists(path))
                return path;

            path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(@"%windir%\System32\bash.exe"));
            if (File.Exists(path))
                return path;

            throw new Exception("Could not find a path to Bash!");
        }

        static string ConvertPathToWSL(string p)
        {
            p = Environment.ExpandEnvironmentVariables(p);
            return "/mnt/" + p[0].ToString().ToLower() + "/" + p.Substring(3).Replace('\\', '/');
        }

        /// <summary>
        /// Split the credential by the @
        /// </summary>
        /// <param name="credential"></param>
        /// <returns></returns>
        private static string[] SplitCredential(string credential)
        {
            var s = credential.Trim().Split('@');
            if (s.Length != 2)
            {
                throw new ArgumentException($"The credential ({credential}) must be in the format username@KRBDOMAIN.");
            }
            return s;
        }
    }
}
