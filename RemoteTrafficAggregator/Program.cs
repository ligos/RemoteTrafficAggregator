// Nfdump and Syslog aggregator / normalisor
// Copyright (c) Murray Grant 2016

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net;
using System.Threading;

using ICSharpCode.SharpZipLib;
using ICSharpCode.SharpZipLib.BZip2;
using NetTools;
using System.Threading.Tasks;

namespace RemoteTrafficAggregator
{
    class Program
    {
        public static AppConfig Config;

        public const double OneMegabyte = 1024.0 * 1024.0;

        public static async Task<int> Main(string[] args)
        {
            if (args.Length <= 0)
            {
                Console.WriteLine("Usage: RemoteTrafficeAggregator <outputFolder> <inputFolders>");
                return 2;
            }

            Console.WriteLine("Starting RemoteTrafficeAggregator at " + DateTimeOffset.Now);

            // Load config object.
            var jsonConfig = await File.ReadAllTextAsync("appsettings.json");
            Config = Newtonsoft.Json.JsonConvert.DeserializeObject<AppConfig>(jsonConfig);

            // First argument is output folder.
            var outDir = new DirectoryInfo(args[0]);
            if (!outDir.Exists) throw new Exception("Unable to find output directory: " + args[0]);
            Console.WriteLine("Output directory: " + outDir.FullName);

            // All subsequent arguments are input folders. Types are determined by file name.
            var inputDirs = args.Skip(1).Select(x => new DirectoryInfo(x)).ToList();
            foreach (var inDir in inputDirs)
            {
                if (!inDir.Exists) throw new Exception("Unable to find input directory: " + inDir.FullName);
                Console.WriteLine("Input directory: " + inDir.FullName);
            }

            // Get list of files from syslog and nfdump and index by day.
            var syslogFiles = inputDirs
                    .SelectMany(d => Directory.EnumerateFiles(d.FullName, "*.log.bz2"))
                    .Where(x => x.Contains("syslog", StringComparison.OrdinalIgnoreCase))
                    .Select(x => new { file = x, date = DateTime.ParseExact(Path.GetFileName(x).Substring(0, 10), "yyyy-MM-dd", System.Globalization.CultureInfo.CurrentCulture) } )
                    .ToLookup(x => x.date);
            Console.WriteLine("Found {0:N0} syslog input file(s) across {1:N0} day(s).", syslogFiles.Sum(x => x.Count()), syslogFiles.Count);
            var nfdumpFiles = inputDirs
                    .SelectMany(d => Directory.EnumerateFiles(d.FullName, "*.log.bz2"))
                    .Where(x => x.Contains("nfcapd", StringComparison.OrdinalIgnoreCase))
                    .Select(x => new { file = x, date = DateTime.ParseExact(Path.GetFileName(x).Substring(7, 8), "yyyyMMdd", System.Globalization.CultureInfo.CurrentCulture) })
                    .ToLookup(x => x.date);
            Console.WriteLine("Found {0:N0} nfcapd input file(s) across {1:N0} day(s).", nfdumpFiles.Sum(x => x.Count()), nfdumpFiles.Count);

            // Find days we need to process for.
            // Not today, as this will run in the early hours, and there won't be any data yet.
            var dates = nfdumpFiles.Concat(syslogFiles).Select(x => x.Key).Where(x => x < DateTime.Today).ToHashSet();
            if (!dates.Any())
            {
                Console.WriteLine("No dates found to parse files: exiting.");
                return 3;
            }
            Console.WriteLine("Using {0:N0} day(s) as keys, from {1:yyyy-MM-dd} to {2:yyyy-MM-dd}", dates.Count, dates.Min(), dates.Max());

            // Create a list of all files for each day.
            var toProcessByDate = dates
                .Select(d => new FileCollectionByDate(d, 
                                nfdumpFiles[d].Select(x => x.file).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(), 
                                syslogFiles[d].Select(x => x.file).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList()
                            )
                        )
                .OrderBy(x => x.Date)
                .ToList();

            // Process each day of files, and write to new stream.
            // PERF: each day could be processed in parallel.
            Console.CancelKeyPress += Console_CancelKeyPress;
            foreach (var data in toProcessByDate)
            {
                ProcessDayOfFiles(data, outDir, Cancellation.Token);
                if (Cancellation.IsCancellationRequested)
                    break;
            }

            // Send positive ack message when we're finished.
            var body = String.Format("Processed logs for {0:N0} day(s).\n\n{1}\n\n{2}", toProcessByDate.Count(),
                                    String.Join("\n", toProcessByDate.Select(x => String.Format("  - {0:yyyy-MM-dd}: {1:N0} records compressed to {2:N2}MB. Read {3:N0} syslog file(s), {4:N0} nfdump files, {5:N0} files encrypted. {6}", x.Date, x.RecordsWritten, x.FileSizeWritten / OneMegabyte, x.SyslogFiles.Count(), x.NfdumpFiles.Count(), x.TotalFilesEncrypted, x.Status))),
                                    "Usage Summary\n" + String.Join("\n", toProcessByDate.Select(x => $"  -{x.Date:yyyy-MM-dd}\n    " + String.Join("\n    ", x.UsageSummary.Where(y => y.TotalRecords > 0).Select(y => y.ToString()))))

                    );
            if (!toProcessByDate.All(x => x.IsCompletedSuccessfully))
                body = "Processing was INCOMPLETE\n\n" + body;
            Console.WriteLine("*** RESULTS ***");
            Console.WriteLine(body);
            ExtensionsAndHelpers.SendEmail(subject: "Wenty Anglican - Successful - Internet Traffic Aggregation", body: body);

            // Return 0 if everything worked. 1 otherwise.
            if (toProcessByDate.All(x => x.IsCompletedSuccessfully))
            {
                Console.WriteLine("Completed successfully at " + DateTimeOffset.Now);
                return 0;
            }
            else
            {
                Console.WriteLine("Completed with errors at " + DateTimeOffset.Now);
                return 1;
            }
        }

        private static readonly CancellationTokenSource Cancellation = new CancellationTokenSource();
        private static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            Cancellation.Cancel();
            e.Cancel = true;
        }

        private static void ProcessDayOfFiles(FileCollectionByDate data, DirectoryInfo outputDir, CancellationToken cancelToken)
        {
            // Determine an output file.
            var outFilename = Path.Combine(outputDir.FullName, data.Date.ToString("yyyy-MM-dd") + ".internet_usage_logs.tsv.bz2");
            data.FilenameAndPath = outFilename;
            if (File.Exists(outFilename))
                File.Delete(outFilename);
            Console.WriteLine("Writing data for date {0:yyyy-MM-dd}. {1:N0} nfdump and {2:N0} syslog file(s) to process.", data.Date, data.NfdumpFiles.Count(), data.SyslogFiles.Count());
            Console.WriteLine("Writing to: " + outFilename);

            // TODO: gather DNS lookups and whois information for all addresses in each day's traffic logs.
            //       store them as a separate file along side usage logs.
            //       Make sure we keep a tab on address ranges so we don't keep querying the same record over and over
            // http://whoisclient.codeplex.com/
            // http://whoisclient.apphb.com/?Query=2001:44b8:3168:9b00:c047:576:a84b:4f92&Server=wq.apnic.net&Encoding=us-ascii
            // http://whoisclient.apphb.com/?Query=150.101.201.180&Server=wq.apnic.net&Encoding=us-ascii


            // Open output file stream.
            long recordCount = 0;
            data.WasStarted = true;
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                using (var outStream = new FileStream(outFilename, FileMode.Create, FileAccess.ReadWrite, FileShare.None, 64 * 1024))
                using (var outBzipStream = new BZip2OutputStream(outStream, 9))
                using (var outWriter = new StreamWriter(outBzipStream, new UTF8Encoding(false), 64 * 1024))
                {
                    outWriter.NewLine = "\n";       // UNIX style newlines to save (a little) space.
                    
                    // Read inputs in date order (assuming that lines are sequential).
                    foreach (var record in ReadLogRecordsFromSyslogAndNfdump(data))
                    {
                        // Aggregate bsaic usage summary.
                        var maybeNfdumpRecord = record as NfdumpFileRecord;
                        if (maybeNfdumpRecord != null)
                        {
                            // Assumes there is a catch all bucket.
                            var matchedBucket = data.UsageSummary.First(x => x.IsMatch(maybeNfdumpRecord));
                            matchedBucket.Add(maybeNfdumpRecord);
                            maybeNfdumpRecord.AggregateTag = matchedBucket.Name;
                        }

                        // Write each object to single day of data.
                        record.WriteToOutput(outWriter);
                        recordCount++;
                        if (recordCount % 1000 == 0)
                            Console.Write('.');
                        if (cancelToken.IsCancellationRequested)
                            break;
                    }
                    Console.WriteLine();

                    // Flush all streams before closing.
                    outWriter.Flush();
                    outBzipStream.Flush();
                    outStream.Flush();

                    // Record some stats about what we wrote.
                    data.FileSizeWritten = outStream.Position;
                    data.RecordsWritten = recordCount;
                }
                sw.Stop();

                data.WasCancelled = cancelToken.IsCancellationRequested;
                if (cancelToken.IsCancellationRequested)
                {
                    Console.WriteLine("Cancelled by user.");
                    return;
                }
                Console.WriteLine("Wrote data for date {0:yyyy-MM-dd}. {1:N0} record(s) written in {2:N1}sec ({3:N1}/sec).", data.Date, recordCount, sw.Elapsed.TotalSeconds, recordCount / sw.Elapsed.TotalSeconds);

                // Once all are processed, we encrypt files just processed for long term storage. 
                // This implicitly restricts what is processed in subsequent runs (files will have extensions .log.bz2.gpg).
                if (Config.EncryptFiles)
                {
                    Console.WriteLine("Encrypting {0:N0} files for {1:yyyy-MM-dd}.", data.TotalFiles, data.Date);
                    sw.Restart();
                    data.TotalFilesEncrypted += EncryptFile(data.FilenameAndPath) ? 1 : 0;
                    foreach (var file in data.SyslogFiles.Concat(data.NfdumpFiles))
                    {
                        data.TotalFilesEncrypted += EncryptFile(file) ? 1 : 0;
                        Console.Write('.');
                        if (Cancellation.IsCancellationRequested)
                            break;
                    }
                    sw.Stop();
                    Console.WriteLine();
                    if (cancelToken.IsCancellationRequested)
                    {
                        Console.WriteLine("Cancelled by user.");
                        return;
                    }
                    Console.WriteLine("Encrypted {0:N0} files for date {1:yyyy-MM-dd} (in {2:N1}sec, {3:N1}/sec).", data.TotalFilesEncrypted, data.Date, sw.Elapsed.TotalSeconds, data.TotalFilesEncrypted / sw.Elapsed.TotalSeconds);
                }

				
				// Finally, we tar all the nfdump logs together, so we don't end up with 100k files in a month or two.
                if (Config.TarNfdumpLogs)
                {
                    Console.WriteLine("Tar-ing {0:N0} nfdump files for {1:yyyy-MM-dd}.", data.NfdumpFiles.Count(), data.Date);
                    sw.Restart();
                    data.TotalFilesEncrypted += TarNfdumpFiles(data.FilenameAndPath, data.Date) ? 1 : 0;
                    sw.Stop();
                    Console.WriteLine();
                    if (cancelToken.IsCancellationRequested)
                    {
                        Console.WriteLine("Cancelled by user.");
                        return;
                    }
                    Console.WriteLine("Encrypted {0:N0} files for date {1:yyyy-MM-dd} (in {2:N1}sec, {3:N1}/sec).", data.TotalFilesEncrypted, data.Date, sw.Elapsed.TotalSeconds, data.TotalFilesEncrypted / sw.Elapsed.TotalSeconds);                    
                }
                
            }
            catch (Exception ex)
            {
                sw.Stop();
                data.Error = ex;
                Console.WriteLine("Error when processing data for day '{0:yyyy-MM-dd}'. Got to line {1:N0}. Skipping to next day.\n\n{2}", data.Date, recordCount, ex);
                ExtensionsAndHelpers.SendEmail(subject: "Wenty Anglican - Error - Internet Traffic Aggregation",
                    body: String.Format("Error when processing data for day '{0:yyyy-MM-dd}'. Got to line {1:N0}. Skipping to next day.\n\n{2}", data.Date, recordCount, ex)
                );

            }
        }

        private static bool EncryptFile(string filenameAndPath)
        {
            if (File.Exists(filenameAndPath + ".gpg"))
                File.Delete(filenameAndPath + ".gpg");
            var exe = Config.PathToGpg;
            var args = String.Format("{2} -r {0} \"{1}\"", Config.GpgIdentityToEncryptTo, filenameAndPath, Config.GpgCommand);
            var result = ExtensionsAndHelpers.Exec(exe, args) == 0;
            if (result)
                // Delete the original file if the encryption succeeded.
                File.Delete(filenameAndPath);
            return result;
        }
        private static bool TarNfdumpFiles(string folder, DateTime date)
        {
            // tar -c --remove-files -f nfcapd.2017-10-31.log.bz2.gpg.tar nfcapd.20171031*.log.bz2.gpg
            var encryptFiles = Config.EncryptFiles;
            var filenameAndPath = Path.Combine(folder, $"nfcapd.{date:yyyy-MM-dd}.log.bz2{(encryptFiles ? ".gpg" : "")}.tar");
            var source = Path.Combine(folder, $"nfcapd.{date:yyyyMMdd}*.log.bz2{(encryptFiles ? ".gpg" : "")}");
            var exe = Config.PathToTar;
            var args = $"-c --remove-files -f {filenameAndPath} {source}";
            var result = ExtensionsAndHelpers.Exec(exe, args) == 0;
            return result;
        }

        private static IEnumerable<FileRecord> ReadLogRecordsFromSyslogAndNfdump(FileCollectionByDate data)
        {
            // Yield lines in date order.
            // Generally we assume the sequence in the files are correct, but we need to merge the two files, which we do by date.
            var syslogRecords = ReadSyslogFiles(data.SyslogFiles, data.Date);
            var nfdumpRecords = ReadNfdumpFiles(data.NfdumpFiles, data.Date);
            var comparer = Comparer<DateTimeOffset>.Create((d1, d2) => d1.CompareTo(d2));

            return ExtensionsAndHelpers.MergeCollections<FileRecord, DateTimeOffset>(syslogRecords, nfdumpRecords, x => x.DateAndTime, comparer);
        }

        private static IEnumerable<FileRecord> ReadSyslogFiles(IEnumerable<string> files, DateTime fileDate)
        {
            // Assumption: the files are in correct sequence order (via OrderBy when reading files).
            foreach (var f in files)
            {
                // Can't yield return in a try {} block, so we buffer.
                // Nfdump records are often slightly out of order, so we buffer and sort them.
                var buffer = new List<FileRecord>(16 * 1000);
                bool fileFailed = false;

                using (var inStream = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.None))
                using (var inBzipStream = new BZip2InputStream(inStream))
                using (var inReader = new StreamReader(inBzipStream, Encoding.UTF8))
                {
                    // Parse and return a record.
                    // Note that some interesting syslog records span multiple lines (dhcp and wireless).
                    foreach (var r in SyslogFileRecord.ParseFromFile(inReader, fileDate))
                        yield return r;
                }
            }
        }
        private static IPAddress _LastPublicIpAddress;
        private static IEnumerable<FileRecord> ReadNfdumpFiles(IEnumerable<string> files, DateTime fileDate)
        {
            // Assumption: the files are in correct sequence order (via OrderBy when reading files).
            foreach (var f in files)
            {
                // Can't yield return in a try {} block, so we buffer.
                var buffer = new List<NfdumpFileRecord>(16 * 1000);
                bool fileFailed = false;
                long lineNumber = 1;        // Assume a single line header.
                try
                {
                    using (var inStream = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.None))
                    using (var inBzipStream = new BZip2InputStream(inStream))
                    using (var inReader = new StreamReader(inBzipStream, Encoding.UTF8))
                    {
                        // Parse and return a record.
                        // Nfdump records are one per line (with a header and some summary aggregates in the footer).
                        foreach (var r in NfdumpFileRecord.ParseFromFile(inReader))
                        {
                            lineNumber++;
                            buffer.Add(r);
                        }
                    }
                }
                catch (IOException ex)
                {
                    fileFailed = true;
                    Console.WriteLine("Error reading from '{0}', skipping file: {1}.", Path.GetFileName(f), ex.GetType().FullName + " - " + ex.Message);
                }
                catch (FormatException ex)
                {
                    fileFailed = true;
                    Console.WriteLine("Error parsing from '{0}', line {1:N}, skipping file: {2}.", Path.GetFileName(f), lineNumber, ex.GetType().FullName + " - " + ex.Message);
                }

                if (!fileFailed)
                {
                    // Determine the most likely IP for public IP address at this point (most frequent non-local address).
                    var ips = buffer.Select(x => x.DestinationIpAddress)
                                     .Concat(buffer.Select(x => x.SourceIpAddress));
                    if (_LastPublicIpAddress != null)
                        // Add some weight to previous IP to hopefully tip the balance when traffic is light.
                        ips = ips.Concat(Enumerable.Repeat(_LastPublicIpAddress, (int)((double)buffer.Count * 0.10)));
                    var mostLikelyPublicIp = ips
                        .Where(ip => ip.IsIPv4() && !ip.IsPrivateIpv4())
                        .GroupBy(ip => ip)
                        .Select(x => new { ip = x.Key, Count = x.Count() })
                        .OrderByDescending(x => x.Count)
                        .FirstOrDefault()
                        ?.ip;
                    foreach (var r in buffer)
                        r.PublicIp = mostLikelyPublicIp;
                    _LastPublicIpAddress = mostLikelyPublicIp;


                    const int windowSize = 500;
                    var sortedBuffer = buffer.OrderBy(x => x.DateAndTime).ToList();      // Nfdump records are often slightly out of order, so we sort them.
                    var adjacentRecords = new LinkedList<NfdumpFileRecord>(sortedBuffer.Take(windowSize));
                    var forwardReader = sortedBuffer.Skip(windowSize).GetEnumerator();
                    foreach (var r in sortedBuffer)
                    {
                        var rec = r;        // So we can change the record we might return due to NAT translation.
                        // Attempt to translate NAT address.
                        if (rec.IsPublicIpToAttemptNatTranslation())
                            rec = TryTranslateDestinationNatAddress(rec, adjacentRecords);

                        yield return rec;

                        // Update the list of recent records.
                        if (forwardReader.MoveNext())
                            adjacentRecords.AddLast(forwardReader.Current);
                        while (adjacentRecords.Count > windowSize * 2)
                            adjacentRecords.RemoveFirst();
                    }
                }
                buffer.Clear();
            }
        }
        private static NfdumpFileRecord TryTranslateDestinationNatAddress(NfdumpFileRecord rec, LinkedList<NfdumpFileRecord> adjacentRecords)
        {
            var node = adjacentRecords.Last;
            while (node != null)
            {
                // The streams come in looking like this:
                // src ip           src port  dest ip          dest port   proto
                // [192.168.0.252]  61456	  104.99.205.55    443	       TCP         = recentNode.Value
                // 104.99.205.55    443       {203.171.77.25}  61456       TCP         = rec
                // The IP in curly braces should be the one in square brackets, but the traffic flow isn't translating NAT for us :-/
                // Note that you cannot assume the previous record is the one to look for, but match on ip & port combos.
                // YOu cannot assume the private address record is before the public one either, about 10% of the time it isn't.
                // It should be no more than a few records forward or back though.
                // The curly braces IP should be the public interface IP address, which we guess on a per nfdump file basis (assuming it will change infrequently).
                if (rec.Protocol == node.Value.Protocol
                    && rec.DestinationPort == node.Value.SourcePort
                    && rec.SourcePort == node.Value.DestinationPort
                    && rec.SourceIpAddress.Equals(node.Value.DestinationIpAddress)
                    && node.Value.SourceIpAddress.IsPrivateIpv4())
                    // Translate!
                    return NfdumpFileRecord.TranslateNat(rec, node.Value.SourceIpAddress);

                node = node.Previous;
            }

            // No translation was done.
            return rec;
        }


        private sealed class FileCollectionByDate
        {
            public FileCollectionByDate(DateTime date, IEnumerable<string> nfdumpFiles, IEnumerable<string> syslogFiles)
            {
                this.Date = date;
                this.NfdumpFiles = nfdumpFiles;
                this.SyslogFiles = syslogFiles;
            }
            public readonly DateTime Date;
            public readonly IEnumerable<string> NfdumpFiles;
            public readonly IEnumerable<string> SyslogFiles;
            public int TotalFiles => this.NfdumpFiles.Count() + this.SyslogFiles.Count() + 1;
            public long RecordsWritten { get; set; }
            public long FileSizeWritten { get; set; }
            public string FilenameAndPath { get; set; }

            public string Status => !this.WasStarted ? "UNPROCESSED"
                                  : this.HasError ? "PARSE ERROR" 
                                  : this.WasCancelled ? "CANCELLED" 
                                  : this.TotalFilesEncrypted != this.TotalFiles ? "CRYPTO ERROR"
                                  : "COMPLETE";
            public bool WasStarted { get; set; }
            public bool WasCancelled { get; set; }
            public Exception Error { get; set; }
            public bool HasError => this.Error != null;
            public bool IsCompletedSuccessfully => this.Status == "COMPLETE";

            public int TotalFilesEncrypted { get; set; }

            public IEnumerable<SummaryUsage> UsageSummary = SummaryUsage.CreateBuckets().ToList();

            public override string ToString()
            {
                return this.Date.ToString("yyyy-MM-dd") + " - " + this.Status;
            }
        }

        private abstract class FileRecord
        {
            public readonly DateTimeOffset DateAndTime;
            public readonly string Type;
            public readonly string OriginalLine;

            public FileRecord(DateTimeOffset dt, string type, string originalLine)
            {
                this.DateAndTime = dt;
                this.Type = type;
                this.OriginalLine = originalLine;
            }

            public abstract void WriteToOutput(TextWriter writer);

            // Format of output file:
            // Tab separated lines.
            // - DateTime
            // - RecordType
            // - Additional data determined by RecordType field

            public override string ToString()
            {
                return this.Type + " - " + this.DateAndTime.ToString("HH:mm:ss");
            }

            private static readonly Dictionary<string, int> _MonthLookup = new [] { "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec" }.Select((s, i) => new { s, i }).ToDictionary(x => x.s.ToLower(), x => x.i + 1);
            protected static DateTimeOffset ParsePartialDate(string l, int year)
            {
                int month = _MonthLookup[l.Substring(0, 3).ToLower()];
                int day = Int32.Parse(l.Substring(4, 2));
                TimeSpan time = TimeSpan.ParseExact(l.Substring(7, 8), "hh\\:mm\\:ss", System.Globalization.CultureInfo.CurrentCulture);
                return new DateTime(year, month, day, time.Hours, time.Minutes, time.Seconds, DateTimeKind.Local);
            }
        }
        private abstract class SyslogFileRecord : FileRecord
        {
            public SyslogFileRecord(DateTimeOffset dt, string type, string originalLine)
                : base(dt, type, originalLine) { }

            public static IEnumerable<FileRecord> ParseFromFile(TextReader reader, DateTime fileDate)
            {
                // Many syslog records span multiple lines.
                // We parse all the lines to extract various useful information.
                var l = "";
                var dhcpExtraDetails = new Dictionary<long, DhcpData>();
                long lastDhcpId = Int64.MinValue;
                long lineNumber = 1;
                bool isDhcpAckDetail = false;

                while (!String.IsNullOrEmpty((l = reader.ReadLine())))
                {
                    var originalLine = Config.IncludeOriginalLineInOutput ? "▸" + lineNumber.ToString() + ":" + l : null;

                    if (l.Contains("wireless,info", StringComparison.OrdinalIgnoreCase) 
                        && l.Contains(" disconnected", StringComparison.OrdinalIgnoreCase))
                    {
                        // Single line wireless disconnection message.
                        var data = ParseWirelessConnectAndDisconnectRecords(l);
                        yield return new SyslogWirelessDisconnectionFileRecord(ParsePartialDate(l, fileDate.Year), data.Item1, data.Item2, originalLine);
                    }
                    else if (l.Contains("wireless", StringComparison.OrdinalIgnoreCase)
                        && l.Contains(" connected", StringComparison.OrdinalIgnoreCase))
                    {
                        // Single line wireless connection message.
                        var data = ParseWirelessConnectAndDisconnectRecords(l);
                        yield return new SyslogWirelessConnectionFileRecord(ParsePartialDate(l, fileDate.Year), data.Item1, data.Item2, originalLine);
                    }
                    else if (l.Contains("web-proxy,account", StringComparison.OrdinalIgnoreCase))
                    {
                        // Single line proxy message.
                        var startOfUrlIdx = l.IndexOf("http://", StringComparison.OrdinalIgnoreCase);
                        if (startOfUrlIdx < 0)
                        {
                            // No URL - probably a CONNECT or something more obscure.
                            var startOfCategory = l.IndexOf("web-proxy,account", StringComparison.OrdinalIgnoreCase);
                            var startOfIpIdx = l.IndexOf(' ', startOfCategory + 1);
                            var startOfVerbIdx = l.IndexOf(' ', startOfIpIdx + 1);
                            var startOfNextIdx = l.IndexOf(' ', startOfVerbIdx + 1);
                            var endOfNextIdx = l.IndexOf("action=", startOfNextIdx + 1, StringComparison.OrdinalIgnoreCase);

                            yield return new SyslogProxyFileRecord(ParsePartialDate(l, fileDate.Year), l.Substring(startOfIpIdx, startOfVerbIdx - startOfIpIdx).Trim(), l.Substring(startOfVerbIdx, startOfNextIdx - startOfVerbIdx).Trim(), l.Substring(startOfNextIdx, endOfNextIdx - startOfNextIdx).Trim(), originalLine);
                        }
                        else
                        {
                            // URL present: normal case.
                            var endOfUrlIdx = l.IndexOf(' ', startOfUrlIdx);
                            if (endOfUrlIdx < 0)
                                endOfUrlIdx = l.Length;
                            var startOfVerbIdx = l.IndexOfBackwards(' ', startOfUrlIdx - 1);
                            var startOfIpIdx = l.IndexOfBackwards(' ', startOfVerbIdx - 1);

                            yield return new SyslogProxyFileRecord(ParsePartialDate(l, fileDate.Year), l.Substring(startOfIpIdx, startOfVerbIdx - startOfIpIdx).Trim(), l.Substring(startOfVerbIdx, startOfUrlIdx - startOfVerbIdx).Trim(), l.Substring(startOfUrlIdx, endOfUrlIdx - startOfUrlIdx).Trim(), originalLine);
                        }
                    }
                    else if (l.Contains("dhcp,info", StringComparison.OrdinalIgnoreCase)
                        && l.Contains(" assigned", StringComparison.OrdinalIgnoreCase))
                    {
                        // Single line dhcp assigned message.
                        var startOfIpIdx = l.IndexOf("assigned ", StringComparison.OrdinalIgnoreCase) + "assigned ".Length;
                        var endOfIpIdx = l.IndexOf(' ', startOfIpIdx);
                        var startOfMacIdx = l.IndexOf("to ", endOfIpIdx, StringComparison.OrdinalIgnoreCase) + "to ".Length;
                        var endOfMacIdx = l.Length;
                        var maybeClassId = "";
                        var maybeHostname = "";
                        if (lastDhcpId != Int64.MinValue && dhcpExtraDetails.ContainsKey(lastDhcpId))
                        {
                            // Possibly with extra data obtained from dhcp debug packets.
                            maybeClassId = dhcpExtraDetails[lastDhcpId].classId;
                            maybeHostname = dhcpExtraDetails[lastDhcpId].providedHostname;
                        }
                        yield return new SyslogDhcpAssignedFileRecord(ParsePartialDate(l, fileDate.Year), l.Substring(startOfMacIdx, endOfMacIdx - startOfMacIdx), l.Substring(startOfIpIdx, endOfIpIdx - startOfIpIdx), maybeHostname, maybeClassId, originalLine);
                    }
                    else if (l.Contains("dhcp,info", StringComparison.OrdinalIgnoreCase)
                        && l.Contains(" deassigned", StringComparison.OrdinalIgnoreCase))
                    {
                        // Single line dhcp deassigned message.
                        var startOfIpIdx = l.IndexOf("deassigned ", StringComparison.OrdinalIgnoreCase) + "deassigned ".Length;
                        var endOfIpIdx = l.IndexOf(' ', startOfIpIdx);
                        var startOfMacIdx = l.IndexOf("from ", endOfIpIdx, StringComparison.OrdinalIgnoreCase) + "from ".Length;
                        var endOfMacIdx = l.Length;
                        yield return new SyslogDhcpDeassignedFileRecord(ParsePartialDate(l, fileDate.Year), l.Substring(startOfMacIdx, endOfMacIdx - startOfMacIdx), l.Substring(startOfIpIdx, endOfIpIdx - startOfIpIdx), originalLine);
                    }
                    else if (l.Contains("dhcp,debug,packet", StringComparison.OrdinalIgnoreCase))
                    {
                        // Multi line dhcp message.
                        // Aggregate information for the dhcp assigned message.
                        if (l.Contains("received request with id ", StringComparison.OrdinalIgnoreCase) 
                            || l.Contains("received discover with id ", StringComparison.OrdinalIgnoreCase)
                            || l.Contains("sending offer with id ", StringComparison.OrdinalIgnoreCase)
                            || l.Contains("sending ack with id ", StringComparison.OrdinalIgnoreCase))
                        {
                            isDhcpAckDetail = l.Contains("sending ack with id ", StringComparison.OrdinalIgnoreCase);
                            lastDhcpId = ParseDhcpId(l);
                            if (!dhcpExtraDetails.ContainsKey(lastDhcpId))
                                dhcpExtraDetails[lastDhcpId] = new DhcpData() { id = lastDhcpId };
                        }
                        else if (l.Contains("dhcp,debug,packet", StringComparison.OrdinalIgnoreCase)
                                && l.Contains("Class-Id =", StringComparison.OrdinalIgnoreCase)
                                && dhcpExtraDetails.ContainsKey(lastDhcpId))
                        {
                            var dd = dhcpExtraDetails[lastDhcpId];
                            var startIdx = l.IndexOf(" Class-Id = ", StringComparison.OrdinalIgnoreCase) + " Class-Id = ".Length;
                            var endIdx = l.Length;
                            dd.classId = l.Substring(startIdx, endIdx - startIdx).Trim().Trim('"');
                        }
                        else if (l.Contains("dhcp,debug,packet", StringComparison.OrdinalIgnoreCase)
                                && l.Contains("Host-Name =", StringComparison.OrdinalIgnoreCase)
                                && dhcpExtraDetails.ContainsKey(lastDhcpId))
                        {
                            var dd = dhcpExtraDetails[lastDhcpId];
                            var startIdx = l.IndexOf(" Host-Name = ", StringComparison.OrdinalIgnoreCase) + " Host-Name = ".Length;
                            var endIdx = l.Length;
                            dd.providedHostname = l.Substring(startIdx, endIdx - startIdx).Trim().Trim('"');
                        }
                        else if (l.Contains("dhcp,debug,packet", StringComparison.OrdinalIgnoreCase)
                                && l.Contains("yiaddr =", StringComparison.OrdinalIgnoreCase)
                                && dhcpExtraDetails.ContainsKey(lastDhcpId))
                        {
                            var dd = dhcpExtraDetails[lastDhcpId];
                            var startIdx = l.IndexOf(" yiaddr = ", StringComparison.OrdinalIgnoreCase) + " yiaddr = ".Length;
                            var endIdx = l.Length;
                            dd.assignedIp = l.Substring(startIdx, endIdx - startIdx).Trim().Trim('"');
                        }
                        else if (l.Contains("dhcp,debug,packet", StringComparison.OrdinalIgnoreCase)
                                && l.Contains("chaddr =", StringComparison.OrdinalIgnoreCase)
                                && dhcpExtraDetails.ContainsKey(lastDhcpId))
                        {
                            var dd = dhcpExtraDetails[lastDhcpId];
                            var startIdx = l.IndexOf(" chaddr = ", StringComparison.OrdinalIgnoreCase) + " chaddr = ".Length;
                            var endIdx = l.Length;
                            dd.deviceAddress = l.Substring(startIdx, endIdx - startIdx).Trim().Trim('"');
                        }
                        else if (l.Contains("dhcp,debug,packet", StringComparison.OrdinalIgnoreCase)
                                && l.Contains("chaddr =", StringComparison.OrdinalIgnoreCase)
                                && dhcpExtraDetails.ContainsKey(lastDhcpId))
                        {
                            // To record a DHCP ack message
                            var dd = dhcpExtraDetails[lastDhcpId];
                            var startIdx = l.IndexOf(" Router = ", StringComparison.OrdinalIgnoreCase) + " Router = ".Length;
                            yield return new SyslogDhcpAssignedFileRecord(ParsePartialDate(l, fileDate.Year), dd.deviceAddress, dd.assignedIp, dd.providedHostname, dd.classId, originalLine);
                        }
                    }

                    lineNumber++;
                }
            }
            private static long ParseDhcpId (string l)
            {
                var startIdx = l.IndexOf(" with id ") + " with id ".Length;
                var endIdx = l.IndexOf(' ', startIdx);
                var result = Int64.Parse(l.Substring(startIdx, endIdx - startIdx));
                return result;
            }
            private static Tuple<string, string> ParseWirelessConnectAndDisconnectRecords(string l)
            {
                var startIdx = l.IndexOf("wireless,info") + "wireless, info".Length;
                var endIdx = l.IndexOf('@', startIdx);
                var deviceAddress = l.Substring(startIdx, endIdx - startIdx);
                startIdx = endIdx + 1;
                endIdx = l.IndexOf(':', startIdx);
                var networkInterface = l.Substring(startIdx, endIdx - startIdx);
                return Tuple.Create(deviceAddress, networkInterface);
            }
            private static int ParseDhcpConnectionId(string l)
            {
                var startIdx = l.IndexOf(" with id ") + " with id ".Length;
                var endIdx = l.IndexOf(' ', startIdx);
                var result = Int32.Parse(l.Substring(startIdx, endIdx - startIdx));
                return result;
            }

            public class DhcpData
            {
                public long id { get; set; }
                public string providedHostname { get; set; }
                public string classId { get; set; }
                public string deviceAddress { get; set; }
                public string assignedIp { get; set; }
            }
        }
        private sealed class SyslogWirelessConnectionFileRecord : SyslogFileRecord
        {
            public readonly string DeviceAddress;
            public readonly string NetworkInterface;

            public SyslogWirelessConnectionFileRecord(DateTimeOffset dt, string deviceAddress, string networkInterface, string originalLine)
                : base(dt, "WirelessConnection", originalLine)
            {
                this.DeviceAddress = deviceAddress;
                this.NetworkInterface = networkInterface;
            }
            public override void WriteToOutput(TextWriter writer)
            {
                writer.Write("{0:yyyy-MM-dd HH:mm:ss zzz}\t{1}\t", this.DateAndTime, this.Type);
                writer.Write("{0}\t{1}", this.NetworkInterface, this.DeviceAddress);
                if (!String.IsNullOrEmpty(this.OriginalLine))
                    writer.Write("\t" + OriginalLine);
                writer.WriteLine();
            }
        }
        private sealed class SyslogWirelessDisconnectionFileRecord : SyslogFileRecord
        {
            public readonly string DeviceAddress;
            public readonly string NetworkInterface;

            public SyslogWirelessDisconnectionFileRecord(DateTimeOffset dt, string deviceAddress, string networkInterface, string originalLine)
                : base(dt, "WirelessDisconnection", originalLine)
            {
                this.DeviceAddress = deviceAddress;
                this.NetworkInterface = networkInterface;
            }
            public override void WriteToOutput(TextWriter writer)
            {
                writer.Write("{0:yyyy-MM-dd HH:mm:ss zzz}\t{1}\t", this.DateAndTime, this.Type);
                writer.Write("{0}\t{1}", this.NetworkInterface, this.DeviceAddress);
                if (!String.IsNullOrEmpty(this.OriginalLine))
                    writer.Write("\t" + OriginalLine);
                writer.WriteLine();
            }
        }
        private abstract class SyslogDhcpFileRecord : SyslogFileRecord
        {
            public readonly string DeviceAddress;
            public readonly string AssignedIpAddress;

            public SyslogDhcpFileRecord(DateTimeOffset dt, string type, string deviceAddress, string assignedIpAddress, string originalLine)
                : base(dt, type, originalLine)
            {
                this.DeviceAddress = deviceAddress;
                this.AssignedIpAddress = assignedIpAddress;
            }
        }
        private sealed class SyslogDhcpAssignedFileRecord : SyslogDhcpFileRecord
        {
            public readonly string ProvidedHostname;
            public readonly string ClassId;

            public SyslogDhcpAssignedFileRecord(DateTimeOffset dt, string deviceAddress, string assignedIpAddress, string providedHostname, string classId, string originalLine)
                : base(dt, "DhcpAssigned", deviceAddress, assignedIpAddress, originalLine)
            {
                this.ProvidedHostname = providedHostname;
                this.ClassId = classId;
            }
            public override void WriteToOutput(TextWriter writer)
            {
                writer.Write("{0:yyyy-MM-dd HH:mm:ss zzz}\t{1}\t", this.DateAndTime, this.Type);
                writer.Write("{0}\t{1}\t{2}\t{3}", this.DeviceAddress, this.AssignedIpAddress, this.ProvidedHostname, this.ClassId);
                if (!String.IsNullOrEmpty(this.OriginalLine))
                    writer.Write("\t" + OriginalLine);
                writer.WriteLine();
            }
        }
        private sealed class SyslogDhcpDeassignedFileRecord : SyslogDhcpFileRecord
        {
            public SyslogDhcpDeassignedFileRecord(DateTimeOffset dt, string deviceAddress, string assignedIpAddress, string originalLine)
                : base(dt, "DhcpDeassigned", deviceAddress, assignedIpAddress, originalLine)
            {
            }
            public override void WriteToOutput(TextWriter writer)
            {
                writer.Write("{0:yyyy-MM-dd HH:mm:ss zzz}\t{1}\t", this.DateAndTime, this.Type);
                writer.Write("{0}\t{1}", this.DeviceAddress, this.AssignedIpAddress);
                if (!String.IsNullOrEmpty(this.OriginalLine))
                    writer.Write("\t" + OriginalLine);
                writer.WriteLine();
            }
        }
        private sealed class SyslogProxyFileRecord : SyslogFileRecord
        {
            public readonly string SourceIpAddress;
            public readonly string HttpMethod;
            public readonly string TargetUrl;

            public SyslogProxyFileRecord(DateTimeOffset dt, string sourceIpAddress, string httpMethod, string targetUrl, string originalLine)
                : base(dt, "ProxyRequest", originalLine)
            {
                this.SourceIpAddress = sourceIpAddress;
                this.HttpMethod = httpMethod;
                this.TargetUrl = targetUrl;
            }
            public override void WriteToOutput(TextWriter writer)
            {
                writer.Write("{0:yyyy-MM-dd HH:mm:ss zzz}\t{1}\t", this.DateAndTime, this.Type);
                writer.Write("{0}\t{1}\t{2}", this.SourceIpAddress, this.HttpMethod, this.TargetUrl);
                if (!String.IsNullOrEmpty(this.OriginalLine))
                    writer.Write("\t" + OriginalLine);
                writer.WriteLine();
            }
        }
        private sealed class NfdumpFileRecord : FileRecord
        {
            private static readonly Char[] CommaDelimiter = new char[] { ',' };

            public readonly DateTimeOffset DateTimeEnd;
            public readonly int DurationMilliseconds;
            public readonly IPAddress SourceIpAddress;
            public readonly IPAddress DestinationIpAddress;
            public readonly UInt16 SourcePort;
            public readonly UInt16 DestinationPort;
            public readonly string Protocol;
            public readonly Int32 IncomingPacketCount;
            public readonly Int32 OutgoingPacketCount;
            public readonly Int32 IncomingByteCount;
            public readonly Int32 OutgoingByteCount;
            public readonly string InSourceMacAddress;
            public readonly string InDestinationMacAddress;
            public readonly string OutSourceMacAddress;
            public readonly string OutDestinationMacAddress;

            public readonly IPAddress PreNATDestinationIpAddress;
            public bool IsNatTranslatedDestination => this.PreNATDestinationIpAddress != null;
            public IPAddress PublicIp;
            public string AggregateTag;

            private NfdumpFileRecord(DateTimeOffset dtStart, DateTimeOffset dtEnd, int durationMilliseconds, IPAddress sourceIp, IPAddress destIp, UInt16 sourcePort, UInt16 destPort, string protocol, Int32 incomingPacketCount, Int32 outgoingPacketCount, Int32 incomingByteCount, Int32 outgoingByteCount, string inSrcMac, string inDestMac, string outSrcMac, string outDestMac, string originalLine, IPAddress preNatDestinationIpAddress)
                : base(dtStart, "Traffic", originalLine)
            {
                this.DateTimeEnd = dtEnd;
                this.DurationMilliseconds = durationMilliseconds;
                this.SourceIpAddress = sourceIp;
                this.DestinationIpAddress = destIp;
                this.SourcePort = sourcePort;
                this.DestinationPort = destPort;
                this.Protocol = protocol;
                this.IncomingPacketCount = incomingPacketCount;
                this.OutgoingPacketCount = outgoingPacketCount;
                this.IncomingByteCount = incomingByteCount;
                this.OutgoingByteCount = outgoingByteCount;
                this.InSourceMacAddress = inSrcMac;
                this.InDestinationMacAddress = inDestMac;
                this.OutSourceMacAddress = outSrcMac;
                this.OutDestinationMacAddress = outDestMac;
                this.PreNATDestinationIpAddress = preNatDestinationIpAddress;
            }

            public static IEnumerable<NfdumpFileRecord> ParseFromFile(TextReader reader)
            {
                // The first line is a header.
                // The last few lines are summary aggregates.
                var l = "";
                var isHeaderLine = true;
                long lineNumber = 1;
                // Use the file's header to determine index of fields we're looking for.
                int timestampStartIdx = -1,
                    timestampEndIdx = -1,
                    durationIdx = -1,
                    sourceIpIdx = -1,
                    destinationIpIdx = -1,
                    sourcePortIdx = -1,
                    destinationPortIdx = -1,
                    protocolIdx = -1,
                    incomingPacketsIdx = -1,
                    outgoingPacketsIdx = -1,
                    incomingBytesIdx = -1,
                    outgoingBytesIdx = -1,
                    incomingSourceMacIdx = -1,
                    incomingDestMacIdx = -1,
                    outgoingSourceMacIdx = -1,
                    outgoingDestMacIdx = -1;


                while (!String.IsNullOrEmpty((l = reader.ReadLine())))
                {
                    if (isHeaderLine)
                    {
                        // Use header line to determine lots of field indexes
                        var columns = l.Split(CommaDelimiter, StringSplitOptions.None);
                        timestampStartIdx = Array.IndexOf(columns, "ts");
                        timestampEndIdx = Array.IndexOf(columns, "te");
                        durationIdx = Array.IndexOf(columns, "td");
                        sourceIpIdx = Array.IndexOf(columns, "sa");
                        destinationIpIdx = Array.IndexOf(columns, "da");
                        sourcePortIdx = Array.IndexOf(columns, "sp");
                        destinationPortIdx = Array.IndexOf(columns, "dp");
                        protocolIdx = Array.IndexOf(columns, "pr");
                        incomingPacketsIdx = Array.IndexOf(columns, "ipkt");
                        outgoingPacketsIdx = Array.IndexOf(columns, "opkt");
                        incomingBytesIdx = Array.IndexOf(columns, "ibyt");
                        outgoingBytesIdx = Array.IndexOf(columns, "obyt");
                        incomingSourceMacIdx = Array.IndexOf(columns, "ismc");
                        incomingDestMacIdx = Array.IndexOf(columns, "idmc");
                        outgoingSourceMacIdx = Array.IndexOf(columns, "osmc");
                        outgoingDestMacIdx = Array.IndexOf(columns, "odmc");

                        isHeaderLine = false;
                        continue;
                    }
                    if (l.StartsWith("Summary") || l.StartsWith("No matched flows"))
                        // Skip summary aggregates at the bottom, or an empty file.
                        yield break;

                    var row = l.Split(CommaDelimiter, StringSplitOptions.None);

                    yield return new NfdumpFileRecord(
                        DateTimeOffset.Parse(row[timestampStartIdx]), 
                        DateTimeOffset.Parse(row[timestampEndIdx]), 
                        (int)(Double.Parse(row[durationIdx]) + 0.5),
                        IPAddress.Parse(row[sourceIpIdx]),
                        IPAddress.Parse(row[destinationIpIdx]),
                        UInt16.Parse(row[sourcePortIdx]),
                        UInt16.Parse(row[destinationPortIdx]),
                        row[protocolIdx], 
                        Int32.Parse(row[incomingPacketsIdx]),
                        Int32.Parse(row[outgoingPacketsIdx]),
                        Int32.Parse(row[incomingBytesIdx]),
                        Int32.Parse(row[outgoingBytesIdx]), 
                        row[incomingSourceMacIdx],
                        row[incomingDestMacIdx],
                        row[outgoingSourceMacIdx],
                        row[outgoingDestMacIdx],
                        Config.IncludeOriginalLineInOutput ? "▸" + lineNumber.ToString() + ":" + l : null,
                        null        // pre-nat IP.
                    );

                    lineNumber++;
                }
            }
            public static NfdumpFileRecord TranslateNat(NfdumpFileRecord ori, IPAddress newIp)
            {
                return new NfdumpFileRecord(
                    ori.DateAndTime,
                    ori.DateTimeEnd,
                    ori.DurationMilliseconds,
                    ori.SourceIpAddress,
                    newIp,                      // NAT translation.
                    ori.SourcePort,
                    ori.DestinationPort,
                    ori.Protocol,
                    ori.IncomingPacketCount,
                    ori.OutgoingPacketCount,
                    ori.IncomingByteCount,
                    ori.OutgoingByteCount,
                    ori.InSourceMacAddress,
                    ori.InDestinationMacAddress,
                    ori.OutSourceMacAddress,
                    ori.OutDestinationMacAddress,
                    ori.OriginalLine,
                    ori.DestinationIpAddress        // Original address before NAT translation.
                );
            }

            public bool IsPublicIpToAttemptNatTranslation()
            {
                return this.PublicIp != null
                    && this.PublicIp.Equals(this.DestinationIpAddress)
                    && this.DestinationIpAddress.IsIPv4()
                    && !this.DestinationIpAddress.IsPrivateIpv4();
            }


            public override void WriteToOutput(TextWriter writer)
            {
                writer.Write("{0:yyyy-MM-dd HH:mm:ss zzz}\t{1}\t", this.DateAndTime, this.Type);
                writer.Write("{0:yyyy-MM-dd HH:mm:ss zzz}\t{1}\t", this.DateTimeEnd, this.DurationMilliseconds);
                writer.Write("{0}\t{1}\t{2}\t{3}\t{4}\t", this.SourceIpAddress, this.SourcePort, this.DestinationIpAddress, this.DestinationPort, this.Protocol);
                writer.Write((this.PreNATDestinationIpAddress == null ? "" : this.PreNATDestinationIpAddress.ToString()) + "\t");
                writer.Write("{0}\t{1}\t{2}\t{3}", this.IncomingPacketCount, this.OutgoingPacketCount, this.IncomingByteCount, this.OutgoingByteCount);
                writer.Write("\t" + this.AggregateTag);
                if (Config.IncludeTrafficMacAddresses)
                    writer.Write("\t{0}\t{1}\t{2}\t{3}", this.InSourceMacAddress, this.InDestinationMacAddress, this.OutSourceMacAddress, this.OutDestinationMacAddress);
                if (!String.IsNullOrEmpty(this.OriginalLine))
                    writer.Write("\t" + OriginalLine);
                writer.WriteLine();
            }
        }

        private sealed class SummaryUsage
        {
            public string Name { get; private set; }
            public Func<NfdumpFileRecord, bool> IsMatch { get; set; }

            public void Add(NfdumpFileRecord r)
            {
                this.TotalPackets = this.TotalPackets + r.IncomingPacketCount + r.OutgoingPacketCount;
                this.TotalBytes = this.TotalBytes + r.IncomingByteCount + r.OutgoingByteCount;
                this.TotalRecords = this.TotalRecords + 1;
            }
            public long TotalPackets { get; private set; }
            public long TotalBytes { get; private set; }
            public long TotalRecords { get; private set; }

            public override string ToString()
            {
                return $"{Name}: traffic = {TotalBytes / OneMegabyte:N2}MB; packets {TotalPackets:N0}; records {TotalRecords:N0}";
            }
            private static bool IsPublicIPv4TrafficForNetwork(IPAddress source, IPAddress destination, IPAddressRange networkRange)
            {
                return source.IsIPv4() && destination.IsIPv4()
                    && (
                           (networkRange.Contains(source) && !destination.IsPrivateIpv4())
                        || (networkRange.Contains(destination) && !source.IsPrivateIpv4())
                    );
            }

            private static readonly IPAddressRange StaffNetmask = IPAddressRange.Parse("192.168.0.0/24");
            private static readonly IPAddressRange MinistryNetmask = IPAddressRange.Parse("192.168.10.0/24");
            private static readonly IPAddressRange NTENetmask = IPAddressRange.Parse("192.168.200.0/24");
            private static readonly IPAddressRange RectoryNetmask = IPAddressRange.Parse("10.18.1.0/24");
            private static readonly IPAddressRange GuestNetmask = IPAddressRange.Parse("10.10.0.0/16");
            public static IEnumerable<SummaryUsage> CreateBuckets()
            {
                // TODO: if these get modified regularly, move them to a config file.
                yield return new SummaryUsage()
                {
                    Name = "Staff (192.168.0.0/24)",
                    IsMatch = r => IsPublicIPv4TrafficForNetwork(r.SourceIpAddress, r.DestinationIpAddress, StaffNetmask),
                };
                yield return new SummaryUsage()
                {
                    Name = "Ministry (192.168.10.0/24)",
                    IsMatch = r => IsPublicIPv4TrafficForNetwork(r.SourceIpAddress, r.DestinationIpAddress, MinistryNetmask),
                };
                yield return new SummaryUsage()
                {
                    Name = "NTE (192.168.200.0/24)",
                    IsMatch = r => IsPublicIPv4TrafficForNetwork(r.SourceIpAddress, r.DestinationIpAddress, NTENetmask),
                };
                yield return new SummaryUsage()
                {
                    Name = "Rectory (10.18.1.0/24)",
                    IsMatch = r => IsPublicIPv4TrafficForNetwork(r.SourceIpAddress, r.DestinationIpAddress, RectoryNetmask),
                };
                yield return new SummaryUsage()
                {
                    Name = "Guest (10.10.0.0/16)",
                    IsMatch = r => IsPublicIPv4TrafficForNetwork(r.SourceIpAddress, r.DestinationIpAddress, GuestNetmask),
                };
                yield return new SummaryUsage()
                {
                    Name = "Router (192.168.0.1)",
                    IsMatch = r => r.SourceIpAddress.Equals(r.PublicIp) || r.DestinationIpAddress.Equals(r.PublicIp),
                };
                // TODO: if these get modified regularly, move them to a config file.

                yield return new SummaryUsage()
                {
                    Name = "IPv4 Local",
                    IsMatch = r => r.SourceIpAddress.IsPrivateIpv4() && r.DestinationIpAddress.IsPrivateIpv4()
                };
                yield return new SummaryUsage()
                {
                    Name = "IPv6 Local",
                    IsMatch = r => r.SourceIpAddress.IsIPv6() && r.DestinationIpAddress.IsIPv6()
                                && (r.SourceIpAddress.IsIPv6Local() || r.DestinationIpAddress.IsIPv6Local()),
                };
                yield return new SummaryUsage()
                {
                    Name = "IPv6 Internet",
                    IsMatch = r => r.SourceIpAddress.IsIPv6() && r.DestinationIpAddress.IsIPv6() 
                                && !r.SourceIpAddress.IsIPv6Local() && !r.DestinationIpAddress.IsIPv6Local(),
                };
                yield return new SummaryUsage()
                {
                    Name = "Other IPv4",
                    IsMatch = r => r.SourceIpAddress.IsIPv4() && r.DestinationIpAddress.IsIPv4(),
                };
                yield return new SummaryUsage()
                {
                    Name = "Other IPv6",
                    IsMatch = r => r.SourceIpAddress.IsIPv6() && r.DestinationIpAddress.IsIPv6(),
                };
                yield return new SummaryUsage()
                {
                    Name = "Catch All",
                    IsMatch = r => true,
                };
            }
        }
    }
}
