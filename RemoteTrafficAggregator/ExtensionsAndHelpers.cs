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
using System.Threading.Tasks;
using System.Net.Mail;
using System.Net;
using NetTools;

namespace RemoteTrafficAggregator
{
    public static class ExtensionsAndHelpers
    {
        public static bool Contains (this string s, string searchFor, StringComparison comparison)
        {
            if (s == null || String.IsNullOrEmpty(searchFor))
                return false;

            return s.IndexOf(searchFor, 0, comparison) != -1;
        }

        public static HashSet<T> ToHashSet<T>(this IEnumerable<T> collection)
        {
            return new HashSet<T>(collection);
        }
        public static HashSet<T> ToHashSet<T>(this IEnumerable<T> collection, IEqualityComparer<T> comparer)
        {
            return new HashSet<T>(collection, comparer);
        }

        public static int IndexOfBackwards(this string s, char ch, int startIdx)
        {
            if (s == null)
                throw new ArgumentNullException(nameof(s));
            if (startIdx < 0 || startIdx > s.Length)
                throw new ArgumentOutOfRangeException(nameof(startIdx), "StartIdx must be between zero and string length.");
            
            for (int i = startIdx; i >= 0; i--)
            {
                if (s[i] == ch) return i;
            }
            return -1;
        }

        public static void SendEmail(string subject, string body)
        {
            var toAddresses = Program.Config.EmailNotificationAddresses.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            if (!toAddresses.Any())
                return;
            var msg = new MailMessage();
            msg.From = new MailAddress(Program.Config.Smtp.FromAddress);
            foreach (var addr in toAddresses)
                msg.To.Add(addr);
            msg.Subject = subject;
            msg.Body = body;
            try
            {
                using (var smtp = new SmtpClient(Program.Config.Smtp.OutgoingServer, Program.Config.Smtp.Port))
                {
                    smtp.Send(msg);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Unable to send email: " + ex.ToString());
            }
        }
        public static int Exec(string executable, string arguments, int timeoutInMilliseconds = 20 * 1000)
        {
            var psi = new System.Diagnostics.ProcessStartInfo();
            psi.UseShellExecute = false;
            psi.FileName = executable;
            psi.Arguments = arguments;
            //psi.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            psi.RedirectStandardError = true;
            psi.RedirectStandardOutput = true;
            using (var p = new System.Diagnostics.Process()
            {
                StartInfo = psi,
            })
            {
                p.OutputDataReceived += (s, e) => Console.WriteLine(e.Data);
                p.ErrorDataReceived += (s, e) => Console.Error.WriteLine(e.Data);
                
                p.Start();
                var exitedBeforeTimeout = p.WaitForExit(timeoutInMilliseconds);
                if (!exitedBeforeTimeout)
                {
                    p.Kill();
                    return Int32.MaxValue;
                }
                return p.ExitCode;
            }

        }

        public static IEnumerable<T> MergeCollections<T, U>(IEnumerable<T> collection1, IEnumerable<T> collection2, Func<T, U> keySelector, IComparer<U> keyComparer)
        {
            var allCollections = new IEnumerable<T>[] { collection1, collection2 };
            var allEnumerators = new IEnumerator<T>[allCollections.Length];
            var enumeratorHasItems = new bool[allCollections.Length];
            int currentCollectionIdx = -1;

            // Pull from each collection and sort based on the key field.
            // As long as the key field is the same, we keep pulling from that collection.

            // Create enumerators for each collection.
            for (int i = 0; i < allCollections.Length; i++)
                allEnumerators[i] = allCollections[i].GetEnumerator();

            try
            {
                // Move to first element for each collection.
                for (int i = 0; i < allEnumerators.Length; i++)
                    enumeratorHasItems[i] = allEnumerators[i].MoveNext();

                // Select the collection to pull from by default (first non-empty collection).
                for (int i = 0; i < allEnumerators.Length; i++)
                {
                    if (enumeratorHasItems[i])
                    {
                        currentCollectionIdx = i;
                        break;
                    }
                }

                while (enumeratorHasItems.Any(x => x))
                {
                    // Find at least one valid enumerator.
                    while (!enumeratorHasItems[currentCollectionIdx])
                        currentCollectionIdx = (currentCollectionIdx + 1) % enumeratorHasItems.Length;

                    // Which enumerator should we pull from?
                    var currentKey = keySelector(allEnumerators[currentCollectionIdx].Current);
                    for (int i = 0; i < allEnumerators.Length; i++)
                    {
                        if (enumeratorHasItems[i] && currentCollectionIdx != i)
                        {
                            var compareToKey = keySelector(allEnumerators[i].Current);
                            var compareResult = keyComparer.Compare(currentKey, compareToKey);
                            if (compareResult <= 0)
                            {
                                // Current is first or equal, continue with current.
                            }
                            else if (compareResult > 0)
                            {
                                // This is before the current, so it should become the current.
                                currentCollectionIdx = i;
                                currentKey = keySelector(allEnumerators[currentCollectionIdx].Current);
                            }
                        }
                    }

                    // Yield.
                    yield return allEnumerators[currentCollectionIdx].Current;
                    enumeratorHasItems[currentCollectionIdx] = allEnumerators[currentCollectionIdx].MoveNext();
                }
            }
            finally
            {
                for (int i = 0; i < allEnumerators.Length; i++)
                    if (allEnumerators[i] != null)
                        allEnumerators[i].Dispose();
            }
        }

        public static bool IsIPv4(this IPAddress ip)
        {
            return ip != null && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        }
        public static bool IsIPv6(this IPAddress ip)
        {
            return ip != null && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        }
        public static bool IsIPv6Local(this IPAddress ip)
        {
            if (ip == null) return false;
            if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6) return false;
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || IPAddress.IPv6Loopback == ip) return true;
            if (IpV6MulticastLocalRange.Contains(ip) || IpV6PrivateLocalRange.Contains(ip)) return true;
            return false;
        }
        public static bool IsIPv6Local(this IPAddress ip, IEnumerable<IPAddressRange> localPublicRanges)
        {
            if (IsIPv6Local(ip)) return true;
            if ((localPublicRanges ?? Enumerable.Empty<IPAddressRange>()).Any(x => x.Contains(ip))) return true;
            return false;
        }
        private static readonly IPAddressRange IpV6MulticastLocalRange = IPAddressRange.Parse("ff02::0/16");
        private static readonly IPAddressRange IpV6PrivateLocalRange = IPAddressRange.Parse("fc00::0/7");
        private static readonly IPAddressRange ClassCRange = IPAddressRange.Parse("192.168.0.0/16");
        private static readonly IPAddressRange ClassBRange = IPAddressRange.Parse("172.16.0.0/12");
        private static readonly IPAddressRange ClassARange = IPAddressRange.Parse("10.0.0.0/8");
        private static readonly IPAddressRange LinkLocalRange = IPAddressRange.Parse("169.254.0.0/16");
        private static readonly IPAddress BroadcastIPv4 = IPAddress.Parse("255.255.255.255");
        private static readonly IPAddress AnyIPv4 = IPAddress.Parse("0.0.0.0");
        public static bool IsPrivateIpv4(this IPAddress ip)
        {
            if (ip == null) return false;
            if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
            if (ClassCRange.Contains(ip) || ClassARange.Contains(ip) || ClassBRange.Contains(ip) || LinkLocalRange.Contains(ip)) return true;
            if (ip.Equals(BroadcastIPv4)) return true;
            if (ip.Equals(AnyIPv4)) return true;
            return false;
        }
    }
}
