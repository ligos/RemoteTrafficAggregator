using System;
using System.Collections.Generic;
using System.Text;

namespace RemoteTrafficAggregator
{
    public class AppConfig
    {
        public bool EncryptFiles { get; set; }
        public bool TarNfdumpLogs { get; set; }
        public bool IncludeOriginalLineInOutput { get; set; }
        public bool IncludeTrafficMacAddresses { get; set; }
        public string EmailNotificationAddresses { get; set; }
        public string PathToGpg { get; set; }
        public string PathToTar { get; set; }
        public string GpgIdentityToEncryptTo { get; set; }
        public string GpgCommand { get; set; }

        public SmtpConfig Smtp { get; set;}

        public class SmtpConfig
        {
            public string FromAddress { get; set; }
            public string OutgoingServer { get; set; }
            public int Port { get; set; }

        }
    }
}
