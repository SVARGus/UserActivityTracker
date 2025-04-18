using System.Collections.Generic;

namespace UserActivityTracker
{
    public class AppConfiguration
    {
        public string ReportFilePath { get; set; }
        public bool EnableStatistics { get; set; }
        public bool EnableModeration { get; set; }
        public List<string> BannedWords { get; set; }
        public List<string> BannedApps { get; set; }
    }
}
