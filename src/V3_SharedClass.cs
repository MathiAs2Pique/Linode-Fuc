namespace V3_Shared
{
    class V3_SharedClass
    {
        public List<string> shared_tokens = new List<string>();
        public List<string> shared_httpProxies = new List<string>();

        public Dictionary<int, Dictionary<string, List<string>>> firewalls_rules = new();
        public Dictionary<int, bool> firewalls_needUpdate = new();
        public Dictionary<int, long> firewalls_lastUpdated = new();
        public int delay = 1000;

    }
}
