using V3_Shared;
using V3_Linode;

namespace V3_Firewall
{

    public class Firewall
    {
        public int Id { get; set; }
        public RulesContainer Rules { get; set; }
    }

    public class RulesContainer
    {
        public Rule[] Inbound { get; set; }
    }

    public class Rule
    {
        public string Label { get; set; }
        public Addresses Addresses { get; set; }
        public string Ports { get; set; }
    }

    public class Addresses
    {
        public List<string> Ipv4 { get; set; }
    }
    
    class V3_FirewallMasterClass
    {

        public V3_LinodeClass linApi;
        public V3_SharedClass v3Shared;
        public int delay = 2000;

        public V3_FirewallMasterClass(V3_SharedClass _shared, V3_LinodeClass _linApi)
        {
            this.v3Shared = _shared;
            this.linApi = _linApi;
            linApi.fwmc = this;
        }
        

        public static long GetTimestamp()
        {
            return DateTimeOffset.Now.ToUnixTimeSeconds();
        }

        /// <summary>
        ///   Worker that updates the firewall every x seconds
        /// </summary>
        /// <param name="doid"></param>
        /// <param name="linApi"></param>
        /// <returns></returns>
        public async Task StartWorker(int doid, V3_LinodeClass linApi)
        {
            try
            {
                while (v3Shared.firewalls_lastUpdated.ContainsKey(doid))
                {
                    Task.Delay(delay).Wait();
                    if (v3Shared.firewalls_needUpdate[doid])
                    {
                        Console.WriteLine($"__Worker [{doid}] updating...");
                        v3Shared.firewalls_needUpdate[doid] = false;
                        v3Shared.firewalls_lastUpdated[doid] = GetTimestamp();
                        linApi.UpdateFirewall(doid);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Worker [{doid}] error: "+ e.Message + " " + e.StackTrace);
            }
        }

        /// <summary>
        ///  Adds a firewall to the list of firewalls to update
        /// </summary>
        /// <param name="doid"></param>
        /// <param name="linApi"></param>
        /// <param name="tcpIps"></param>
        /// <param name="udpIps"></param>
        /// <param name="tempPorts"></param>
        public void Add(int doid, V3_LinodeClass linApi, List<string> tcpIps, List<string> udpIps, List<string> tempPorts)
        {
            Dictionary<string, List<string>> rules = new();
            if(tcpIps != null)
            {
                rules.Add("tcp", udpIps);
            }
            if(udpIps != null)
            {
                rules.Add("udp", tcpIps);
            }
            if(tempPorts != null)
            {
                rules.Add("temp", tempPorts);
            }
            v3Shared.firewalls_rules.Add(doid, rules);
            v3Shared.firewalls_needUpdate.Add(doid, false);
            v3Shared.firewalls_lastUpdated.Add(doid, GetTimestamp());

            Task.Run(() => StartWorker(doid, linApi));
        }

        /// <summary>
        ///  Updates the firewall rules
        /// </summary>
        /// <param name="doid"></param>
        /// <param name="tcpIps"></param>
        /// <param name="udpIps"></param>
        /// <param name="tempPorts"></param>
        public void Update(int doid, List<string> tcpIps, List<string> udpIps, List<string> tempPorts)
        {
            Dictionary<string, List<string>> rules = new();
            if (tcpIps != null)
            {
                rules.Add("tcp", tcpIps);
            }
            if (udpIps != null)
            {
                rules.Add("udp", udpIps);
            }
            if (tempPorts != null)
            {
                rules.Add("temp", tempPorts);
            }
            v3Shared.firewalls_rules[doid] = rules;
            v3Shared.firewalls_lastUpdated[doid] = GetTimestamp();
        }

        public string RemoveRule(int fwId, string ip, string type, int port = 0)
        {
            switch(type){
            case "tcp":
                if (!v3Shared.firewalls_rules[fwId]["tcp"].Contains(ip))
                    return "not_present_in_fw";
                v3Shared.firewalls_rules[fwId]["tcp"].Remove(ip);
                v3Shared.firewalls_needUpdate[fwId] = true;
                v3Shared.firewalls_lastUpdated[fwId] = GetTimestamp();
                return "success";
            break;
            
            case "udp":
                if (!v3Shared.firewalls_rules[fwId]["udp"].Contains(ip))
                    return "not_present_in_fw";
                v3Shared.firewalls_rules[fwId]["udp"].Remove(ip);
                v3Shared.firewalls_needUpdate[fwId] = true;
                v3Shared.firewalls_lastUpdated[fwId] = GetTimestamp();
                return "success";
            break;
            
            case "both":
                bool isUpdated = false;
                if (v3Shared.firewalls_rules[fwId]["tcp"].Contains(ip))
                {
                    v3Shared.firewalls_rules[fwId]["tcp"].Remove(ip);
                    isUpdated = true;
                }
                if (v3Shared.firewalls_rules[fwId]["udp"].Contains(ip))
                {
                    v3Shared.firewalls_rules[fwId]["udp"].Remove(ip);
                    isUpdated = true;
                }
                if (isUpdated)
                {
                    v3Shared.firewalls_needUpdate[fwId] = true;
                    v3Shared.firewalls_lastUpdated[fwId] = GetTimestamp();
                }
                return "success";
            break;
            
            case "temp":
                if (!v3Shared.firewalls_rules[fwId]["temp"].Contains(port.ToString()))
                    return "not_present_in_fw";
                v3Shared.firewalls_rules[fwId]["temp"].Remove(port.ToString());
                v3Shared.firewalls_needUpdate[fwId] = true;
                v3Shared.firewalls_lastUpdated[fwId] = GetTimestamp();
                return "success";
            break;

            default:
                return "__400";
            }
        }

        public string AddRule(int fwId, string ip, string type, int port = 0){
            switch (type){
                case "tcp":
                    if (v3Shared.firewalls_rules[fwId]["tcp"].Contains(ip))
                        return "present_in_fw";
                    v3Shared.firewalls_rules[fwId]["tcp"].Add(ip);
                    v3Shared.firewalls_needUpdate[fwId] = true;
                    v3Shared.firewalls_lastUpdated[fwId] = GetTimestamp();
                    return "success";
                break;

                case "udp":
                    if (v3Shared.firewalls_rules[fwId]["udp"].Contains(ip))
                        return "present_in_fw";
                    v3Shared.firewalls_rules[fwId]["udp"].Add(ip);
                    v3Shared.firewalls_needUpdate[fwId] = true;
                    v3Shared.firewalls_lastUpdated[fwId] = GetTimestamp();
                    return "success";
                break;

                case "both":
                    bool isUpdated = false;
                    if (!v3Shared.firewalls_rules[fwId]["tcp"].Contains(ip))
                    {
                        v3Shared.firewalls_rules[fwId]["tcp"].Add(ip);
                        isUpdated = true;
                    }
                    if (!v3Shared.firewalls_rules[fwId]["udp"].Contains(ip))
                    {
                        v3Shared.firewalls_rules[fwId]["udp"].Add(ip);
                        isUpdated = true;
                    }
                    if (isUpdated)
                    {
                        v3Shared.firewalls_needUpdate[fwId] = true;
                        v3Shared.firewalls_lastUpdated[fwId] = GetTimestamp();
                    }
                    return "success";
                break;

                case "temp":
                    if (v3Shared.firewalls_rules[fwId]["temp"].Contains(port.ToString()))
                        return "present_in_fw";
                    v3Shared.firewalls_rules[fwId]["temp"].Add(port.ToString());
                    v3Shared.firewalls_needUpdate[fwId] = true;
                    v3Shared.firewalls_lastUpdated[fwId] = GetTimestamp();
                    return "success";
                break;
                
                default:
                    return "__400";
                break;
            }
        }
    }
}
