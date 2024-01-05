using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Net;
using V3_Shared;
using V3_Firewall;

namespace V3_Linode
{

    class V3_LinodeClass
    {

        public string linApiUrl = "https://api.linode.com/v4";
        public V3_SharedClass shared = new();
        public V3_FirewallMasterClass ?fwmc;
        private List<string> apiTokens = new();
        readonly string portRange = "0-2000";
        string systemIPs = "";

        public V3_LinodeClass(V3_SharedClass _shared){
            this.shared = _shared;
            InitTokens();
            InitSystemIPs();
        }

        /// <summary>
        /// Read the tokens from the file and store them in the list.
        /// </summary>        
        private void InitTokens()
        {
            string rawTokens = File.ReadAllText("tokens.json");
            JArray jTokens = JArray.Parse(rawTokens);
            List<string> tokens = new ();

            foreach (var token in jTokens)
            {
                tokens.Add(token.ToString());
            }

            if(tokens.Count == 0)
            {
                throw new Exception("No tokens found in tokens.json");
            }

            apiTokens = tokens;
        }

        /// <summary>
        /// Read the system IPs from the file and store them in the string.
        /// </summary>
        private void InitSystemIPs()
        {
            string rawIps = File.ReadAllText("systemIPs.json");
            JArray jIps = JArray.Parse(rawIps);
            if(jIps.Count == 0)
            {
                throw new Exception("No IPs found in systemIPs.json");
            }

            foreach(var ip in jIps)
            {
                systemIPs += $"\"{ip}\",";
            }
            systemIPs = systemIPs.Remove(systemIPs.Length - 1);
        }

        /// <summary>
        /// Get a random token from the list.
        /// </summary>
        private string GetToken()
        {
            return apiTokens[new Random().Next(0, apiTokens.Count - 1)];
        }

        /// <summary>
        /// Make a request to the Linode API.
        /// </summary>
        /// <param name="url">The url to request.</param>
        /// <param name="method">The method to use.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>The response.</returns>
        public async Task<string> LinRequest(string url, string method, string data = null)
        {
            string resp = "__placeholder";
            bool isRequestFailed = true;
            string respE = "__placeholder"; // Error response
            int respEC = 0; // Error response code

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = method;

            request.ContentType = "application/json";

            string auth = GetToken();
            request.Headers["Authorization"] = "Bearer " + auth;

            if (data != null)
            {
                byte[] postData = System.Text.Encoding.UTF8.GetBytes(data);
                request.ContentLength = postData.Length;

                using (Stream stream = await request.GetRequestStreamAsync())
                {
                    await stream.WriteAsync(postData, 0, postData.Length);
                }
            }

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)await request.GetResponseAsync())
                {
                    using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                    {
                        resp = await reader.ReadToEndAsync();
                        isRequestFailed = false;
                    }
                }
            }
            catch (WebException ex)
            {
                try
                {
                    using (HttpWebResponse response = (HttpWebResponse)ex.Response)
                    {
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            respE = await reader.ReadToEndAsync();
                            isRequestFailed = true;

                            // Get http response code
                            respEC = (int)response.StatusCode;
                        }
                    }
                    Console.WriteLine(ex.Message);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[!] linRequest unhandled error: {e.Message}");
                }
            }

            if (isRequestFailed)
            {
                // Error! Throw exception
                throw new Exception($"Request failed: {respE} ({respEC})    (url: {url}, post: \"{data}\")");
            }

            return resp;

        }

        public string GetFirewalls()
        {
            return LinRequest(linApiUrl + "/networking/firewalls", "GET").Result;
        }

        /// <summary>
        ///  Get all the firewalls and add them to the shared class.
        /// </summary>
        public void InitFirewalls()
        {
            string resp = GetFirewalls();
            List<Firewall> firewalls = JsonConvert.DeserializeObject<List<Firewall>>(JObject.Parse(resp)["data"].ToString());

            foreach (var fw in firewalls)
            {
                List<string> udpIps = new();
                List<string> tcpIps = new();
                List<string> tempPorts = new();

                foreach (var rule in fw.Rules.Inbound)
                {
                    switch (rule.Label)
                    {
                        case "TCP":
                            foreach (var ip in rule.Addresses.Ipv4)
                            {
                                tcpIps.Add(ip.Replace("/32", ""));
                            }
                            break;
                        case "UDP":
                            foreach (var ip in rule.Addresses.Ipv4)
                            {
                                udpIps.Add(ip.Replace("/32", ""));
                            }
                            break;
                        case "TEMP":
                                tempPorts.Add(rule.Ports);
                            break;
                    }
                }
                
                // Add firewall
                fwmc.Add(fw.Id, this, tcpIps, udpIps, tempPorts);
            }
        }

        /// <summary>
        ///  Fetch the firewall and add it to the shared class.
        /// </summary>
        /// <param name="fwId">Firewall's ID</param>
        public void FetchFirewall(int fwId)
        {
            string resp = LinRequest(linApiUrl + "/networking/firewalls/" + fwId, "GET").Result;

            Firewall fw = JsonConvert.DeserializeObject<Firewall>(JObject.Parse(resp).ToString());

            List<string> udpIps = new();
            List<string> tcpIps = new();
            List<string> tempPorts = new();

            foreach (var rule in fw.Rules.Inbound)
            {
                switch (rule.Label)
                {
                    case "TCP":
                        foreach (var ip in rule.Addresses.Ipv4)
                        {
                            tcpIps.Add(ip.Replace("/32", ""));
                        }
                        break;
                    case "UDP":
                        foreach (var ip in rule.Addresses.Ipv4)
                        {
                            udpIps.Add(ip.Replace("/32", ""));
                        }
                        break;
                    case "TEMP":
                        tempPorts.Add(rule.Ports);
                        break;
                }
            }

            // Add firewall
            if(shared.firewalls_lastUpdated.ContainsKey(fwId))
            {
                fwmc.Update(fwId, tcpIps, udpIps, tempPorts);
            }
            else
            {
                fwmc.Add(fwId, this, tcpIps, udpIps, tempPorts);
            }
        }

        /// <summary>
        /// Update the firewall with the new rules.
        /// </summary>
        /// <param name="doid"></param>
        public void UpdateFirewall(int doid)
        {
            List<string> tempPorts = shared.firewalls_rules[doid]["temp"];
            List<string> udpIps = shared.firewalls_rules[doid]["udp"];
            List<string> tcpIps = shared.firewalls_rules[doid]["tcp"];

            string tcpIps_str = "";
            string udpIps_str = "";

            // Format tcpIp_str
            foreach (string ip in tcpIps)
            {
                tcpIps_str += $"\"{ip}/32\",";
            }
            if(tcpIps_str != "")
                tcpIps_str = tcpIps_str.Remove(tcpIps_str.Length - 1);

            // Format udpIp_str
            foreach (string ip in udpIps)
            {
                udpIps_str += $"\"{ip}/32\",";
            }
            if(udpIps_str != "")
                udpIps_str = udpIps_str.Remove(udpIps_str.Length - 1);

            // null ? 
            if(tcpIps_str == "")
            {
                tcpIps_str = "\"1.1.1.1/32\"";
            }
            if (udpIps_str == "")
            {
                udpIps_str = "\"1.1.1.1/32\"";
            }

            string tempPorts_str = "";
            foreach (string port in tempPorts)
            {
                tempPorts_str += $"{{\"protocol\": \"TCP\",\"ports\": \"{port}\",\"addresses\":{{\"ipv4\": [\"0.0.0.0/0\"]}},\"action\": \"ACCEPT\",\"label\": \"TEMP\",\"description\": \"Temp TCP\"}},";
            }
            if(tempPorts_str != "")
                tempPorts_str = ","+tempPorts_str.Remove(tempPorts_str.Length - 1);

            // Format the json : first, udp, tcp, temp, system
            string commonJson = $"\"inbound\": [" +
                $"{{\"protocol\": \"TCP\",\"ports\": \"{portRange}\",\"addresses\":{{\"ipv4\": [{tcpIps_str}]}},\"action\": \"ACCEPT\",\"label\": \"TCP\",\"description\": \"Main TCP\"}}," +
                $"{{\"protocol\": \"UDP\",\"ports\": \"{portRange}\",\"addresses\":{{\"ipv4\": [{udpIps_str}]}},\"action\": \"ACCEPT\",\"label\": \"UDP\",\"description\": \"Main UDP\"}}," +
                $"{{\"protocol\": \"TCP\",\"ports\": \"1-65535\",\"addresses\":{{\"ipv4\": [{systemIPs}]}},\"action\": \"ACCEPT\",\"label\": \"SYSTEM\",\"description\": \"System TCP\"}}" +
                tempPorts_str +
                $"]";

            string data = "{" +
                $"\"inbound_policy\": \"DROP\"," +
                $"{commonJson}," +
                $"\"outbound_policy\":\"ACCEPT\"" + 
                "}";

            LinRequest(linApiUrl + "/networking/firewalls/" + doid + "/rules", "PUT", data).Wait();
        }
    }
}