using System.Net;
using System.Text;
using V3_Linode;
using V3_Shared;
using Newtonsoft.Json.Linq;
using V3_Firewall;

namespace V3_WebServer
{
    class V3_WebServerClass
    {
        private List<string> keys = new(); // Change this !
        public bool extensiveDebug = false;
        private List<int> fetching = new();
        private V3_LinodeClass linApi;
        private V3_SharedClass v3shared;
        private V3_FirewallMasterClass fwmc;
        public static List<string> supportedTypes = new() { "udp", "tcp", "both", "temp" };

        public V3_WebServerClass(V3_LinodeClass _linApi, V3_SharedClass _v3shared, V3_FirewallMasterClass _fwmc)
        {
            this.linApi = _linApi;
            this.v3shared = _v3shared;
            this.fwmc = _fwmc;
            InitKeys();
        }

        /// <summary>
        /// Read the keys from the keys.json file
        /// </summary>
        private void InitKeys()
        {
            string rawKeys = File.ReadAllText("keys.json");
            JArray jKeys = JArray.Parse(rawKeys);
            foreach (string key in keys)
            {
                this.keys.Add(key);
            }
        }

        /// <summary>
        ///  Get the current timestamp
        /// </summary>
        public static long GetTimestamp()
        {
            return DateTimeOffset.Now.ToUnixTimeSeconds();
        }

        /// <summary>
        /// Handle the rule removal
        /// </summary>
        ///  Example of request : POST /rules/:fwId/:type
        ///  type can be udp, tcp, both, temp
        ///  Query string: port, ip
        public async Task<string> ProcessRequest(HttpListenerRequest request, V3_SharedClass v3shared, V3_LinodeClass linApi)
        {
            try
            {
                // Get the request IP
                string reqIp = "";
                if (request.Headers.AllKeys.Contains("X-Forwarded-For"))
                    reqIp = request.Headers.Get("X-Forwarded-For");
                else if (request.Headers.AllKeys.Contains("cf-connecting-ip"))
                    reqIp = request.Headers.Get("cf-connecting-ip");
                else
                    reqIp = request.RemoteEndPoint.Address.ToString();

                // Check if the key is present and valid
                if ((request.Headers.AllKeys.Contains("key") && keys.Contains(request.Headers.Get("key"))) || (request.Headers.AllKeys.Contains("Key") && keys.Contains(request.Headers.Get("Key"))))
                {
                    Console.WriteLine($"{reqIp} Missing Key header / Wrong key.");
                    return "__403";
                }

                // Logging
                Console.WriteLine($"{request.HttpMethod} {request.Url.AbsolutePath} - {reqIp}");

                // Basic return to check if the server is alive / cache isn't enabled
                if (request.Url.AbsolutePath == "/alive")
                {
                    return (GetTimestamp() % 60).ToString();
                }

                if (request.Url.AbsolutePath.StartsWith("/firewall"))
                {
                    int fwId = 0;
                    try
                    {
                        fwId = int.Parse(request.Url.AbsolutePath.Split("/")[2]);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Error parsing firewall id: " + e.Message + " " + e.StackTrace);
                        return "__400";
                    }
                    if (request.HttpMethod == "POST")
                    {
                        // Firewall creation
                        linApi.FetchFirewall(fwId);
                        return "fw_created";
                    }
                    else if (request.HttpMethod == "DELETE")
                    {
                        // Firewall deletion
                        v3shared.firewalls_rules.Remove(fwId);
                        v3shared.firewalls_needUpdate.Remove(fwId);
                        v3shared.firewalls_lastUpdated.Remove(fwId);
                        return "fw_deleted";
                    }
                }
                else if (request.Url.AbsolutePath.StartsWith("/rules"))
                {
                    // Extract important data
                    string[] path = request.Url.AbsolutePath.Split("/");
                    string type = path[3];
                    string opIp = "";
                    int opPort = -1;
                    // Type
                    if(!supportedTypes.Contains(type))
                    {
                        Console.WriteLine("Unsupported type: " + type);
                        return "__400";
                    }
                    // Firewall id
                    int fwId = 0;
                    try
                    {
                        fwId = int.Parse(request.Url.AbsolutePath.Split("/")[2]);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Error parsing firewall id: " + e.Message + " " + e.StackTrace);
                        return "__400";
                    }
                    // Port
                    if (request.QueryString.AllKeys.Contains("port"))
                    {
                        if(int.TryParse(request.QueryString.Get("port"), out opPort))
                        {
                            if(opPort < 0 || opPort > 65535){
                                Console.WriteLine("Invalid port: " + opPort);
                                return "__400";
                            }
                        }
                        else{
                            Console.WriteLine("Invalid port: " + opPort);
                            return "__400";
                        }
                    }
                    else if(type == "temp")
                    {
                        Console.WriteLine("Missing port");
                        return "__400";
                    }
                    // IP
                    if (request.QueryString.AllKeys.Contains("ip"))
                    {
                        opIp = request.QueryString.Get("ip");
                    }
                    else if (type != "temp")
                    {
                        Console.WriteLine("Missing ip");
                        return "__400";
                    }
                    

                    if (request.HttpMethod == "POST")
                    {
                        // rule addition
                        fwmc.AddRule(fwId, opIp, type, opPort);

                    }
                    else if (request.HttpMethod == "DELETE")
                    {
                        // rule deletion
                        fwmc.RemoveRule(fwId, opIp, type, opPort);
                        
                    }
                }

                return "__404";
            }
            catch (Exception e)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("HTTP Error :\n-" + e.Message + "-\n" + e.StackTrace);
                Console.ForegroundColor = ConsoleColor.White;
                return "{\"error\":\"\n🧨 Internal error: Unable to handle your request.\"}";
            }
        }


        async Task HandleClient(HttpListenerContext context, V3_SharedClass v3shared, V3_LinodeClass linApi)
        {
            HttpListenerRequest request = context.Request;
            HttpListenerResponse response = context.Response;

            // Print out some info about the request
            if(extensiveDebug)
                Console.WriteLine(request.HttpMethod + " " + request.Url.AbsolutePath);
            // Get the response string
            string responseString = await ProcessRequest(request, v3shared, linApi);
            if (responseString == "__404")
            {
                response.StatusCode = 404;
                response.Close();
            }
            else if (responseString == "__403")
            {
                response.StatusCode = 403;
                response.Close();
            }
            else if (responseString == "__400")
            {
                response.StatusCode = 400;
                response.Close();
            }
            else if (responseString == "__500")
            {
                response.StatusCode = 500;
                response.Close();
            }
            else
            {
                // Write the response info
                byte[] buffer = Encoding.UTF8.GetBytes(responseString);
                // Get a response stream and write the response to it.
                response.StatusCode = 200;
                response.ContentLength64 = buffer.Length;
                response.ContentType = "text/plain";
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                // You must close the output stream.
                if (extensiveDebug) Console.WriteLine("  Reponse: " + responseString + "\n");
                response.Close();
            }
        }

        public async Task startWebServer(int port, V3_SharedClass shared, V3_LinodeClass linApi)
        {
            HttpListener listener = new HttpListener();
            string url = $"http://+:{port}/";
            listener.Prefixes.Add(url);
            listener.Start();

            Console.WriteLine($"# Starting HTTP server. (port {port})");

            while (true)
            {
                HttpListenerContext context = await listener.GetContextAsync();
                Task.Run(() => HandleClient(context, shared, linApi)).Wait();
            }
        }


    }
}
