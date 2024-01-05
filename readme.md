# Fuc (Firewall Unique Conveyor)
Designed for FiveM and Linode.

## Main objective
For my system ([PurpleMaze](https://purplemaze.net)), I needed to whitelist player IPs on the proxies they connect to. With my previous cloud provider (DigitalOcean), their API was really simple, with just a bunch of POST / DELETE. But now that my use case has been banned, I needed to rebuild my system on Linode.  
The main problem with Linode is that their API for Cloud Firewalls is different, requiring the rule set to be updated with every PUT request. My systems were not designed to work with this: With high traffic and multiple nodes, it would create synchronisation or performance issues. Rather than rewrite all my code, I preferred to create this software, allowing me to manipulate their API like DigitalOcean's.

## Disclaimer
This software wasn't created to be open-source, but I need to learn about it, and it helps me code in a better way. Although it's not a final version and I'm still working on it, the code doesn't follow all the standards and isn't really pretty, I hope you'll forgive me but I was in a hurry, it was ~~created~~ speedran in a day or two.  
  

**:warning: Additionnally, the software is currently untested, as I'm still working on it. Stuff can break**

## How does it works
The FUC is acting like a kind of middleware, keeping the ruleset in memory and sending it to Linode's API regularly.  
It will fetch all firewalls and associated rulset at startup.  
As soon as a request is received, the process is the following:
- Is the firewall existing in memory ?
    - Yes: Check the ruleset
    - No: Fetch it, add it and skip the next step
- Is the ruleset recent ? 
    - Yes: Nice, nothing to do
    - No: Fetch it from Linode
- Is the rule already in memory ?
    - Yes: Nice, nothing to do
    - No: Add it  

In the same time, as soon as a firewall is added, a 'Worker' is launched, checking every x milliseconds for a ruleset change, to push it.

## Concret usage
- Provide Linode API tokens in `tokens.json`. Depending on your traffic, multiple tokens can be helpful to avoid rate limits. (800 calls/min/token actually)
- Create API Keys in `keys.json`
- Provide System IPs : They will be allowed on all the ports (TCP only).
- Build the software: `build` (Windows) | `bash build.bat` (Linux/MacOS) (You'll need to install .NET SDK 6+ on your computer)
- Run it `./fuc [port]` (default port is 6001)
- Call it with the following requests (With the header `Key: <a_key_from_the_keys_file>`):
    - Init a firewall: `POST /firewall/:fwId` (**The firewall need to be created on Linode before this!**)
    - Delete a firewall: `DELETE /firewall/:fwId` (**It will only unload it's ruleset and worker, this will not delete the fw from Linode**)
    - Add a rule: `POST /rules/:fwId/<udp|tcp|both|temp>?ip=[ip]&port=[port]`
    - Delete a rule: `DELETE /rules/:fwId/<udp|tcp|both|temp>?ip=[ip]&port=[port]`

### Different rules types
- `udp`: Whitelist the IP address for UDP only (In the port range defined in V3_LinodeApi.cs, variable portRange)
- `tcp`: Whitelsit the IP address for TCP only (In the port range defined in V3_LinodeApi.cs, variable portRange)
- `both`: Whitelsit the IP address on UDP/TCP (in the port range defined in V3_LinodeApi.cs, variable portRange)
- `temp`: Open a port for TCP trafic, all addresses. (Useful when you don't know the IP address that will show up.)