# Building a SOC + Honeynet in Azure (Live Traffic)
![Cloud Honeynet / SOC](https://i.imgur.com/ZWxe03e.jpg)

## Introduction

In this project, I build a mini honeynet in Azure and ingest log sources from various resources into a Log Analytics workspace, which is then used by Microsoft Sentinel to build attack maps, trigger alerts, and create incidents. I measured some security metrics in the insecure environment for 24 hours, apply some security controls to harden the environment, measure metrics for another 24 hours, then show the results below. The metrics we will show are:

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)



## Architecture Before Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/aBDwnKb.jpg)

## Architecture After Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/YQNa9Pp.jpg)

The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel

For the "BEFORE" metrics, all resources were originally deployed, exposed to the internet. The Virtual Machines had both their Network Security Groups and built-in firewalls wide open, and all other resources are deployed with public endpoints visible to the Internet; aka, no use for Private Endpoints.

For the "AFTER" metrics, Network Security Groups were hardened by blocking ALL traffic with the exception of my admin workstation, and all other resources were protected by their built-in firewalls as well as Private Endpoint

Let's start by configuring the resources we will need for our Honeynet

## Step 1: Configuring our Honeynet Resources
### 1. Create a Resource Group
```Bash
az group create --name Honeynet-RG --location eastus
```

### 2. Create a Virtual Network and Subnet
```Bash
az network vnet create \
  --resource-group Honeynet-RG \
  --name Honeynet-VNet \
  --address-prefix 10.0.0.0/16 \
  --subnet-name Honeynet-Subnet \
  --subnet-prefix 10.0.0.0/24
```

### 3. Create a Public IP Address
```Bash
az network public-ip create \
  --resource-group Honeynet-RG \
  --name Honeynet-PublicIP
```

### 4. Create a Network Security Group (NSG) to Allow all Inbound Traffic via the Internet

We are creating this NSG to allow all inbound traffic to our Virtual Machines, making our Honeynet environment enticing to attackers/hackers. not to worry will be replaced with a hardened NSG later on in our project.

#### 4.1. Create NSG Instance
```Bash
az network nsg create \
  --resource-group Honeynet-RG \
  --name Honeynet-NSG
```
#### 4.2. Create NSG Rule to Allow All Inbound Traffic
```Bash
az network nsg rule create \
  --resource-group Honeynet-RG \
  --nsg-name Honeynet-NSG \
  --name DANGER_AllowAnyInbound \
  --priority 100 \
  --direction Inbound \
  --access Allow \
  --protocol ‘*’ \
  --source-address-prefix ‘*’ \
  --source-port-range ‘*’ \
  --destination-address-prefix ‘*’ \
  --destination-port-range ‘*’
```

### 5. Configure the Windows Virtual Machine

#### 5.1. Create Windows VM
Here, we use a Windows 10 image for the VM.
```Bash
az vm create \
  --resource-group Honeynet-RG \
  --name Windows-VM \
  --vnet-name Honeynet-VNet \
  --subnet Honeynet-Subnet \
  --image MicrosoftWindowsDesktop:Windows-10:win10-21h2-pro:latest \
  --admin-username <username> \
  --admin-password <password>
```

#### 5.2. Identify the NIC Associated with the Windows VM

We will need to know the VM's Network Interface Card (NIC) in order to associate the Open Honeynet NSG to the VM
```Bash
az vm show \
  --resource-group Honeynet-RG \
  --name Windows-VM \
  --query “networkProfile.networkInterfaces[0].id” \
  --output tsv
```

#### 5.3. Apply the NSG to the NIC

Use the az network nic update command to associate the NSG with the Windows NIC
```Bash
az network nic update \
  --resource-group Honeynet-RG \
  --name <WindowsVMNIC> \
  --network-security-group Honeynet-NSG
```
**Parameters:**  
  --name: Replace <**WindowsVMNIC**> with the name of the VM's NIC you discovered earlier
  
### 6. Configure Linux Virtual Machine

#### 6.1.	Create Linux VM

Here, we use an Ubuntu Linux image for the VM
```Bash
az vm create \
  --resource-group Honeynet-RG \
  --name Linux-VM \
  --vnet-name Honeynet-VNet \
  --subnet Honeynet-Subnet \
  --image UbuntuLTS \
  --size Standard_E2bs_v5 \
  --authentication-type password \
  --admin-username <username> \
  --admin-password <password> \
```

#### 6.2. Identify the NIC Associated with the Linux VM
```Bash
az vm show \
  --resource-group Honeynet-RG \
  --name Linux-VM \
  --query “networkProfile.networkInterfaces[0].id” \
  --output tsv
```

#### 6.3. Apply the NSG to the NIC

Use the az network nic update command to associate the NSG with the Linux NIC
```Bash
az network nic update \
  --resource-group Honeynet-RG \
  --name <LinuxVMNIC> \
  --network-security-group Honeynet-NSG
 ``` 
**Parameters:**  
  --name: Replace <**LinuxVMNIC**> with the name of the VM's NIC you discovered earlier
  

### 7. Configure the SQL Server within the Windows VM

#### 7.1. Connect to the VM
Identify the Windows VM's Public IP address using the following command:
```Bash
az vm list-ip-addresses
  --name Windows-VM \
  --resource-group Honeynet-RG \
  --query "[].virtualMachine.network.publicIp.Addresses[].ipAddress" \
  --output tsv
```

Use Remote Desktop Protocol (RDP) to connect to the VM:
```batch
mstsc /v:<Windows VM-Public-IP-Address>
```
![RDP](https://github.com/user-attachments/assets/d4d58475-0fb3-436e-a716-65a7df290fda)

Log in with the admin username and password you set earlier.


#### 7.2. Turn Off Windows Defender Firewall

In order for our Windows VM to be discoverable over the internet, we have to disable the Windows Defender Firewall within the VM

Once inside the VM:

•	Turn off the Windows firewall (this will allow the VM to respond to ping requests and make it more discoverable on the internet to bad actors/attackers)
-	Type in “wf.msc” in the start menu
-	Go to “Windows Defender Firewall Properties” and turn off the Firewall states on the Domain, Private and Public Profile tabs

![Turn off Windows Firewall (1)](https://github.com/user-attachments/assets/80491864-d45d-4330-bc44-a2d63be61ea6)

![Turn off Windows Firewall (2)](https://github.com/user-attachments/assets/3a8e81df-4c3d-4576-8295-e5343c9e017d)

#### 7.3. Set up SQL Server

a) Install SQL Server Evaluation  <https://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2019>

This can be downloaded online as an .exe file 

Follow the installation steps provided:

-	Feature Selection:	Database Engine Services
-	Instance ID:	**MSSQLSERVER** (Default)
-	Server Config:	(Default)
-	Authen Mode:	**Mixed Mode**
-	Username:		**sa** (Default System Admin)
-	Password:		<**Password**>
-	Specify SQL Admin: **Add Current User**

b) Install SSMS (SQL Server Management Studio): <https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms>

c) Enable logging for SQL Server to be ported into Windows Event Viewer
-	Link to step-by-step process available here: <https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/write-sql-server-audit-events-to-the-security-log?view=sql-server-ver16> 

-	Provide full permission for the SQL Server service account to the registry hive:

 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security**

 ![Set up SQL server within windows VM](https://github.com/user-attachments/assets/3799d599-740d-46f5-9c66-159e5bb41b93)

-	Right click “Security”, Select “Permissions”
-	Click “Add”
-	Enter “NETWORK SERVICES” and click OK
-	Allow “Full Control” and Click Apply

d) Open a command prompt with administrative permissions.

- From the Start menu, navigate to Command Prompt, and then select Run as administrator.
- If the User Account Control dialog box opens, select Continue.

e) Execute the following statement to enable auditing from SQL Server.
```Powershell
auditpol /set /subcategory:"application generated" /success:enable /failure:enable
```

f) Close the command prompt window.

g) Open SQL Server Management Studio (SSMS).
-	Login using the System Admin (sa) credentials you set up earlier
-	Once connected, right-click on the SQL Server (in the Object Explorer Box on the left-hand side)
-	Click “Properties” > “Security” 
-	On “Login Auditing”, check “both failed and successful logins” and click OK
-	Right click the SQL Server and click “Restart”

### 8. Configure a Storage Account

Here’s the command to create a storage account:
```Bash
az storage account create \
    --name Honeynet-Storage \
    --resource-group Honeynet-RG \
    --location eastus \
    --sku Standard_LRS \
    --kind StorageV2
```

**Parameters:**  
--name: A globally unique name for the storage account (3-24 characters, alphanumeric, no special characters).  
--resource-group: The name of the resource group where the storage account will be created.  
--location: The Azure region (e.g., eastus, westus).  
--sku: The pricing tier (e.g., Standard_LRS, Standard_GRS, Premium_LRS).  
--kind: The type of storage account (e.g., StorageV2, Storage, BlobStorage).  

### 9. Configure a Key Vault

Here's the command to create a Key Vault
```Bash
az keyvault create \
    --name Honeynet-KeyVault \
    --resource-group Honeynet-RG \
    --location eastus \
    --sku standard \
    --enabled-for-deployment true \
    --enabled-for-template-deployment true \
    --enabled-for-disk-encryption true \
    --enable-rbac-authorization false
```

**Parameters Explained:**  
--name: Specifies the name of the Key Vault (must be globally unique).  
--resource-group: The name of the resource group where the Key Vault will be created.  
--location: The Azure region where the Key Vault will be created (e.g., eastus, westeurope).  
--sku: Specifies the pricing tier of the Key Vault. Options are standard or premium.  
--enabled-for-deployment true: Allows Azure virtual machines to retrieve certificates from the Key Vault.  
--enabled-for-template-deployment true: Allows Azure Resource Manager templates to access the Key Vault.  
--enabled-for-disk-encryption true: Enables Azure Disk Encryption to retrieve secrets from the Key Vault.  
--enable-rbac-authorization false: Configures the Key Vault to use the Vault access policy permission model instead of Role-Based Access Control (RBAC).  

Next, we will need to ensure that all the Logs and metrics from are ingested and flow through to our Logs Analytics Workspace. This will later be used by Windows Sentinel to build attack maps, trigger alerts, and create incidents.

## Step 2: Logging and Monitoring

### 1. Create a Log Analytics Workspace

```Bash
az monitor log-analytics workspace create \
  --resource-group "Honeynet-RG" \
  --workspace-name "Honeynet-LAW" \
  --location "eastus"
```

**Parameters:**  
--resource-group: The resource group where the workspace will reside.  
--workspace-name: Name of the Log Analytics workspace.  
--location: Azure region where the workspace will be created.  

### 2. Enable Microsoft Sentinel

Enable Microsoft Sentinel on the created Log Analytics workspace:
```Bash
az sentinel create \
  --resource-group "Honeynet-RG" \
  --workspace-name "Honeynet-LAW"
```

**Parameters:**  
--resource-group: The resource group containing the Log Analytics workspace.  
--workspace-name: Name of the workspace on which to enable Microsoft Sentinel.  

### 3. Create the Watchlist

To create a watchlist in Microsoft Sentinel, use the az sentinel watchlist create command and include the --file parameter to upload your .csv file:
```Bash
az sentinel watchlist create \
  --resource-group "Honeynet-RG" \
  --workspace-name "Honeynet-LAW" \
  --watchlist-name "geoip" \
  --alias "geoip" \
  --description "List of Geo IP addresses used map events/alerts" \
  --file "./geoip-summarized.csv" \
  --items-search-key "network"
```

**Parameters:**  
--resource-group: The name of the resource group.  
--workspace-name: The name of the Log Analytics workspace associated with Microsoft Sentinel.  
--watchlist-name: A unique name for the watchlist.  
--alias: An optional,  unique identifier for the watchlist.  
--description: A brief description of the watchlist’s purpose.  
--file: Path to the .csv file containing the watchlist data.  
--items-search-key: The key column name in your CSV that will be used to query the watchlist (e.g., network in this case).  

### 4. Enable Microsoft Defender for Cloud

Microsoft Defender for Cloud is a comprehensive security solution that helps organizations protect their cloud workloads across Azure, AWS, and Google Cloud environments. It offers capabilities like security posture management, threat protection, vulnerability management, and compliance monitoring. By continuously assessing risks and providing real-time alerts, Defender for Cloud helps detect threats early, automate security management, and ensure compliance with industry standards. It also integrates with other Microsoft security products, offering a unified approach to defending critical assets like virtual machines, SQL databases, storage accounts, and Key Vaults. This reduces the attack surface, improves security posture, and enhances overall cloud security.

#### 4.1. Enable Microsoft Defender for Cloud Plans

Use the following commands to enable Defender for Cloud plans for VMs, SQL Servers, Storage Accounts, and Key Vault at the subscription level.

Commands to Enable Defender for Resources:
```Bash
# Enable Defender for Virtual Machines
az security pricing create --name VirtualMachines --tier Standard

# Enable Defender for SQL Servers
az security pricing create --name SqlServers --tier Standard

# Enable Defender for Storage Accounts
az security pricing create --name StorageAccounts --tier Standard

# Enable Defender for Key Vaults
az security pricing create --name KeyVaults --tier Standard
```

**Parameters:**  

--name: The Defender Plan to Enable (VirtualMachines, SqlServers, StorageAccounts, KeyVaults)  
--tier: The tier of the Defender plan. Set to standard to enable the full set of features for that resource  


#### 4.2. Enable Windows Defender for Cloud for Log Analytics Workspace

Defender for Cloud integrates with Log Analytics Workspace to store and analyze logs, alerts, and security data. Use the following command to enable Defender for the workspace:

Command to Enable Defender for Log Analytics Workspace:
```Bash
az security setting update \
  --name MCAS \
  --value Enabled \
  --workspace-id "/subscriptions/<subscription-id>/resourceGroups/Honeynet-RG/providers/Microsoft.OperationalInsights/workspaces/Honeynet-LAW"
```

**Parameters:**  

--name: The setting to enable (e.g. MCAS for Defender integration with the workspace)  
--value: Set to Enabled to activate Defender for Cloud integration  
--workspace-id: The full resource ID of the Log Analytics Workspace  

You can retrieve this ID with:
```Bash
az monitor log-analytics workspace show \
  --resource-group Honeynet-RG \
  --workspace-name Honeynet-LAW \
  --query id -o tsv
```

#### 4.3. Configure Continuous Export

Continuous Export sends data from Microsoft Defender for Cloud to a destination like Log Analytics Workspace, Event Hub, or Storage Account.

The command to Enable Continuous Export to Log Analytics Workspace:
```Bash
az security setting update \
  --name ContinuousExport \
  --workspace-id "/subscriptions/<subscription-id>/resourceGroups/Honeynet-RG/providers/Microsoft.OperationalInsights/workspaces/Honeynet-LAW" \
  --value Enabled
```

**Parameters:**  
--name: The name of the Setting (ContinuousExport)  
--workspace-id: The full resource ID of the Log Analytics Workspace  

#### 4.4. Ensure Collection of All Windows Security Events

To ensure that all Windows security events are collected (including all events in your VMs), we will need to configure Data Collection Rules (DCR) and set them to collect Windows security events.

Command to Create and Configure Data Collection Rule:
```Bash
az monitor data-collection rule create \
  --resource-group <resource-group-name> \
  --rule-name "AllWindowsSecurityEvents" \
  --data-sources "WindowsSecurity" \
  --destination "/subscriptions/<subscription-id>/resourceGroups/Honeynet-RG/providers/Microsoft.OperationalInsights/workspaces/Honeynet-LAW"
```

#### 4.5. Verify the Configuration

After configuring the Microsoft Defender for Cloud settings, you can verify the settings as follows:

Verify Defender Plan Settings:
```Bash
az security pricing list --output table
```
Verify Continuous Export Settings:
```Bash
az security setting list --output table
```
Verify Data Collection Rule (DCR):
```Bash
az monitor data-collection rule list --output table
```

### 5. Enable Log Collection from Virtual Machines (VMs) and Network Security Groups (NSGs)

These are the Logs we will collect the following sources:

- Window Event Logs (windows-vm)
- syslog (linux-vm)
- Flow Logs (NSGs)

#### Steps to Enable NSG Flow Logs

#### 5.1. Enable Network Watcher

Ensure Network Watcher is enabled in the region where your NSG resides:
```Bash
az network watcher configure \
    --locations eastus \
    --resource-group Honeynet-RG \
    --enabled true
```
#### 5.2. Enable NSG Flow Logs

Run the following command to enable flow logs for VM NSGs:

**WINDOWS VM NSG** (NSG **NOT** currently enabled, Generated on VM Creation, will use during VM Hardening)
```Bash
az network watcher flow-log create \
    --location eastus \
    --name Windows-FlowLog \
    --nsg Windows-nsg \
    --resource-group Honeynet-RG \
    --storage-account Honeynet-Storage \
    --enabled true
```

**LINUX VM NSG** (NSG **NOT** currently enabled, Generated on VM Creation, will use during VM Hardening)
```Bash
az network watcher flow-log create \
    --location eastus \
    --name Linux-FlowLog \
    --nsg Linux-nsg \
    --resource-group Honeynet-RG \
    --storage-account Honeynet-Storage \
    --enabled true
```

**Honeynet NSG** (NSG currently enabled, associated to both Windows & Linux NICs, created to open VM's to the Internet)
```Bash
az network watcher flow-log create \
    --location eastus \
    --name Honeynet-FlowLog \
    --nsg Honeynet-NSG \
    --resource-group Honeynet-RG \
    --storage-account Honeynet-Storage \
    --enabled true
```

**Parameters:**  

--location: The region where the NSG and Network Watcher are located.  
--name: A name for the flow log.  
--nsg: The name of the NSG for which you want to enable flow logs.  
--resource-group: The resource group containing the NSG and storage account.  
--storage-account: The name of the storage account where logs will be stored.  



#### 5.3. Enable Traffic Analytics

To enable traffic analytics for additional insights:

**WINDOWS VM FLOW LOG**
```Bash
az network watcher flow-log update \
    --location eastus \
    --name Windows-FlowLog \
    --nsg Windows-nsg \
    --resource-group Honeynet-RG\
    --traffic-analytics \
    --workspace <log-analytics-workspace-id> \
    --enabled true
```

**LINUX VM FLOW LOG**
```Bash
az network watcher flow-log update \
    --location eastus \
    --name Linux-FlowLog \
    --nsg Linux-nsg \
    --resource-group Honeynet-RG \
    --traffic-analytics \
    --workspace <log-analytics-workspace-id> \
    --enabled true
```

**HONEYNET FLOW LOG**
```Bash
az network watcher flow-log update \
    --location eastus \
    --name Honeynet-FlowLog \
    --nsg Honeynet-NSG \
    --resource-group Honeynet-RG \
    --traffic-analytics \
    --workspace <log-analytics-workspace-id> \
    --enabled true
```

• <**log-analytics-workspace-id**>: The ID of your Log Analytics workspace (can be retrieved using az monitor log-analytics workspace list).

****Note: You can retrieve the ID of any resource in azure using the following command:**
```Bash
az vm show \
    --name <resource-name> \
    --resource-group Honeynet-RG \
    --query “id” \
    --output tsv
```

**Parameters:**  
--name: Name of the Resource.  
--resource-group: Name of the Resource Group.  
--query “id”: Filters the output to return only the Resource ID  
--output tsv: Outputs the ID as plain text  


#### 5.4 Steps to Configure Data Collection Rules (DCRs)

a) Install AMA for Windows VM
```Bash
az vm extension set \
    --publisher Microsoft.Azure.Monitor \
    --name WindowsAMA \
    --vm-name windows-vm \
    --resource-group Honeynet-RG \
    --location eastus
```

b) Install AMA for Linux VM
```Bash
az vm extension set \
    --publisher Microsoft.Azure.Monitor \
    --name LinuxAMA \
    --vm-name linux-vm \
    --resource-group Honeynet-RG \
    --location eastus
```

**Parameters:**  
--publisher: Specifies the publisher of the VM extension (For AMA, the publisher is “Microsoft.Azure.Monitor”)  
--vm-name: Name of the VM.  
--vm-name: Name of the VM.  
--resource-group: Name of the resource group containing the VM.  
--location: The Azure region of the VM.  

c) Verify AMA Installation

To verify the installation of the AMA extension:
```Bash
az vm extension list \
    --vm-name <vm-name> \
    --resource-group Honeynet-RG \
    --output table
```

d) Create a Data Collection Rule for Windows VM

Run the following command to create a DCR for Windows Security Events, with all event logs enabled.
```Bash
az monitor data-collection rule create \
    --resource-group Honeynet-RG \
    --name Windows-dcr \
    --location eastus \
    --data-flows '[{"streams": ["Microsoft-SecurityEvent"], "destinations": ["ContentHub"]}]' \
    --destinations '[{"name": "ContentHub", "resourceId": "<log-analytics-workspace-id>"}]' \
    --data-sources '[{"stream": "Microsoft-SecurityEvent", "eventLog": {"xPathQueries": ["*"]}}]'
```

e) Create a Data Collection Rule for Linux VM

Run the following command to create a DCR for Linux VMs to collect syslog auth debug data.
```Bash
az monitor data-collection rule create \
    --resource-group Honeynet-RG \
    --name Linux-dcr \
    --location eastus \
    --data-flows '[{"streams": ["Syslog"], "destinations": ["ContentHub"]}]' \
    --destinations '[{"name": "ContentHub", "resourceId": "<log-analytics-workspace-id>"}]' \
    --data-sources '[{"stream": "Syslog", "syslog": {"facilityNames": ["auth"], "logLevels": ["debug"]}}]'
```

**Parameters:**  
--resource-group: The name of the resource group.  
--name: A name for the Data Collection Rule (e.g., Windows-dcr).  
--location: Azure region (e.g., eastus).  
ContentHub: Built-in destination for AMA  
<**log-analytics-workspace-id**>: The resource ID of your Log Analytics workspace.  


f) Associate DCRs with VMs

Associate the respective DCRs with the target VMs:

For Windows VM:
```Bash
az monitor data-collection rule association create \
    --resource-group Honeynet-RG \
    --rule-name Window-dcr \
    --resource <windows-vm-id> \
    --association-name WindowsDCRAssoc
```

For Linux VM:
```Bash
az monitor data-collection rule association create \
    --resource-group Honeynet-RG \
    --rule-name Linux-dcr \
    --resource <linux-vm-id> \
    --association-name LinuxDCRAssoc
```

**Parameters:**  

--rule-name: The name of the Data Collection Rule (DCR).  
--resource: The resource ID of your VM.  
--association-name: A unique name for the DCR association (e.g., WindowsDCRAssoc).  


g) Verification

List the DCRs in your resource group:
```Bash
az monitor data-collection rule list --resource-group Honeynet-RG
```
Check the DCR associations for a specific VM:
```Bash
az monitor data-collection rule association list --resource <vm-id>
```

### 6. Create Diagnostics Settings in Microsoft Entra ID and Enable Audit and SignIn Logs (Tenant-Level Logging)

Tenant-Level Logs in Azure focus on directory-wide activities and events in Microsoft Entra ID (Azure AD), including Audit Logs (records of changes to users, groups, and applications), Sign-In Logs (details of user and service principal authentication, including IP, location, and device), Provisioning Logs (automatic user/group provisioning to external systems), Risky Sign-In Logs (potentially compromised sign-ins flagged by identity protection), and Risk Detection Logs (indicators of security risks like unusual locations or leaked credentials). These logs are critical for monitoring and securing identity and access management across the tenant.

#### 6.2. Identify the Log Analytics Workspace
Retrieve the workspace ID where you want the logs to be sent:
```Bash
az monitor log-analytics workspace list \
    --query "[].{Name:name, ID:id}" \
    --output table
```

Note the ID of the desired workspace.


#### 6.2. Create Diagnostics Settings

Use the following command to create the diagnostics settings:
```Bash
az monitor diagnostic-settings create \
    --name HoneynetEntraDS \
    --resource-type "microsoft.aadiam/tenant" \
    --workspace <log-analytics-workspace-id> \
    --logs '[{"category": "AuditLogs", "enabled": true}, {"category": "SignInLogs", "enabled": true}]'
```

**Parameters:**  
--name <diagnostic-setting-name>: A name for the diagnostic settings (e.g., EntraAuditAndSignInLogs).  
--resource-type "microsoft.aadiam/tenant": Specifies that the diagnostics settings apply to Microsoft Entra ID.  
--workspace <log-analytics-workspace-id>: The ID of the Log Analytics Workspace where the logs will be sent.  
--logs: Specifies the log categories (AuditLogs and SignInLogs) to enable and their status.  


#### 6.3. Verify Configuration

To verify that the diagnostics settings were created, run:
```Bash
az monitor diagnostic-settings list \
    --resource-type "microsoft.aadiam/tenant" \
    --output table
```

### 7. Export Azure Activity Logs to Log Analytics Workspace (Subscription-Level Logging)

Subscription-Level Logs in Azure capture activities and events related to resources within a specific subscription. These include Activity Logs (records of management operations like resource creation, updates, or deletions), Resource Logs (detailed logs specific to individual resources), Policy Logs (evaluations of Azure Policy compliance), Security Alerts (threat and vulnerability alerts from Azure Security Center), and Autoscale Logs (information about scaling actions). These logs are essential for monitoring resource usage, ensuring compliance, and maintaining security at the subscription level.

#### 7.1. Identify the Log Analytics Workspace where the activity logs will be sent:
```Bash
az monitor log-analytics workspace list \
    --query "[].{Name:name, ID:id}" \
    --output table
```

Note the ID of the desired workspace.

#### 7.2. Create Diagnostic Settings for Activity Logs

Use the following command to create a diagnostic setting for exporting all categories of activity logs to a Log Analytics Workspace:
```Bash
az monitor diagnostic-settings create \
    --name ActivityLogsDS \
    --resource "/subscriptions/<subscription-id>" \
    --workspace <log-analytics-workspace-id> \
    --logs '[{"category": "Administrative", "enabled": true}, {"category": "Security", "enabled": true}, {"category": "ServiceHealth", "enabled": true}, {"category": "Alert", "enabled": true}, {"category": "Recommendation", "enabled": true}, {"category": "Policy", "enabled": true}, {"category": "Autoscale", "enabled": true}, {"category": "ResourceHealth", "enabled": true}]'
```

**Parameters:**  
--name: The name for the diagnostic setting (e.g., ActivityLogDS).  
--resource "/subscriptions/<subscription-id>": Specifies the subscription for which activity logs are being exported. Replace <subscription-id> with your subscription ID.  
--workspace <log-analytics-workspace-id>: The ID of the Log Analytics Workspace where the activity logs will be sent.  
--logs: A JSON array specifying all activity log categories to export, with enabled set to true.  


#### 7.3. Verify Configuration

To confirm that the diagnostic settings were successfully created, run:
```Bash
az monitor diagnostic-settings list \
    --resource "/subscriptions/<subscription-id>" \
    --output table
```

### 8. Configure Logging for Azure Storage and Key Vault (Resource-Level Logging)

Resource-Level Logs in Azure provide detailed insights into the operations and performance of individual resources. These include resource logs (e.g., read/write/delete operations within a resource), metrics (e.g., CPU usage, memory utilization, or request latency), and diagnostic logs specific to the resource type (e.g., virtual machine boot logs, database queries, or storage access). These logs are crucial for troubleshooting, performance optimization, and auditing resource-specific activities.


#### 8.1. Create Diagnostic Settings for Azure Storage Account (Audit Logs)

Use the following command to create a diagnostic setting for the Storage Account and enable Audit Logs:
```Bash
az monitor diagnostic-settings create \
    --name <diagnostic-setting-name> \
    --resource "/subscriptions/<subscription-id>/resourceGroups/Honeynet-RG/providers/Microsoft.Storage/storageAccounts/Honeynet-Storage" \
    --workspace <log-analytics-workspace-id> \
    --logs '[{"category": "AuditLogs", "enabled": true}]'
```

**Parameters:**  
--name <diagnostic-setting-name>: The name for the diagnostic setting (e.g., StorageAuditLogs).  
--resource: The full resource ID of the Storage Account.  
--workspace: The ID of the Log Analytics Workspace where the logs will be sent.  
--logs '[{"category": "AuditLogs", "enabled": true}]': Specifies that AuditLogs should be enabled for the Storage Account.  


#### 8.2. Verify Configuration

To verify that the diagnostic settings were applied correctly, you can run:
```Bash
az monitor diagnostic-settings list \
    --resource "/subscriptions/<subscription-id>/resourceGroups/Honeynet-RG/providers/Microsoft.Storage/storageAccounts/Honeynet-Storage" \
    --output table
```

#### 8.3. Create Diagnostic Settings for Key Vault (Audit Logs)

Use the following Azure CLI command to enable logging for Audit Logs in your Key Vault:
```Bash
az monitor diagnostic-settings create \
    --name <diagnostic-setting-name> \
    --resource "/subscriptions/<subscription-id>/resourceGroups/Honeynet-RG/providers/Microsoft.KeyVault/vaults/Honeynet-KeyVault" \
    --workspace <log-analytics-workspace-id> \
    --logs '[{"category": "AuditEvent", "enabled": true}]'
```

**Parameters:**  
--name <diagnostic-setting-name>: Name of the diagnostic setting (e.g., KeyVaultAuditLogs).  
--resource: The full resource ID of the Key Vault.  
--workspace <log-analytics-workspace-id>: The ID of the Log Analytics Workspace where the logs will be sent.  
--logs '[{"category": "AuditEvent", "enabled": true}]': Specifies the log category (AuditEvent) to enable.  


#### 8.4. Verify Configuration

To confirm the diagnostic settings were created, run:
```Bash
az monitor diagnostic-settings list \
    --resource "/subscriptions/<subscription-id>/resourceGroups/Honeynet-RG/providers/Microsoft.KeyVault/vaults/Honeynet-KeyVault" \
    --output table
```

## Step 3: Microsoft Entra ID User Configuration

In this step, we will configure several Users with varying roles/permissions: 

- Tenant-Level Global Reader
- Subscription Reader
- Resource Group Contributor

### 1. Tenant-Level Global Reader

The Global Reader role is a read-only version of the Global Administrator role. It provides the user with the ability to:
- View all administrative information across the Azure tenant.
- View resource configurations in Microsoft Entra ID, Azure subscriptions, and resources.
- Access data and configurations without making any modifications.
- View security policies, user attributes, group memberships, and directory settings

Key Characteristics:
- No Write Access: The user cannot make changes to resources or settings.
- Tenant-Level Scope: When assigned at the root (/), the role applies globally across the tenant.

#### 1.1. Create a User Account
```Bash
az ad user create \
  --display-name "Global Reader User" \
  --user-principal-name globalreader@example.com \
  --password "YourStrongPassword123!"
```
**Parameters:**  
--display-name: The name of the user displayed in Microsoft Entra ID.  
--user-principal-name: The user’s unique login name (e.g., user@yourdomain.com).  
--password: A strong password for the user. Must meet password complexity requirements.  

#### 1.2. Assign the Global Reader Role

To assign the Global Reader role to the user at the tenant level, use the following command:
```Bash
az role assignment create \
  --assignee globalreader@example.com \
  --role "Global Reader" \
  --scope "/"
```

**Parameters:**  
--assignee: The user being assigned the role. Can be specified as:  
• User Principal Name (e.g., globalreader@example.com),  
• Object ID,  
• or Service Principal ID.  
--role: The name of the role. In this case, it is "Global Reader". This role has pre-defined read-only permissions across the tenant.
--scope: The level at which the role applies:  
• / indicates the tenant root scope (global permissions).  

#### 1.3. Verify Role Assignment

To confirm the user has been assigned the role:
```Bash
az role assignment list \
  --assignee globalreader@example.com \
  --all
```

### 2. Subscription Reader

The Reader role provides read-only access to Azure resources. A user assigned this role can:
- View all resources within the assigned subscription.
- Read resource properties and configurations.
- Monitor and view metrics or logs.
- Access dashboards and reports.

Key Characteristics:
- No Write Access: The user cannot create, modify, or delete resources.
- Subscription-Level Scope: Permissions are limited to resources within the assigned subscription.

#### 2.1. Create a User Account
```Bash
az ad user create \
  --display-name "Subscription Reader User" \
  --user-principal-name readeruser@example.com \
  --password "YourSecurePassword123!"
```
**Parameters:**  
--display-name: The friendly name of the user displayed in Microsoft Entra ID.  
--user-principal-name: The user’s unique login name (e.g., user@yourdomain.com).  
--password: A strong password for the user. Must meet complexity requirements.  

#### 2.2. Assign the Reader Role

Assign the Reader role to the user at the subscription level. First, identify the subscription ID where you want to assign the role:

a) Retrieve Subscription ID:
```Bash
az account list --output table
```

This will display a list of subscriptions with their IDs. Copy the relevant Subscription ID.

b) Assign the Reader Role:
```Bash
az role assignment create \
  --assignee readeruser@example.com \
  --role "Reader" \
  --scope "/subscriptions/<subscription-id>"
```

**Parameters:**  
--assignee: The user or identity receiving the role. You can provide:  
• User Principal Name (e.g., readeruser@example.com),  
• Object ID, or  
• Service Principal ID.  
--role: The name of the role being assigned. Here, it is "Reader".  
--scope: The level at which the role applies. For subscription-level permissions, use:  
• /subscriptions/<subscription-id>.

#### 2.3. Verify Role Assignment

To confirm the user has the Reader role, run:
```Bash
az role assignment list \
  --assignee readeruser@example.com \
  --scope "/subscriptions/<subscription-id>" \
  --output table
```

### 3. Resource Group Contributor

The Contributor role provides full access to manage resources within the specified scope. A user with this role can:
- Create, modify, and delete resources within the assigned resource group.
- Manage resource configurations and properties.
- Deploy or remove resources using templates or scripts.
- View resource properties and monitor metrics.

Key Characteristics:
- No Access to Billing: The Contributor role does not include permissions to manage billing or assign roles.
- Resource Group-Level Scope: Access is restricted to the resources in the specified resource group.


#### 3.1. Create a User Account
```Bash
az ad user create \
  --display-name "Resource Group Contributor" \
  --user-principal-name contributoruser@example.com \
  --password "YourSecurePassword123!"
```

**Parameters:**  
--display-name: The name of the user displayed in Microsoft Entra ID.  
--user-principal-name: The unique login name for the user (e.g., user@yourdomain.com).  
--password: A secure password that complies with Azure’s password policies.  

#### 3.2. Assign the Contributor Role at the Resource Group Level

a) Retrieve the Resource Group Name  

To list all resource groups in your subscription, use:
```Bash
az group list --output table
```

This command will display all resource groups with their names and locations. Copy the name of the resource group where you want to assign the role.

b) Assign the Contributor Role
```Bash
az role assignment create \
  --assignee contributoruser@example.com \
  --role "Contributor" \
  --scope "/subscriptions/<subscription-id>/resourceGroups/<resource-group-name>"
```

**Replace:**  
• <**subscription-id**>: With your Azure subscription ID.
• <**resource-group-name**>: With the name of the target resource group (“Honeynet-RG” in this case).

**Parameters:**  
--assignee: The user to receive the role. Can be specified as:  
• User Principal Name (e.g., contributoruser@example.com),  
• Object ID, or  
• Service Principal ID.  
--role: The name of the role. Here, it is "Contributor".  
--scope: The level of access being granted. For a resource group, use:  
• /subscriptions/<subscription-id>/resourceGroups/<resource-group-name>.  

#### 3.3. Verify Role Assignment

To confirm the user has been assigned the role, run:
```Bash
az role assignment list \
  --assignee contributoruser@example.com \
  --scope "/subscriptions/<subscription-id>/resourceGroups/<resource-group-name>" \
  --output table
```

## Step 4: Alerts & Attack World Maps 

In this step, we will import a list of Custom Sentinel Analytics Rules, written in .JSON. This file has been attached to this project.  

An analytics rule in Microsoft Sentinel is a set of conditions and logic that automatically analyzes data ingested into the platform to detect potential security threats or incidents. It uses built-in or custom queries, such as KQL (Kusto Query Language), to scan logs and telemetry data for patterns indicative of suspicious or malicious activity. Analytics rules are used to trigger alerts, investigate incidents, and automate responses, helping security teams quickly identify and mitigate risks in their environment.

### 1. Import Sentinel Analytics Rules

- Login to the Azure Portal
- Go to: Microsoft Sentinel > Analytics > Import
- Select the "Sentinel-Analytics-Rules (KQL Alert Queries).JSON" file to import

![Sentinel Analytics Rules](https://github.com/user-attachments/assets/3624b4d4-5fd3-4c24-be63-27c8d446dd53)


### 2. Attack World Maps

The attack maps will be generated using the .JSON files attached to this project.

### Attack Maps Before Hardening / Security Controls

### nsg-malicious-allowed-in
![nsg-malicious-allowed in](https://github.com/user-attachments/assets/95ab83aa-3914-4e96-aa4f-6b5d1ae23080)<br>

### Syslog-ssh-auth-fail
![syslog-ssh-auth-fail](https://github.com/user-attachments/assets/04d547b9-38b9-40d3-8414-d118d9a3ef0b)<br>

### Windows-rdp-smb-auth-fail
![windows-rdp-smb-auth-fail](https://github.com/user-attachments/assets/2151d1be-3df2-445b-b4ca-745df823169a)<br>

### Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
Start Time 2023-03-15 17:04:29
Stop Time 2023-03-16 17:04:29

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 19470
| Syslog                   | 3028
| SecurityAlert            | 10
| SecurityIncident         | 348
| AzureNetworkAnalytics_CL | 843

## Attack Maps Before Hardening / Security Controls

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Step 5: Secure / Harden Cloud Configuration

There are many ways in which I have chosen to secure our Azure Cloud architecture. When you enable Microsoft Defender for Cloud, it provides you with your current Cloud Configuration with a "Secure Score". This is a measurement of your cloud environment's security posture, expressed as a percentage based on the implementation of recommended security controls. It identifies weaknesses in your infrastructure, prioritizes actionable recommendations, and quantifies improvements as you address them. Enabling Secure Score is important because it provides a clear, continuous assessment of your security posture, helps mitigate risks by prioritizing critical vulnerabilities, and aligns your environment with best practices for safeguarding against threats across hybrid and multi-cloud infrastructures.  

The NIST SP 800-53 Regulatory Compliance Recommendations from Microsoft Defender for Cloud provides a comprehensive framework for assessing and improving the security posture of cloud configurations by aligning them with NIST standards. It maps Azure resources and workloads to specific controls in NIST SP 800-53, offering actionable security recommendations, such as enabling encryption, enforcing least privilege access, and configuring logging. This helps organizations identify compliance gaps, implement best practices, and meet regulatory requirements, ultimately strengthening cloud security and reducing the risk of misconfigurations or breaches.

In this step, we will enable MDC Regulatory Compliance Recommendations based on NIST SP 800-53. We will also implement a few the framework's suggested remediations.

### 5.1. Enable Microsoft Defender for Cloud Regulatory Compliance Recommendations based on NIST 800-53

Using the Azure Portal, Serch for "Microsoft Defender for Cloud"

Select the Following: Regulatory Compliance > Manage Compliance Polices > Select Subscription > Security Policy > Industry & Regulatory Standards (Add more Standards) > Add NIST 800-53 (Latest Revision) > Review + Create with Default Settings


## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
Start Time 2023-03-18 15:37
Stop Time	2023-03-19 15:37

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 8778
| Syslog                   | 25
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

## Conclusion

In this project, a mini honeynet was constructed in Microsoft Azure and log sources were integrated into a Log Analytics workspace. Microsoft Sentinel was employed to trigger alerts and create incidents based on the ingested logs. Additionally, metrics were measured in the insecure environment before security controls were applied, and then again after implementing security measures. It is noteworthy that the number of security events and incidents were drastically reduced after the security controls were applied, demonstrating their effectiveness.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.
