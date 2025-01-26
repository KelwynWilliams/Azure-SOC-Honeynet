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




## Attack Maps Before Hardening / Security Controls
![NSG Allowed Inbound Malicious Flows](https://i.imgur.com/1qvswSX.png)<br>
![Linux Syslog Auth Failures](https://i.imgur.com/G1YgZt6.png)<br>
![Windows RDP/SMB Auth Failures](https://i.imgur.com/ESr9Dlv.png)<br>

## Metrics Before Hardening / Security Controls

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
