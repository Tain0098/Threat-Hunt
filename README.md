# Threat Hunt Report (Unauthorized TOR Usage)

**Detection of Unauthorized TOR Browser Installation and Use on Workstation:** `htainvm`

---

### 📝 Example Scenario
Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### 🎯 High-Level TOR related IoC Discovery Plan
1. Check `DeviceFileEvents` for any `tor(.exe)` or `firefox(.exe)` file events
2. Check `DeviceProcessEvents` for any signs of installation or usage
3. Check `DeviceNetworkEvents` for any signs of outgoing connections over known TOR ports

---

## 🔍 Steps Taken

### 1. File Creation Query
At `2026-04-25T03:36:00.3250574Z`, I search for the `DeviceFileEvent` for any file with name containing `tor.exe` and a device name `[htainvm]` shows up with file creation of `tor.exe`.

**Query used:**
```kusto
DeviceFileEvents
| where DeviceName has "htainvm"
| where FileName contains "tor.exe"
```

---

### 2. Process Execution Query
`2026-04-25T03:35:48.2784045Z`  
Next, I search in `DeviceProcessEvent` with keyword `tor` in the device `[htainvm]`. Found a PowerShell `ProcessCommandLine` `["tor-browser-windows-x86_64-portable-15.0.10.exe" /S]`. This means the user did a silent install of the Tor Browser in the background without showing.

**Query used:**
```kusto
DeviceProcessEvents
| where DeviceName has "htainvm"
| where ProcessCommandLine contains "tor"
```

---

### 3. Network Connection Query
At `2026-04-25T03:37:28.2843351Z`  
The user has made multiple connections through the Tor Browser with commonly used `tor.exe` ports like **9001** and visiting websites such as `https://7osvw2w5tp7tuff5v.com` commonly used in `tor.exe` and black market sites.

**Query used:**
```kusto
DeviceNetworkEvents
| where DeviceName has "htainvm"
| where InitiatingProcessFileName contains "tor"
```

---

### 4. Note Creation Check
For a final check just to be sure, I went back to `DeviceFileEvent`. Between **Apr 24, 2026 11:39:19 PM** and **Apr 24, 2026 11:41:19 PM**, a file name `shopping list.txt` was created.

**Query used:**
```kusto
DeviceFileEvents
| where DeviceName has "htainvm"
| where TimeGenerated between (datetime(2026-04-25T03:39:19.0520363Z) .. datetime(2026-04-25T03:41:19.0520363Z))
```

---

## ⏱️ Chronological Events

* **03:35:48 Z | Silent Installation Initiated**
  * **Action:** PowerShell executed a portable Tor Browser installer.
  * **Command:** `"tor-browser-windows-x86_64-portable-15.0.10.exe" /S`
  * **Key Detail:** The `/S` switch indicates the user purposely hid the installation UI from view.

* **03:36:00 Z | Tor Executable Dropped**
  * **Action:** `tor.exe` was successfully created/extracted to the file system.
  * **Context:** This confirms the silent installation was successful and the Tor binary is now present on the disk.

* **03:37:28 Z | Dark Web / Black Market Activity**
  * **Action:** Outbound network connections via `tor.exe`.
  * **Traffic:** Connections over Port 9001 (Tor Relay) and navigation to the suspicious "black market" URL (`7osvw2w5tp7tuff5v.com`).
  * **Context:** The user is actively bypassing corporate filters to access hidden services.

* **03:39:19 Z – 03:41:19 Z | Data Exfiltration or Note Taking**
  * **Action:** Creation of a file named `shopping list.txt`.
  * **Context:** This follows immediately after browsing the black market site. In a security context, a "shopping list" on a black market often refers to a list of stolen credentials, prohibited items, or target data for exfiltration.


---

## 🚩 Key Security Findings
* **Stealth:** The use of `/S` and a portable version of Tor shows intent to bypass local security controls and leave a minimal footprint.
* **Network Bypass:** Connecting to Port 9001 confirms they successfully tunneled traffic out of your network.
* **Potential Data Risk:** The creation of `shopping list.txt` immediately after browsing suggests the user may have saved sensitive information or "orders" from the market.

---

## 🛡️ Response Taken
TOR usage was confirmed on endpoint **[htainvm]**. The device was isolated from the network to prevent potential data exfiltration, and the user's direct manager was notified for further disciplinary action.



