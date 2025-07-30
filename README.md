# 🕵️‍♂️ SolarWinds IOC Detection in Proxy Logs using Splunk

> **_Category_**: SOC Analyst  
> **_Tools Used_**: Splunk, Threat Intelligence Correlation, CSV Log Analysis

---

## 🎯 Objective

This project simulates a **threat detection scenario** in which I identify signs of a SolarWinds-based compromise by correlating known Indicators of Compromise (IOCs) with proxy logs using **Splunk**.

I ingested **SolarWinds IOC data** alongside **enterprise proxy logs**, created custom search queries, and visualized suspicious communications.

---

## 🌱 What I Did

### 1. **📥 Ingested Datasets into Splunk**
- Uploaded:
  - `NetworkProxyLog02.csv` – simulated enterprise proxy logs
  - `SolarWinds_IOCs.csv` – known malicious IPs and domains from the SolarWinds breach

📸 **Uploading CSV Logs into Splunk**

![NetworkProxyLog02.csv](https://raw.githubusercontent.com/codepath/cyb102-file-storage/main/NetworkProxyLog02.csv
)

---

### 2. **🔍 Correlated IOC IPs with Proxy Activity**
- Wrote SPL query to detect any internal machine reaching out to **SolarWinds IOC IPs**
- Used the `IP Address` field for correlation

```spl
(index=main source="NetworkProxyLog02.csv") OR (index=main source="SolarWinds_IOCs.csv")
| stats values(source) as sources, values("Computer Name") as ComputerName, values("User Agent String") as UserAgent, values(Date) as Date, values(Time) as Time by "IP Address"
| where mvcount(sources) > 1
| table "IP Address", ComputerName, UserAgent, Date, Time
```

---

### 3. **📊 Visualized Suspicious Traffic**

- Created a **bar chart** to show how frequently each suspicious IP address appeared in the logs.
- This helped identify the top external hosts contacted by internal machines.
- Used Splunk’s visualization tools to graph activity across different IP addresses.

📸 **Bar Chart – Suspicious IP Frequency**  
<img width="1918" height="1003" alt="image" src="https://github.com/user-attachments/assets/e3fd73b5-6634-4f7e-8b7f-e205af39352c" />

---

### 4. **💡 Key Takeaways**

- Learned to **correlate known IOCs with network logs** using Splunk.
- Practiced **threat hunting and IOC matching** with real-world-style datasets.
- Used **custom queries and visualizations** to identify suspicious behavior.
- Simulated how a **SOC analyst** investigates network-based threats.

---

### 5. **🧪 Skills Practiced**

- 📌 IOC matching in Splunk (multi-source correlation)
- 🧠 SPL query design (`stats`, `mvcount`, `table`, `values`)
- 📊 Visualizing trends with bar charts
- 🧩 Pivoting between data sources (SolarWinds IOCs + proxy logs)
- 🗒️ Documenting and communicating findings clearly
