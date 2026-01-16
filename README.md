# AI Analyzer for Burp Suite

**AI Analyzer** is a sophisticated Burp Suite extension that integrates Large Language Models (LLMs) via the OpenRouter API to automate the security analysis of HTTP responses. Acting as an AI-powered security assistant, it helps penetration testers and bug hunters identify sensitive data leaks, hidden endpoints, logic flaws, and potential vulnerabilities in real-time.

## 🚀 Key Features

*   **Multi-Model Support**: Seamlessly switch between top-tier models like **Google Gemini**, **OpenAI GPT-4**, **Claude 3**, **Llama 3**, and more via OpenRouter.
*   **Automated Scanning**: Automatically captures and analyzes traffic matching your defined scope and MIME types.
*   **Context-Aware Manual Scanning**: Trigger specific analyzes directly from Burp's Proxy, Repeater, or Intruder context menus.
*   **Smart Request Management**: Features a robust queuing system with **Pause/Resume** capabilities and smart caching to minimize API costs.
*   **Advanced Filtering**: Powerful search and filter options for both the scan queue and the analysis results (supports Regex, Case Sensitivity, and Deep Content Search).
*   **Interactive Site Map**: Results are organized in a clean, comprehensive tree view, allowing for easy navigation and management of findings.
*   **Target Scope Control**: Granular control over which domains and URLs are analyzed using Inclusion/Exclusion Regex rules.

---

## 🛠️ Installation

1.  **Prerequisites**: Ensure you have **Jython** configured in Burp Suite.
    *   Download the Jython Standalone JAR.
    *   Go to **Extensions** -> **Extensions Settings** -> **Python Environment**.
    *   Select the downloaded JAR file.
2.  **Load Extension**:
    *   Go to the **Extensions** tab -> **Installed**.
    *   Click **Add**.
    *   Select **Extension type: Python**.
    *   Browse and select the `AIAnalyzer.py` file.
    *   Click **Next**. The extension should load and the **AI Analyzer** tab will appear.

---

## ⚙️ Configuration Guide

Navigate to the **AI Analyzer -> Configuration** tab to set up the tool.

### 1. General Settings
*   **OpenRouter Key**: Enter your API key from [openrouter.ai](https://openrouter.ai). Click **Check & Save** to verify the connection and fetch the latest list of available models.
*   **Model Name**: Choose the AI model you wish to use for scanning (e.g., `google/gemini-pro`, `anthropic/claude-3-opus`).
*   **Enable Auto-Scanning**: Check this box to enable automatic analysis of live traffic.
*   **Rate Limit**: Set the delay (in seconds) between API requests to avoid hitting rate limits. Default is `45`.
*   **Persist History**: (Reference only) Intended for saving history across reloads.
*   **Allowed MIME Types**: Specify which content types to scan. Recommended: `application/javascript, application/json, text/html, text/xml`.
*   **Ignore Query Params**:
    *   **Enabled**: `script.js?v=1` and `script.js?v=2` are treated as the same resource (scanned once).
    *   **Disabled**: Each unique query string is scanned separately.

### 2. Target Scope
Strictly define what gets scanned to stay within your engagement rules.
*   **Include Section**: Only URLs matching these Regex rules will be processed.
*   **Exclude Section**: URLs matching these rules are ignored (even if they match Include rules).
*   *Tip*: Use `.*\.target\.com` to match a domain and its subdomains.

### 3. Custom System Prompt
You can fully customize the instructions sent to the AI.
*   **Required Placeholders**: You must keep `{url}` and `{code}` in the prompt template, as these are replaced with the actual target data during scanning.

---

## 🎮 Usage Guide

### Automated Scanning
1.  Set up your **Target Scope** and **MIME Types**.
2.  Select your desired **Model**.
3.  Enable **Auto-Scanning**.
4.  Browse your target application. As requests are made, the extension will capture relevant responses and queue them for analysis.

### Manual Scanning
You can manually send any request to the AI Analyzer:
1.  Right-click on a request in **Proxy**, **Repeater**, or **Intruder**.
2.  Hover over **AI Analyzer**.
3.  Choose:
    *   **Rescan with Default (...)**: Scans using the model currently selected in the Config tab.
    *   **Select Model...**: Choose a specific model just for this request.

---

## 📊 Monitoring & Controls

The **Monitor & Logs** tab is your mission control center.

### Active Scans Queue
Displays the list of all queued, running, and completed scan tasks.
*   **Search Filter**: Real-time filtering of the task list by URL or status.
    *   **Regex**: Use Regular Expressions for advanced searching.
    *   **Case Sensitive**: Toggle case sensitivity.
    *   **Negative Search**: Show items that *do not* match the term.
*   **Controls**:
    *   **Pause/Resume**: Stop the processing of the queue without losing tasks. New tasks added while paused will be set to "Paused" status.
    *   **Clear Finished**: Removes logical clutter by deleting completed tasks from the list involved.

### Context Menu (Right-Click on Task)
*   **Rescan**: Re-queue the selected task for fresh analysis.
*   **Delete Task**: Remove the specific task from the queue.

---

## 📝 Analyzer Results (Site Map)

The **Analyzer Results** tab visualizes the findings.

### Site Map Tree
Organizes results hierarchically by **Protocol -> Domain -> Folder -> File**.
*   Clicking a file node displays the full Markdown report generated by the AI in the right-hand preview pane.

### Management & Filtering
*   **Filter Bar**: Located to the right of the Site Map title.
    *   Searches against both **URLs** and **Report Content**. Find every file where the AI mentioned "password" or "critical".
*   **Clear Site Map**: Permanently deletes all results and clears the internal cache.
*   **Right-Click Menu (Tree Nodes)**:
    *   **Rescan**: Send this specific file back to the AI.
    *   **Delete**: Remove a file, folder, or entire domain from the results. This essentially "forgets" the item so it can be re-scanned if encountered again.

---

**Important Note**: The quality, accuracy, and depth of the scan results are heavily dependent on the chosen **AI Model** and the effectiveness of your **Custom System Prompt**. Experimenting with different models and refining your prompt instructions can significantly improve the ability to find specific information.

**Disclaimer**: This extension transmits HTTP response data to the configured AI provider (OpenRouter). Please ensure you comply with all data privacy requirements and engagement authorizations before sending target data to third-party services.
