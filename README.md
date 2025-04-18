# Inbox Exodus

![Inbox Exodus Logo](https://via.placeholder.com/150x150?text=Inbox+Exodus)

A litigation-aware, AI-driven file migration tool designed to extract, classify, audit, and reorganize files and emails from Microsoft 365 (Outlook + OneDrive) into Google Workspace (Gmail + Drive), while preserving forensic chain-of-custody and surfacing legal triggers like contracts, disputes, or litigation signals.

## 🔍 Problem It Solves

| Problem | How Inbox Exodus Solves It |
|---------|----------------------------|
| 🧃 Old emails/files scattered in Outlook & OneDrive | Pulls and reclassifies into structured Google Drive folders |
| 🧠 Files with legal value buried in noise | Flags litigation-relevant terms (e.g. TRO, ownership, PTG) |
| 📜 Need for forensic audit trails | Generates TOTAL RECALL logs with SHA-256, timestamps, routing history |
| 🤖 Manual classification takes too long | Uses GPT to auto-classify every file/email by entity, type, purpose |
| 🧺 Duplicates and outdated files everywhere | Deduplicates, archives non-relevant, syncs only canonical versions |

## ⚙️ Key Features

### 1. MS365 Exporters
- 📤 Exports .pst/.eml from Outlook
- 📁 Downloads entire OneDrive tree

### 2. GPT Classification Engine
- 📊 Analyzes file contents (not names)
- Tags by:
  - Business entity (ARIBIA LLC, Jean Arlene Venturing LLC, etc.)
  - File type (Lease, Contract, Receipt, Statement, Creative)
  - Usage (Legal, Tax, Trust, Rental, Archive)

### 3. Litigation Flagging
- Detects content with terms like "ownership dispute," "TRO," "arbitration," "PTG refund"
- Sends flagged files to /SOURCE_OF_TRUTH/LITIGATION_HOLD/

### 4. Total Recall Logging
- Creates an audit trail per file
- SHA-256, GPT tags, source, destination, timestamp, and action

### 5. Three-Phase Workflow
- **Phase 1:** Analyze files
- **Phase 2:** Propose structure
- **Phase 3:** Execute migration after approval

## 🧱 Stack

| Layer | Tech |
|-------|------|
| Language | Python 3.11+ |
| Cloud | Google Drive API, Gmail API, MS Graph API |
| AI | OpenAI GPT-4o / GPT-3.5 (configurable) |
| Audit | JSONL audit logs |
| UI | Rich CLI |

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/NeverShitty/inbox-exodus.git
   cd inbox-exodus
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure environment variables:
   ```bash
   # Microsoft 365 API credentials
   export MS_CLIENT_ID="your_ms_client_id"
   export MS_CLIENT_SECRET="your_ms_client_secret"
   export MS_TENANT_ID="your_ms_tenant_id"
   
   # Google API credentials
   export GOOGLE_CLIENT_ID="your_google_client_id"
   export GOOGLE_CLIENT_SECRET="your_google_client_secret"
   export GOOGLE_PROJECT_ID="your_google_project_id"
   
   # OpenAI API key
   export OPENAI_API_KEY="your_openai_api_key"
   ```

## 🚀 Usage

Run the application:
```bash
python main.py
