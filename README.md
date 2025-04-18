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
| Framework | Flask, SQLAlchemy |
| Cloud | Google Drive API, Gmail API, MS Graph API |
| AI | OpenAI GPT-4o (the newest OpenAI model) |
| Database | PostgreSQL |
| Audit | JSONL audit logs + SQL database |
| UI | Web interface + Rich CLI |

## 🚀 Project Status

This project has been transitioned from a CLI-based tool to a full web application with:

- **Database Integration**: PostgreSQL with SQLAlchemy ORM for structured data storage
- **Modern Web Interface**: Bootstrap-based responsive design
- **API Endpoints**: Structured REST API for extensibility
- **Cloud-Ready**: Designed to run on Replit or any cloud provider

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/inbox-exodus.git
   cd inbox-exodus
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure environment variables:
   ```bash
   # Database connection
   export DATABASE_URL="postgresql://user:password@localhost:5432/inboxexodus"
   
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
   
   # Session secret for Flask
   export SESSION_SECRET="your_secure_session_secret"
   ```

## 🚀 Usage

1. Run the web application:
   ```bash
   gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app
   ```

2. Visit the application in your browser at `http://localhost:5000`

## 📊 Database Structure

The application uses a PostgreSQL database with the following main models:

- **User**: Application users and authentication
- **MicrosoftAccount**: Microsoft 365 connection information
- **GoogleAccount**: Google Workspace connection information
- **MigrationJob**: File migration job tracking
- **FileItem**: Individual file or email being migrated
- **AuditLog**: Comprehensive audit trail for all operations
- **FolderStructure**: Proposed and approved folder structures

## 🔄 Three-Phase Migration Process

Our migration process follows a careful, methodical approach:

1. **Analyze Phase**: 
   - Extract and analyze files from Microsoft 365
   - Classify content with GPT
   - Detect litigation-related terms

2. **Propose Phase**:
   - Generate intelligent folder structure proposal
   - Present to user for review and approval
   - Allow customization before proceeding

3. **Execute Phase**:
   - Create approved folder structure in Google Workspace
   - Migrate files with integrity validation
   - Generate comprehensive audit logs

## 🛡️ Security and Compliance

- **Chain of Custody**: SHA-256 hashing ensures file integrity throughout migration
- **Litigation Awareness**: Automatic detection of legal terms flags sensitive content
- **Audit Trail**: Comprehensive logging of all actions for compliance requirements
- **Secure Authentication**: OAuth 2.0 for Microsoft and Google integrations
