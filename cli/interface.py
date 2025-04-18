"""
CLI Interface for Inbox Exodus
Provides a rich command-line interface for the application
"""
import os
import sys
import time
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn
from rich.tree import Tree
from rich.prompt import Prompt, Confirm
from rich.markdown import Markdown
from rich import box

from extractors.microsoft_extractor import MicrosoftExtractor
from processors.gpt_classifier import GPTClassifier
from processors.litigation_scanner import LitigationScanner
from migrators.google_migrator import GoogleMigrator

logger = logging.getLogger("inbox_exodus.cli")

class InboxExodusCLI:
    """Command-line interface for Inbox Exodus"""
    
    def __init__(self, config):
        """
        Initialize CLI Interface
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.console = Console()
        
        # Initialize components
        self.ms_extractor = MicrosoftExtractor(config)
        self.gpt_classifier = GPTClassifier(config)
        self.litigation_scanner = LitigationScanner(config)
        self.google_migrator = GoogleMigrator(config)
        
        # State variables
        self.extracted_files = []
        self.classified_files = []
        self.proposed_structure = None
        self.folder_id_map = None
    
    def start(self):
        """Start the CLI interface"""
        self._show_welcome()
        
        # Main menu loop
        while True:
            choice = self._show_main_menu()
            
            if choice == "1":
                # Connect to Microsoft 365
                self._connect_microsoft()
            elif choice == "2":
                # Connect to Google Workspace
                self._connect_google()
            elif choice == "3":
                # Analyze Microsoft 365 data
                self._analyze_microsoft_data()
            elif choice == "4":
                # Extract files
                self._extract_files()
            elif choice == "5":
                # Classify files
                self._classify_files()
            elif choice == "6":
                # Generate folder structure
                self._generate_folder_structure()
            elif choice == "7":
                # Migrate files
                self._migrate_files()
            elif choice == "8":
                # View logs
                self._view_logs()
            elif choice == "9":
                # Run complete workflow
                self._run_complete_workflow()
            elif choice == "0":
                # Exit
                self.console.print("[bold green]Exiting Inbox Exodus. Goodbye![/bold green]")
                sys.exit(0)
    
    def _show_welcome(self):
        """Show welcome message"""
        welcome_md = """
        # 📁 Inbox Exodus

        ## AI-Driven File Migration Tool

        Migrate files from Microsoft 365 to Google Workspace with AI-powered classification and litigation awareness.

        ---

        **Three-Phase Workflow:**
        1. **Analyze** - Extract and classify files from Microsoft 365
        2. **Propose** - Generate folder structure proposal
        3. **Execute** - Migrate files to Google Workspace

        ---
        """
        
        self.console.print(Panel(Markdown(welcome_md), title="Welcome to Inbox Exodus", border_style="blue"))
    
    def _show_main_menu(self) -> str:
        """
        Show main menu and get user choice
        
        Returns:
            str: User choice
        """
        self.console.print("\n[bold cyan]Main Menu[/bold cyan]")
        
        menu_items = [
            ("1", "Connect to Microsoft 365"),
            ("2", "Connect to Google Workspace"),
            ("3", "Analyze Microsoft 365 Data"),
            ("4", "Extract Files from Microsoft 365"),
            ("5", "Classify Extracted Files"),
            ("6", "Generate Folder Structure Proposal"),
            ("7", "Migrate Files to Google Workspace"),
            ("8", "View Logs"),
            ("9", "Run Complete Workflow"),
            ("0", "Exit")
        ]
        
        table = Table(box=box.ROUNDED)
        table.add_column("Option", style="cyan")
        table.add_column("Action", style="white")
        
        for option, action in menu_items:
            table.add_row(option, action)
        
        self.console.print(table)
        
        choice = Prompt.ask("[bold yellow]Select an option[/bold yellow]", choices=[item[0] for item in menu_items], default="9")
        return choice
    
    def _connect_microsoft(self):
        """Connect to Microsoft 365"""
        self.console.print("\n[bold cyan]Connecting to Microsoft 365...[/bold cyan]")
        
        # Check if required env vars are set
        if not all([self.config.ms_client_id, self.config.ms_client_secret, self.config.ms_tenant_id]):
            self.console.print("[bold red]Error: Microsoft 365 API credentials not set in environment variables.[/bold red]")
            self.console.print("Please set MS_CLIENT_ID, MS_CLIENT_SECRET, and MS_TENANT_ID.")
            return
        
        # Get auth URL
        auth_url = self.ms_extractor.get_auth_url()
        
        self.console.print(f"\nPlease visit the following URL to authorize the application:")
        self.console.print(f"[bold blue]{auth_url}[/bold blue]\n")
        
        # Get auth code from user
        auth_code = Prompt.ask("[bold yellow]Enter the authorization code[/bold yellow]")
        
        # Exchange auth code for token
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn()
        ) as progress:
            task = progress.add_task("Authenticating...", total=1)
            
            result = self.ms_extractor.get_token_from_code(auth_code)
            progress.update(task, advance=1)
        
        if result:
            self.console.print("[bold green]Successfully connected to Microsoft 365![/bold green]")
            
            # Get user info
            user_info = self.ms_extractor._get_user_info()
            if user_info:
                user_email = user_info.get("userPrincipalName", "Unknown")
                self.console.print(f"Connected as: [bold]{user_email}[/bold]")
        else:
            self.console.print("[bold red]Failed to connect to Microsoft 365. Please check the authorization code and try again.[/bold red]")
    
    def _connect_google(self):
        """Connect to Google Workspace"""
        self.console.print("\n[bold cyan]Connecting to Google Workspace...[/bold cyan]")
        
        # Check if required env vars are set
        if not all([self.config.google_client_id, self.config.google_client_secret]):
            self.console.print("[bold red]Error: Google API credentials not set in environment variables.[/bold red]")
            self.console.print("Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.")
            return
        
        self.console.print("Starting authentication flow. A browser window should open automatically.")
        self.console.print("If it doesn't open, please check the URL that will be printed and open it manually.")
        
        # Start authentication
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn()
        ) as progress:
            task = progress.add_task("Authenticating...", total=1)
            
            result = self.google_migrator.authenticate()
            progress.update(task, advance=1)
        
        if result:
            self.console.print("[bold green]Successfully connected to Google Workspace![/bold green]")
        else:
            self.console.print("[bold red]Failed to connect to Google Workspace. Please try again.[/bold red]")
    
    def _analyze_microsoft_data(self):
        """Analyze Microsoft 365 data"""
        self.console.print("\n[bold cyan]Analyzing Microsoft 365 Data...[/bold cyan]")
        
        # Check if connected to Microsoft 365
        if not self.ms_extractor.access_token:
            self.console.print("[bold red]Error: Not connected to Microsoft 365. Please connect first.[/bold red]")
            return
        
        # Analyze data
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn()
        ) as progress:
            task = progress.add_task("Analyzing...", total=1)
            
            stats = self.ms_extractor.analyze_storage()
            progress.update(task, advance=1)
        
        # Display results
        if stats:
            # Outlook stats
            outlook_stats = stats.get("outlook", {})
            outlook_table = Table(title="Outlook Statistics", box=box.ROUNDED)
            outlook_table.add_column("Metric", style="cyan")
            outlook_table.add_column("Value", style="white", justify="right")
            
            outlook_table.add_row("Folders", str(outlook_stats.get("folder_count", 0)))
            outlook_table.add_row("Emails", str(outlook_stats.get("email_count", 0)))
            outlook_table.add_row("Total Size", self._format_size(outlook_stats.get("total_size_bytes", 0)))
            
            self.console.print(outlook_table)
            
            # OneDrive stats
            onedrive_stats = stats.get("onedrive", {})
            onedrive_table = Table(title="OneDrive Statistics", box=box.ROUNDED)
            onedrive_table.add_column("Metric", style="cyan")
            onedrive_table.add_column("Value", style="white", justify="right")
            
            onedrive_table.add_row("Folders", str(onedrive_stats.get("folder_count", 0)))
            onedrive_table.add_row("Files", str(onedrive_stats.get("file_count", 0)))
            onedrive_table.add_row("Total Size", self._format_size(onedrive_stats.get("total_size_bytes", 0)))
            
            self.console.print(onedrive_table)
            
            # Overall summary
            total_items = outlook_stats.get("email_count", 0) + onedrive_stats.get("file_count", 0)
            total_size = outlook_stats.get("total_size_bytes", 0) + onedrive_stats.get("total_size_bytes", 0)
            
            self.console.print(f"\n[bold green]Total: {total_items:,} items ({self._format_size(total_size)})[/bold green]")
        else:
            self.console.print("[bold red]Failed to analyze Microsoft 365 data.[/bold red]")
    
    def _extract_files(self):
        """Extract files from Microsoft 365"""
        self.console.print("\n[bold cyan]Extracting Files from Microsoft 365...[/bold cyan]")
        
        # Check if connected to Microsoft 365
        if not self.ms_extractor.access_token:
            self.console.print("[bold red]Error: Not connected to Microsoft 365. Please connect first.[/bold red]")
            return
        
        # Ask user which source(s) to extract from
        sources = ["Outlook", "OneDrive", "Both"]
        source_choice = Prompt.ask(
            "[bold yellow]Which source do you want to extract from?[/bold yellow]",
            choices=["1", "2", "3"],
            default="3"
        )
        
        # Create extraction directories
        outlook_dir = os.path.join(self.config.temp_dir, "outlook")
        onedrive_dir = os.path.join(self.config.temp_dir, "onedrive")
        
        # Extract files
        with Progress() as progress:
            outlook_task = None
            onedrive_task = None
            
            if source_choice in ["1", "3"]:  # Outlook or Both
                outlook_task = progress.add_task("[blue]Extracting from Outlook...", total=1)
            
            if source_choice in ["2", "3"]:  # OneDrive or Both
                onedrive_task = progress.add_task("[green]Extracting from OneDrive...", total=1)
            
            # Extract from Outlook
            outlook_files = []
            if outlook_task is not None:
                outlook_files = self.ms_extractor.extract_emails(outlook_dir)
                progress.update(outlook_task, completed=1)
            
            # Extract from OneDrive
            onedrive_files = []
            if onedrive_task is not None:
                onedrive_files = self.ms_extractor.extract_onedrive_files(onedrive_dir)
                progress.update(onedrive_task, completed=1)
        
        # Combine extracted files
        self.extracted_files = outlook_files + onedrive_files
        
        # Show summary
        self.console.print(f"\n[bold green]Extraction complete![/bold green]")
        self.console.print(f"Extracted {len(outlook_files)} emails and {len(onedrive_files)} files.")
        self.console.print(f"Total: {len(self.extracted_files)} items")
        
        # Ask if user wants to view extraction locations
        if Confirm.ask("Do you want to see the extraction directories?"):
            self.console.print(f"\nOutlook files: [cyan]{outlook_dir}[/cyan]")
            self.console.print(f"OneDrive files: [cyan]{onedrive_dir}[/cyan]")
    
    def _classify_files(self):
        """Classify extracted files"""
        self.console.print("\n[bold cyan]Classifying Extracted Files...[/bold cyan]")
        
        # Check if files have been extracted
        if not self.extracted_files:
            self.console.print("[bold yellow]No files have been extracted yet.[/bold yellow]")
            
            # Ask user if they want to extract files
            if Confirm.ask("Do you want to extract files now?"):
                self._extract_files()
                
                # Check again
                if not self.extracted_files:
                    self.console.print("[bold red]No files to classify.[/bold red]")
                    return
            else:
                self.console.print("[bold red]No files to classify.[/bold red]")
                return
        
        # Check if OpenAI API key is set
        if not self.config.openai_api_key:
            self.console.print("[bold red]Error: OpenAI API key not set in environment variables.[/bold red]")
            self.console.print("Please set OPENAI_API_KEY.")
            return
        
        # Get file paths for classification
        file_paths = []
        for file_item in self.extracted_files:
            if isinstance(file_item, dict) and "file_path" in file_item:
                file_paths.append(file_item["file_path"])
        
        # Classify files
        self.classified_files = []
        
        with Progress() as progress:
            task = progress.add_task("[blue]Classifying files...", total=len(file_paths))
            
            for file_path in file_paths:
                # Classify file
                classification = self.gpt_classifier.classify_file(file_path)
                
                # Add to classified files
                self.classified_files.append(classification)
                
                # Update progress
                progress.update(task, advance=1)
        
        # Show summary
        self.console.print(f"\n[bold green]Classification complete![/bold green]")
        self.console.print(f"Classified {len(self.classified_files)} files.")
        
        # Count litigation risks
        litigation_risks = sum(1 for c in self.classified_files if c.get("litigation_risk", False))
        self.console.print(f"[bold red]Litigation risks found: {litigation_risks}[/bold red]")
        
        # Ask if user wants to see classification summary
        if Confirm.ask("Do you want to see a classification summary?"):
            self._show_classification_summary()
    
    def _show_classification_summary(self):
        """Show classification summary"""
        # Group by entity
        entities = {}
        for classification in self.classified_files:
            entity = classification.get("entity", "Unknown")
            if entity not in entities:
                entities[entity] = []
            entities[entity].append(classification)
        
        # Create table
        table = Table(title="Classification Summary by Entity", box=box.ROUNDED)
        table.add_column("Entity", style="cyan")
        table.add_column("Files", style="white", justify="right")
        table.add_column("Litigation Risks", style="red", justify="right")
        
        for entity, files in sorted(entities.items()):
            litigation_risks = sum(1 for c in files if c.get("litigation_risk", False))
            table.add_row(
                entity,
                str(len(files)),
                str(litigation_risks)
            )
        
        self.console.print(table)
        
        # Group by type
        types = {}
        for classification in self.classified_files:
            file_type = classification.get("type", "Unknown")
            if file_type not in types:
                types[file_type] = []
            types[file_type].append(classification)
        
        # Create table
        table = Table(title="Classification Summary by Type", box=box.ROUNDED)
        table.add_column("Type", style="cyan")
        table.add_column("Files", style="white", justify="right")
        table.add_column("Litigation Risks", style="red", justify="right")
        
        for file_type, files in sorted(types.items()):
            litigation_risks = sum(1 for c in files if c.get("litigation_risk", False))
            table.add_row(
                file_type,
                str(len(files)),
                str(litigation_risks)
            )
        
        self.console.print(table)
        
        # Group by purpose
        purposes = {}
        for classification in self.classified_files:
            purpose = classification.get("purpose", "Unknown")
            if purpose not in purposes:
                purposes[purpose] = []
            purposes[purpose].append(classification)
        
        # Create table
        table = Table(title="Classification Summary by Purpose", box=box.ROUNDED)
        table.add_column("Purpose", style="cyan")
        table.add_column("Files", style="white", justify="right")
        table.add_column("Litigation Risks", style="red", justify="right")
        
        for purpose, files in sorted(purposes.items()):
            litigation_risks = sum(1 for c in files if c.get("litigation_risk", False))
            table.add_row(
                purpose,
                str(len(files)),
                str(litigation_risks)
            )
        
        self.console.print(table)
    
    def _generate_folder_structure(self):
        """Generate folder structure proposal"""
        self.console.print("\n[bold cyan]Generating Folder Structure Proposal...[/bold cyan]")
        
        # Check if files have been classified
        if not self.classified_files:
            self.console.print("[bold yellow]No files have been classified yet.[/bold yellow]")
            
            # Ask user if they want to classify files
            if Confirm.ask("Do you want to classify files now?"):
                self._classify_files()
                
                # Check again
                if not self.classified_files:
                    self.console.print("[bold red]No files to generate folder structure for.[/bold red]")
                    return
            else:
                self.console.print("[bold red]No files to generate folder structure for.[/bold red]")
                return
        
        # Generate folder structure
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn()
        ) as progress:
            task = progress.add_task("Generating folder structure...", total=1)
            
            self.proposed_structure = self.gpt_classifier.generate_folder_structure(self.classified_files)
            progress.update(task, advance=1)
        
        # Show summary
        self.console.print(f"\n[bold green]Folder structure generation complete![/bold green]")
        
        # Show folder structure
        self._show_folder_structure()
        
        # Ask for approval
        if Confirm.ask("[bold yellow]Do you approve this folder structure?[/bold yellow]", default=True):
            self.console.print("[bold green]Folder structure approved![/bold green]")
            return True
        else:
            self.console.print("[bold yellow]Folder structure rejected. Please modify or regenerate.[/bold yellow]")
            return False
    
    def _show_folder_structure(self):
        """Show folder structure proposal"""
        if not self.proposed_structure:
            self.console.print("[bold red]No folder structure to display.[/bold red]")
            return
        
        structure = self.proposed_structure.get("structure", {})
        
        # Create a tree
        tree = Tree("[bold cyan]Proposed Folder Structure[/bold cyan]")
        
        # Add structure to tree
        self._add_structure_to_tree(structure, tree)
        
        # Print tree
        self.console.print(tree)
        
        # Show file placements
        file_placements = self.proposed_structure.get("file_placements", {})
        
        # Create table
        table = Table(title="File Placement Summary", box=box.ROUNDED)
        table.add_column("Target Folder", style="cyan")
        table.add_column("Files", style="white", justify="right")
        
        # Count files per folder
        folder_counts = {}
        for file_path, folder_path in file_placements.items():
            if folder_path not in folder_counts:
                folder_counts[folder_path] = 0
            folder_counts[folder_path] += 1
        
        # Add rows to table
        for folder_path, count in sorted(folder_counts.items()):
            table.add_row(folder_path, str(count))
        
        self.console.print(table)
    
    def _add_structure_to_tree(self, structure, tree, current_path=""):
        """Add folder structure to tree"""
        for name, children in structure.items():
            path = f"{current_path}/{name}" if current_path else name
            
            # Create node
            node = tree.add(f"[bold]{name}[/bold]")
            
            # Add children
            if children:
                self._add_structure_to_tree(children, node, path)
    
    def _migrate_files(self):
        """Migrate files to Google Workspace"""
        self.console.print("\n[bold cyan]Migrating Files to Google Workspace...[/bold cyan]")
        
        # Check if folder structure has been generated
        if not self.proposed_structure:
            self.console.print("[bold yellow]No folder structure has been generated yet.[/bold yellow]")
            
            # Ask user if they want to generate folder structure
            if Confirm.ask("Do you want to generate folder structure now?"):
                result = self._generate_folder_structure()
                
                # Check if user approved
                if not result:
                    self.console.print("[bold red]Migration canceled.[/bold red]")
                    return
                
                # Check again
                if not self.proposed_structure:
                    self.console.print("[bold red]No folder structure to migrate files with.[/bold red]")
                    return
            else:
                self.console.print("[bold red]No folder structure to migrate files with.[/bold red]")
                return
        
        # Check if connected to Google Workspace
        if not self.google_migrator.drive_service or not self.google_migrator.gmail_service:
            self.console.print("[bold yellow]Not connected to Google Workspace.[/bold yellow]")
            
            # Ask user if they want to connect
            if Confirm.ask("Do you want to connect to Google Workspace now?"):
                self._connect_google()
                
                # Check again
                if not self.google_migrator.drive_service or not self.google_migrator.gmail_service:
                    self.console.print("[bold red]Not connected to Google Workspace. Migration canceled.[/bold red]")
                    return
            else:
                self.console.print("[bold red]Not connected to Google Workspace. Migration canceled.[/bold red]")
                return
        
        # Get structure and file placements
        structure = self.proposed_structure.get("structure", {})
        file_placements = self.proposed_structure.get("file_placements", {})
        
        # Show migration summary
        self.console.print(f"\n[bold]Migration Summary:[/bold]")
        self.console.print(f"Files to migrate: {len(file_placements)}")
        
        # Ask for confirmation
        if not Confirm.ask("[bold yellow]Do you want to proceed with migration?[/bold yellow]", default=True):
            self.console.print("[bold yellow]Migration canceled.[/bold yellow]")
            return
        
        # Log commit intent
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        # Migrate files
        with Progress() as progress:
            # Create folders task
            create_folders_task = progress.add_task("[blue]Creating folder structure...", total=1)
            
            # Create folder structure in Google Drive
            self.folder_id_map = self.google_migrator.create_folder_structure(structure)
            progress.update(create_folders_task, completed=1)
            
            # Migrate files task
            migrate_files_task = progress.add_task("[green]Migrating files...", total=len(file_placements))
            
            # Migrate files
            results = self.google_migrator.migrate_files(file_placements, self.folder_id_map)
            progress.update(migrate_files_task, completed=len(file_placements))
        
        # Show results
        self.console.print(f"\n[bold green]Migration complete![/bold green]")
        self.console.print(f"Successfully migrated {len(results)} files.")
        
        # Log execution result
        verified_by = "user"
        self.gpt_classifier.audit_logger.log_execution_result(
            status="EXECUTED",
            timestamp=datetime.utcnow().isoformat() + "Z",
            verified_by=verified_by
        )
    
    def _view_logs(self):
        """View logs"""
        self.console.print("\n[bold cyan]Viewing Logs...[/bold cyan]")
        
        # Define log files
        log_files = [
            ("1", "Extraction Log", os.path.join(self.config.log_dir, "extraction_log.jsonl")),
            ("2", "Classification Log", os.path.join(self.config.log_dir, "classification_log.jsonl")),
            ("3", "Litigation Log", os.path.join(self.config.log_dir, "litigation_log.jsonl")),
            ("4", "Migration Log", os.path.join(self.config.log_dir, "migration_log.jsonl")),
            ("5", "Error Log", os.path.join(self.config.log_dir, "error_log.jsonl")),
            ("6", "Total Recall Log", os.path.join(self.config.log_dir, "TOTAL_RECALL_LOG.jsonl")),
            ("7", "Failure Log", os.path.join(self.config.log_dir, "TOTAL_RECALL_FAILURE_LOG.jsonl")),
            ("0", "Back to Main Menu", None)
        ]
        
        # Create table
        table = Table(box=box.ROUNDED)
        table.add_column("Option", style="cyan")
        table.add_column("Log", style="white")
        
        for option, log_name, _ in log_files:
            table.add_row(option, log_name)
        
        self.console.print(table)
        
        # Get user choice
        choice = Prompt.ask(
            "[bold yellow]Select a log to view[/bold yellow]",
            choices=[item[0] for item in log_files],
            default="6"
        )
        
        # Check if user wants to go back
        if choice == "0":
            return
        
        # Get selected log file
        selected_log = next((item for item in log_files if item[0] == choice), None)
        
        if not selected_log:
            self.console.print("[bold red]Invalid choice.[/bold red]")
            return
        
        log_name = selected_log[1]
        log_path = selected_log[2]
        
        # Check if log file exists
        if not os.path.exists(log_path):
            self.console.print(f"[bold yellow]Log file does not exist: {log_path}[/bold yellow]")
            return
        
        # Read log file
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                log_entries = [json.loads(line) for line in f.readlines()]
            
            # Show log entries
            self.console.print(f"\n[bold cyan]{log_name}[/bold cyan] - {len(log_entries)} entries")
            
            # Create table
            table = Table(box=box.ROUNDED)
            table.add_column("Timestamp", style="cyan")
            table.add_column("Action", style="white")
            table.add_column("Details", style="white")
            
            # Add rows
            for entry in log_entries[-10:]:  # Show last 10 entries
                timestamp = entry.get("timestamp", "Unknown")
                action = entry.get("action", "Unknown")
                
                # Get details based on action
                details = "No details"
                
                if action == "extraction":
                    source_type = entry.get("source_type", "Unknown")
                    destination = entry.get("destination", "Unknown")
                    details = f"From {source_type} to {os.path.basename(destination)}"
                elif action == "classification":
                    file_path = entry.get("file_path", "Unknown")
                    classification = entry.get("classification", {})
                    entity = classification.get("entity", "Unknown")
                    file_type = classification.get("type", "Unknown")
                    details = f"{os.path.basename(file_path)} -> {entity}/{file_type}"
                elif action == "litigation_scan":
                    file_path = entry.get("file_path", "Unknown")
                    litigation_risk = entry.get("litigation_risk", False)
                    terms = entry.get("terms_found", [])
                    details = f"{os.path.basename(file_path)} -> {'RISK' if litigation_risk else 'No risk'}"
                    if terms:
                        details += f" ({', '.join(terms[:2])})"
                elif action == "migration":
                    source_path = entry.get("source_path", "Unknown")
                    destination_type = entry.get("destination_type", "Unknown")
                    details = f"{os.path.basename(source_path)} -> {destination_type}"
                elif action == "error":
                    module = entry.get("module", "Unknown")
                    error_message = entry.get("error_message", "Unknown")
                    details = f"{module}: {error_message[:50]}..."
                
                table.add_row(timestamp, action, details)
            
            self.console.print(table)
            
            # Ask if user wants to view more entries
            if len(log_entries) > 10 and Confirm.ask("Do you want to view more entries?"):
                # Create pager for all entries
                all_entries_table = Table(box=box.ROUNDED)
                all_entries_table.add_column("Timestamp", style="cyan")
                all_entries_table.add_column("Action", style="white")
                all_entries_table.add_column("Details", style="white")
                
                for entry in log_entries:
                    timestamp = entry.get("timestamp", "Unknown")
                    action = entry.get("action", "Unknown")
                    
                    # Get details based on action
                    details = "No details"
                    
                    if action == "extraction":
                        source_type = entry.get("source_type", "Unknown")
                        destination = entry.get("destination", "Unknown")
                        details = f"From {source_type} to {os.path.basename(destination)}"
                    elif action == "classification":
                        file_path = entry.get("file_path", "Unknown")
                        classification = entry.get("classification", {})
                        entity = classification.get("entity", "Unknown")
                        file_type = classification.get("type", "Unknown")
                        details = f"{os.path.basename(file_path)} -> {entity}/{file_type}"
                    elif action == "litigation_scan":
                        file_path = entry.get("file_path", "Unknown")
                        litigation_risk = entry.get("litigation_risk", False)
                        terms = entry.get("terms_found", [])
                        details = f"{os.path.basename(file_path)} -> {'RISK' if litigation_risk else 'No risk'}"
                        if terms:
                            details += f" ({', '.join(terms[:2])})"
                    elif action == "migration":
                        source_path = entry.get("source_path", "Unknown")
                        destination_type = entry.get("destination_type", "Unknown")
                        details = f"{os.path.basename(source_path)} -> {destination_type}"
                    elif action == "error":
                        module = entry.get("module", "Unknown")
                        error_message = entry.get("error_message", "Unknown")
                        details = f"{module}: {error_message[:50]}..."
                    
                    all_entries_table.add_row(timestamp, action, details)
                
                self.console.print(all_entries_table)
            
        except Exception as e:
            self.console.print(f"[bold red]Error reading log file: {str(e)}[/bold red]")
    
    def _run_complete_workflow(self):
        """Run complete workflow"""
        self.console.print("\n[bold cyan]Running Complete Workflow...[/bold cyan]")
        
        # Phase 1: Connect to services
        self.console.print("\n[bold blue]Phase 1: Connect to Services[/bold blue]")
        
        # Connect to Microsoft 365
        if not self.ms_extractor.access_token:
            self.console.print("[bold yellow]Not connected to Microsoft 365.[/bold yellow]")
            self._connect_microsoft()
            
            # Check if connected
            if not self.ms_extractor.access_token:
                self.console.print("[bold red]Failed to connect to Microsoft 365. Workflow terminated.[/bold red]")
                return
        
        # Connect to Google Workspace
        if not self.google_migrator.drive_service or not self.google_migrator.gmail_service:
            self.console.print("[bold yellow]Not connected to Google Workspace.[/bold yellow]")
            self._connect_google()
            
            # Check if connected
            if not self.google_migrator.drive_service or not self.google_migrator.gmail_service:
                self.console.print("[bold red]Failed to connect to Google Workspace. Workflow terminated.[/bold red]")
                return
        
        # Phase 2: Analyze files
        self.console.print("\n[bold blue]Phase 2: Analyze Files[/bold blue]")
        
        # Analyze Microsoft 365 data
        self._analyze_microsoft_data()
        
        # Extract files
        self._extract_files()
        
        # Check if files were extracted
        if not self.extracted_files:
            self.console.print("[bold red]No files were extracted. Workflow terminated.[/bold red]")
            return
        
        # Classify files
        self._classify_files()
        
        # Check if files were classified
        if not self.classified_files:
            self.console.print("[bold red]No files were classified. Workflow terminated.[/bold red]")
            return
        
        # Phase 3: Propose structure
        self.console.print("\n[bold blue]Phase 3: Propose Structure[/bold blue]")
        
        # Generate folder structure
        result = self._generate_folder_structure()
        
        # Check if user approved
        if not result:
            self.console.print("[bold red]Folder structure not approved. Workflow terminated.[/bold red]")
            return
        
        # Phase 4: Execute migration
        self.console.print("\n[bold blue]Phase 4: Execute Migration[/bold blue]")
        
        # Migrate files
        self._migrate_files()
        
        # Workflow complete
        self.console.print("\n[bold green]Complete Workflow Finished Successfully![/bold green]")
    
    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """
        Format size in bytes to human-readable format
        
        Args:
            size_bytes: Size in bytes
            
        Returns:
            str: Human-readable size
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024 or unit == 'TB':
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
