import sys
import re
import base64
import json
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTableWidget, QTableWidgetItem, QTextEdit, 
                             QMessageBox, QProgressBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from github import Github
from spellchecker import SpellChecker

class RepositoryTypoScannerThread(QThread):
    """Background thread for scanning multiple repositories"""
    scan_update = pyqtSignal(dict)
    scan_complete = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    progress_update = pyqtSignal(int, int)

    def __init__(self, github_token):
        super().__init__()
        self.github_token = github_token
        self.spell = SpellChecker()
        
        # Load additional dictionaries and ignore lists
        self.load_custom_dictionaries()

    def load_custom_dictionaries(self):
        """Load custom dictionaries and ignore lists"""
        # Technical terms and common programming words to ignore
        self.programming_ignore_list = {
            'api', 'url', 'config', 'params', 'args', 'kwargs', 'func', 
            'iter', 'init', 'str', 'int', 'bool', 'dict', 'list', 'tuple', 
            'enum', 'async', 'await', 'def', 'class', 'impl', 'impl', 
            'idx', 'res', 'req', 'var', 'val', 'len', 'http', 'https', 
            'localhost', 'json', 'xml', 'html', 'css', 'js', 'py', 
            'uuid', 'jwt', 'auth', 'admin', 'github', 'gitlab', 
            'stackoverflow', 'linux', 'windows', 'macos'
        }
        
        # Add these to the spell checker's known words
        for word in self.programming_ignore_list:
            self.spell.word_frequency.add(word)

    def is_code_like(self, word):
        """
        Determine if a word looks like a variable, function, or code-specific term
        """
        # Check for camelCase, snake_case, and UPPER_CASE
        code_patterns = [
            r'^[a-z]+[A-Z][a-zA-Z]*$',  # camelCase
            r'^[a-z]+(_[a-z]+)+$',       # snake_case
            r'^[A-Z]+(_[A-Z]+)*$',       # UPPER_CASE
            r'^\d+$',                    # Pure numbers
            r'^[a-zA-Z]\w*\d+$',         # Variable with number suffix
        ]
        
        return any(re.match(pattern, word) for pattern in code_patterns)

    def is_valid_file(self, filename):
        """Check if file should be scanned"""
        # List of file extensions to scan
        valid_extensions = [
            '.txt', '.md', '.rst', '.adoc', 
            '.log', '.doc', '.docx', 
            '.readme', '.text', '.wiki'
        ]
        
        # Ignore code-heavy files and configuration files
        ignore_patterns = [
            r'\.(?:py|js|css|html|json|yaml|yml|toml|ini|cfg)$',
            r'requirements\.txt$',
            r'package\.json$',
            r'Dockerfile$',
            r'LICENSE$'
        ]
        
        return (any(filename.lower().endswith(ext) for ext in valid_extensions) and 
                not any(re.search(pattern, filename, re.IGNORECASE) for pattern in ignore_patterns))

    def check_file_for_typos(self, file_content):
        """
        Comprehensive typo checking with programming-aware filtering
        """
        # Normalize content: remove code-like blocks, URLs, etc.
        # Remove markdown code blocks
        file_content = re.sub(r'```[\s\S]*?```', ' ', file_content)
        file_content = re.sub(r'`[^`]+`', ' ', file_content)
        
        # Remove URLs
        file_content = re.sub(r'https?://\S+', ' ', file_content)
        
        # Extract words, preserving case
        words = re.findall(r'\b\w+\b', file_content)
        
        # Filter out code-like words and very short words
        filtered_words = [
            word for word in words 
            if (len(word) > 2 and 
                not self.is_code_like(word) and 
                word.lower() not in self.programming_ignore_list)
        ]
        
        # Find misspelled words
        misspelled = self.spell.unknown(filtered_words)
        
        # Track typo locations
        typo_locations = {}
        for word in misspelled:
            # Skip words that look like code
            if self.is_code_like(word):
                continue
            
            for match in re.finditer(r'\b' + re.escape(word) + r'\b', file_content):
                line_number = file_content[:match.start()].count('\n') + 1
                typo_locations[word] = {
                    'line': line_number,
                    'context': file_content[max(0, match.start()-30):min(len(file_content), match.end()+30)]
                }
        
        return typo_locations

    def run(self):
        """Scan multiple repositories"""
        try:
            # Initialize GitHub connection
            g = Github(self.github_token)
            
            # Get all repositories user has access to
            all_repos = list(g.get_user().get_repos())
            
            # Tracking results
            global_typos = {}
            
            # Scan progress
            for repo_index, repo in enumerate(all_repos, 1):
                try:
                    # Emit progress
                    self.progress_update.emit(repo_index, len(all_repos))
                    
                    # Skip forks and limit to repositories owned by the user
                    if repo.fork:
                        continue
                    
                    # Scan repository
                    typos_found = {}
                    
                    def scan_directory(contents_path=''):
                        try:
                            contents = repo.get_contents(contents_path)
                            
                            for content in contents:
                                if content.type == 'dir':
                                    scan_directory(content.path)
                                elif content.type == 'file':
                                    # Only check specific file types
                                    if self.is_valid_file(content.path):
                                        try:
                                            file_content = base64.b64decode(content.content).decode('utf-8')
                                            file_typos = self.check_file_for_typos(file_content)
                                            
                                            if file_typos:
                                                typos_found[content.path] = file_typos
                                        except Exception as e:
                                            print(f"Error reading file {content.path}: {e}")
                        except Exception as e:
                            print(f"Error scanning directory {contents_path}: {e}")
                    
                    # Start scanning
                    scan_directory()
                    
                    # Update global typos if any found
                    if typos_found:
                        global_typos[repo.full_name] = typos_found
                        
                    # Emit partial results for each repo
                    self.scan_update.emit({repo.full_name: typos_found})
                
                except Exception as repo_error:
                    print(f"Error scanning repository {repo.full_name}: {repo_error}")
            
            # Final emission of all results
            self.scan_complete.emit(global_typos)
        
        except Exception as e:
            self.error_occurred.emit(str(e))

class GitHubTypoFinderApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('GitHub Comprehensive Typo Scanner')
        self.setGeometry(100, 100, 1000, 700)

        # Central Widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)

        # Input Section
        input_layout = QHBoxLayout()
        
        # GitHub Token Input
        token_label = QLabel('GitHub Token:')
        self.token_input = QLineEdit()
        self.token_input.setEchoMode(QLineEdit.Password)
        input_layout.addWidget(token_label)
        input_layout.addWidget(self.token_input)

        # Scan Button
        self.scan_button = QPushButton('Scan All Repositories')
        self.scan_button.clicked.connect(self.start_scan)
        input_layout.addWidget(self.scan_button)

        main_layout.addLayout(input_layout)

        # Progress Bar
        self.progress_bar = QProgressBar()
        main_layout.addWidget(self.progress_bar)

        # Results Table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(['Repository', 'File', 'Typo', 'Line'])
        self.results_table.itemClicked.connect(self.show_typo_details)
        main_layout.addWidget(self.results_table)

        # Context Display
        self.context_display = QTextEdit()
        self.context_display.setReadOnly(True)
        main_layout.addWidget(self.context_display)

    def start_scan(self):
        token = self.token_input.text()

        if not token:
            QMessageBox.warning(self, 'Input Error', 'Please enter GitHub token')
            return

        # Clear previous results
        self.results_table.setRowCount(0)
        self.context_display.clear()
        self.progress_bar.setValue(0)

        # Start scanning thread
        self.scan_thread = RepositoryTypoScannerThread(token)
        self.scan_thread.scan_update.connect(self.update_results)
        self.scan_thread.scan_complete.connect(self.finalize_scan)
        self.scan_thread.error_occurred.connect(self.handle_scan_error)
        self.scan_thread.progress_update.connect(self.update_progress)
        self.scan_thread.start()

        # Disable scan button during scan
        self.scan_button.setEnabled(False)
        self.scan_button.setText('Scanning...')

    def update_results(self, partial_results):
        """Update results table with partial scan results"""
        current_row = self.results_table.rowCount()
        
        for repo, repo_typos in partial_results.items():
            for file_path, file_typos in repo_typos.items():
                for typo, details in file_typos.items():
                    self.results_table.insertRow(current_row)
                    self.results_table.setItem(current_row, 0, QTableWidgetItem(repo))
                    self.results_table.setItem(current_row, 1, QTableWidgetItem(file_path))
                    self.results_table.setItem(current_row, 2, QTableWidgetItem(typo))
                    self.results_table.setItem(current_row, 3, QTableWidgetItem(str(details['line'])))
                    current_row += 1

        self.results_table.resizeColumnsToContents()

    def update_progress(self, current, total):
        """Update progress bar"""
        progress = int((current / total) * 100)
        self.progress_bar.setValue(progress)

    def finalize_scan(self, final_results):
        """Finalize scan and re-enable UI"""
        self.scan_button.setEnabled(True)
        self.scan_button.setText('Scan All Repositories')
        self.progress_bar.setValue(100)

        if not final_results:
            QMessageBox.information(self, 'Scan Complete', 'No typos found in any repositories!')

    def show_typo_details(self, item):
        """Display detailed context for selected typo"""
        row = item.row()
        repo = self.results_table.item(row, 0).text()
        file_path = self.results_table.item(row, 1).text()
        typo = self.results_table.item(row, 2).text()
        line = self.results_table.item(row, 3).text()

        details = f"Repository: {repo}\n"
        details += f"File: {file_path}\n"
        details += f"Typo: {typo}\n"
        details += f"Line: {line}\n"

        self.context_display.setText(details)

    def handle_scan_error(self, error):
        """Handle and display scan errors"""
        self.scan_button.setEnabled(True)
        self.scan_button.setText('Scan All Repositories')
        QMessageBox.critical(self, 'Scan Error', str(error))

def main():
    app = QApplication(sys.argv)
    ex = GitHubTypoFinderApp()
    ex.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()