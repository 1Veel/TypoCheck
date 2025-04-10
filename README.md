**GitHub Comprehensive Typo Scanner**

A Python-based desktop GUI application that scans all your accessible GitHub repositories for typos in documentation and text-based files. Designed with developers in mind, it intelligently ignores programming-related terms while checking for spelling mistakes.
🚀 Features

    ✅ Scans all repositories you have access to via GitHub API

    ✅ Ignores code-heavy and configuration files

    ✅ Smart spellchecking with support for tech-specific dictionaries

    ✅ Highlights typos with contextual line numbers

    ✅ User-friendly PyQt5 interface

    ✅ Real-time scanning progress with a progress bar

📸 Screenshot

![image](https://github.com/user-attachments/assets/22de98bd-7246-4a22-bc31-e791690b741b)

🔧 Installation
Requirements

    Python 3.7+

    GitHub access token (with repo read permissions)

    PyQt5

    PyGithub

    pyspellchecker

Setup

git clone https://github.com/yourusername/github-typo-scanner.git
cd github-typo-scanner
pip install -r requirements.txt

or you can install manually:

pip install PyQt5 PyGithub pyspellchecker

🧠 How It Works

    Login: Enter your GitHub personal access token.

    Scan: The app fetches all your non-fork repositories.

    Typo Detection:

        Only scans documentation files (.md, .txt, .rst, .docx, etc.)

        Ignores programming and config files

        Uses a custom dictionary to ignore common tech terms (api, url, kwargs, etc.)

    Results:

        Shows repository, file, typo word, and line number

        Click on a typo to view its context

📂 File Types Scanned

    .md, .txt, .rst, .adoc, .docx, .log, .readme, .wiki, etc.

⛔ Files Ignored

    Source code (.py, .js, .html, etc.)

    Config files (requirements.txt, .yaml, .json, etc.)

    License and Docker-related files

📌 Custom Dictionary

The app includes a built-in ignore list for common tech/programming terms. You can expand this by modifying the load_custom_dictionaries() method in RepositoryTypoScannerThread.
🖥️ Usage

Run the app with:

python typochecker.py

🛡️ Security Note

Your GitHub token is never stored or transmitted elsewhere. It's used only locally to authenticate and retrieve repository content via the GitHub API.
🙋‍♀️ Contributions

Feel free to open issues or PRs for new features, bug fixes, or dictionary improvements!
📄 License

MIT License
