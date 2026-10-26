#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Mars Banking Initiative Repository Setup Script
#
# This script creates a realistic git repository for the
# Exposed Local Git Repository demonstration.

"""
Setup script for creating the Mars Banking Initiative git repository.

Creates a git repository with realistic commit history, planted secrets,
and intellectual property for security testing scenarios including:
- T1005 Data from Local System
- T1552 Unsecured Credentials
- T1213 Data from Information Repositories

Usage:
    python scripts/setup_mars_repo.py [target_path]
    
Default target: <repo>/data/projects/mars-banking-initiative (/app/data/projects/mars-banking-initiative in the container)

Note: the application builds this repository itself at start-up (app.py setup_mars_repo()); this script is a standalone variant for rebuilding it by hand (its history has one more commit than app.py's).
"""

import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path


# Source directory containing the repository template files
TEMPLATE_DIR = Path(__file__).parent.parent / "vulnerable_data" / "mars_banking_initiative"

# Default target directory for the exposed repository
DEFAULT_TARGET = Path(__file__).parent.parent / "data" / "projects" / "mars-banking-initiative"


# Commit history to simulate realistic development
COMMITS = [
    {
        "message": "Initial commit - Project Ares scaffolding",
        "author": "Eleanor Blackwood <eleanor.blackwood@gocortex.io>",
        "days_ago": 180,
        "files": ["README.md", "requirements.txt", ".gitignore"]
    },
    {
        "message": "Add SpaceATM core module with dispensing logic",
        "author": "Marcus Chen <marcus.chen@gocortex.io>",
        "days_ago": 150,
        "files": ["src/__init__.py", "src/space_atm.py"]
    },
    {
        "message": "Implement Mars Gateway relay system",
        "author": "Marcus Chen <marcus.chen@gocortex.io>",
        "days_ago": 120,
        "files": ["src/mars_gateway.py"]
    },
    {
        "message": "Add orbital authentication for spacesuit biometrics",
        "author": "Priya Sharma <priya.sharma@gocortex.io>",
        "days_ago": 90,
        "files": ["src/orbital_auth.py"]
    },
    {
        "message": "Implement quantum ledger with QDCP",
        "author": "Eleanor Blackwood <eleanor.blackwood@gocortex.io>",
        "days_ago": 60,
        "files": ["src/quantum_ledger.py"]
    },
    {
        "message": "Add production configuration (DO NOT COMMIT - oops)",
        "author": "Marcus Chen <marcus.chen@gocortex.io>",
        "days_ago": 45,
        "files": ["config/production.yaml", "config/.env.production"]
    },
    {
        "message": "Add credentials file for deployment automation",
        "author": "Simon Sigre <simon@simonsigre.com>",
        "days_ago": 30,
        "files": ["config/credentials.json"]
    },
    {
        "message": "Add SSH keys for Mars Gateway deployment",
        "author": "Marcus Chen <marcus.chen@gocortex.io>",
        "days_ago": 25,
        "files": [".ssh/id_rsa", ".ssh/id_rsa.pub"]
    },
    {
        "message": "Add financial projections and patent strategy docs",
        "author": "Simon Sigre <simon@simonsigre.com>",
        "days_ago": 15,
        "files": ["docs/FINANCIAL_PROJECTIONS.md", "docs/PATENT_STRATEGY.md"]
    },
    {
        "message": "Update README with architecture overview",
        "author": "Eleanor Blackwood <eleanor.blackwood@gocortex.io>",
        "days_ago": 5,
        "files": ["README.md"]
    }
]


def run_git(args: list, cwd: Path, env: dict = None) -> subprocess.CompletedProcess:
    """Run a git command in the specified directory."""
    git_env = os.environ.copy()
    if env:
        git_env.update(env)
    
    result = subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        env=git_env
    )
    
    if result.returncode != 0:
        print(f"Git command failed: git {' '.join(args)}")
        print(f"stderr: {result.stderr}")
    
    return result


def setup_repository(target_path: Path) -> bool:
    """
    Create the Mars Banking Initiative git repository.
    
    Args:
        target_path: Directory where the repository will be created
        
    Returns:
        True if successful, False otherwise
    """
    print(f"Setting up Mars Banking Initiative repository at: {target_path}")
    
    # Create target directory
    target_path.mkdir(parents=True, exist_ok=True)
    
    # Copy template files
    if TEMPLATE_DIR.exists():
        for item in TEMPLATE_DIR.iterdir():
            dest = target_path / item.name
            if item.is_dir():
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(item, dest)
            else:
                shutil.copy2(item, dest)
        print(f"Copied template files from {TEMPLATE_DIR}")
    else:
        print(f"Warning: Template directory not found: {TEMPLATE_DIR}")
        return False
    
    # Remove any existing .git directory
    git_dir = target_path / ".git"
    if git_dir.exists():
        shutil.rmtree(git_dir)
    
    # Initialise git repository
    run_git(["init"], target_path)
    run_git(["config", "user.email", "ares-system@gocortex.io"], target_path)
    run_git(["config", "user.name", "Ares Build System"], target_path)
    
    # Create commits with realistic history
    for commit in COMMITS:
        # Calculate commit date
        commit_date = datetime.now() - timedelta(days=commit["days_ago"])
        date_str = commit_date.strftime("%Y-%m-%dT%H:%M:%S")
        
        # Add files for this commit
        for file_path in commit["files"]:
            full_path = target_path / file_path
            if full_path.exists():
                run_git(["add", file_path], target_path)
        
        # Create commit with author and date
        env = {
            "GIT_AUTHOR_NAME": commit["author"].split("<")[0].strip(),
            "GIT_AUTHOR_EMAIL": commit["author"].split("<")[1].rstrip(">"),
            "GIT_AUTHOR_DATE": date_str,
            "GIT_COMMITTER_NAME": commit["author"].split("<")[0].strip(),
            "GIT_COMMITTER_EMAIL": commit["author"].split("<")[1].rstrip(">"),
            "GIT_COMMITTER_DATE": date_str
        }
        
        run_git(["commit", "-m", commit["message"], "--allow-empty"], target_path, env)
        print(f"Created commit: {commit['message'][:50]}...")
    
    print(f"\nRepository created successfully with {len(COMMITS)} commits")
    print(f"Location: {target_path}")
    
    # Show git log
    result = run_git(["log", "--oneline", "-10"], target_path)
    if result.returncode == 0:
        print("\nRecent commits:")
        print(result.stdout)
    
    return True


def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
    else:
        target = DEFAULT_TARGET
    
    try:
        success = setup_repository(target)
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"Error setting up repository: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
