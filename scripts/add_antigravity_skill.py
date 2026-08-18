import argparse
import os
import shutil
from pathlib import Path

ANTIGRAVITY_SKILLS_DIR = Path(os.path.expanduser(r"~\.gemini\config\skills"))

def add_skill(source_path, overwrite=False):
    source_path = Path(source_path).resolve()
    if not source_path.exists():
        print(f"Error: Source path '{source_path}' does not exist.")
        return

    if not source_path.is_dir():
        print(f"Error: Source path '{source_path}' is not a directory.")
        return

    skill_name = source_path.name
    dest_path = ANTIGRAVITY_SKILLS_DIR / skill_name

    if dest_path.exists():
        if not overwrite:
            print(f"Skill '{skill_name}' already exists in Antigravity ({dest_path}).")
            choice = input("Do you want to overwrite it? (y/n): ")
            if choice.lower() != 'y':
                print("Aborting.")
                return
        shutil.rmtree(dest_path)

    try:
        os.makedirs(ANTIGRAVITY_SKILLS_DIR, exist_ok=True)
        shutil.copytree(source_path, dest_path)
        print(f"Successfully added skill '{skill_name}' to Antigravity ({dest_path})")
    except Exception as e:
        print(f"Error adding skill: {e}")

def main():
    parser = argparse.ArgumentParser(description="Add a skill to Antigravity")
    parser.add_argument("skill_dir", help="Path to the skill directory to add (e.g., skills/recon)")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite if the skill already exists")
    parser.add_argument("--all", action="store_true", help="Install all skills from a parent directory")
    args = parser.parse_args()

    if args.all:
        parent_dir = Path(args.skill_dir).resolve()
        if not parent_dir.is_dir():
            print(f"Error: '{parent_dir}' is not a directory.")
            return
        
        for item in parent_dir.iterdir():
            if item.is_dir() and (item / "SKILL.md").exists():
                print(f"Installing {item.name}...")
                add_skill(item, overwrite=args.overwrite)
    else:
        add_skill(args.skill_dir, overwrite=args.overwrite)

if __name__ == "__main__":
    main()
