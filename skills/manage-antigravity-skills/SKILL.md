---
name: manage-antigravity-skills
description: "Provides instructions and CLI context for installing or managing Antigravity skills from this repository. Use when the user wants to add, update, or install new skills into their Antigravity environment."
allowed-tools: Bash, Read, Write
---

# Manage Antigravity Skills

This skill helps you manage and install Antigravity skills stored in this repository into your global Antigravity configuration.

## Installing Skills via CLI

A CLI script is provided at the root of the project to help you install these skills into your Antigravity environment (`~/.gemini/config/skills`).

### Usage

To install a single skill:
```bash
python add_antigravity_skill.py skills/recon
```

To install all skills in a directory:
```bash
python add_antigravity_skill.py skills --all
```

To overwrite existing skills without prompting:
```bash
python add_antigravity_skill.py skills --all --overwrite
```

## How It Works

Antigravity automatically discovers skills placed in its global customizations root (`~/.gemini/config/skills/`) or workspace customizations root (`.agents/skills/`). The provided script simply copies the skill directories from this project to the global customizations root, making them instantly available to your agent.

Each skill must contain a `SKILL.md` file with YAML frontmatter specifying its `name` and `description`.
