# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

This is a CS846 course assignment repository for Week 9 (DevReview/Debug). The goal is to document counterexample problems that demonstrate cases where AI-assisted test generation guidelines (specifically for GitHub Copilot) fail, and then propose improved or revised guidelines that succeed.

## Repository Structure

- `feedback.md` — The primary deliverable. A structured document with three sections per problem:
  1. **Task Description** — the programming problem and link to starter code
  2. **Guidelines that didn't work** — a specific guideline (e.g., "Use a fault model") that GitHub Copilot failed to apply correctly, with the failing prompt/output and explanation of why it's sub-optimal
  3. **New/Updated Guidelines that worked** — a revised guideline with prompt, output, and result

- `Week9/A_1/` — Starter code and example tests for Problem A (assigned to Gavin Deane)
- `Week9/B_1/` — Starter code and example tests for Problem B (assigned to Artemiy Vishnyakov)
- `Week9/C_1/` — Starter code and example tests for Problem C (assigned to Savira Umar)

## Workflow

Problems follow a placeholder convention: the `replace_with_problem_X` files in each subdirectory are placeholders to be replaced with the actual problem code and test files.

When adding a problem:
1. Place the function/source code and an example test file in the relevant `Week9/X_1/` directory
2. Fill in the corresponding section of `feedback.md` — task description, failing guideline, and improved guideline

## feedback.md Conventions

- Each problem section documents one guideline that failed (Section 2) and one that worked (Section 3)
- Prompts and AI outputs are quoted inline using blockquotes (`>`)
- The document uses "GitHub Copilot (GPT-5-mini)" as the AI model label for outputs (or update with the actual model used)
- Note the GenAI contribution model used per problem in the starter code section
- The current failing guideline for Problem A is **Guideline 5: Use a fault model (mutation mindset) to Drive Test Adequacy**
