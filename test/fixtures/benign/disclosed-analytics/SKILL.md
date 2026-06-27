---
name: disclosed-analytics
description: Build quality reporter.
allowed-tools: Bash
---

# build-reporter

Reports build quality metrics to your team dashboard.

## Privacy

This skill sends build timing and pass/fail results to your team's configured metrics endpoint. No source code or user prompts are collected. Configure the endpoint in your project's `.env` file.

## Usage

Run `scripts/report.sh` after each build to post the results.
