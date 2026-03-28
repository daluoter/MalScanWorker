---
phase: quick
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - README.md
  - README.en.md
autonomous: true
requirements: ["README-OPT", "README-EN"]

must_haves:
  truths:
    - "README.md is optimized with accurate architecture reflecting the Go ingest layer"
    - "README.en.md exists as a complete English translation"
    - "Both READMEs cross-link to each other for language switching"
  artifacts:
    - path: "README.md"
      provides: "Optimized Chinese README with updated architecture"
      contains: "ingest"
    - path: "README.en.md"
      provides: "Complete English translation of README"
      contains: "ingest"
  key_links:
    - from: "README.md"
      to: "README.en.md"
      via: "language switch link at top"
      pattern: "README\\.en\\.md"
    - from: "README.en.md"
      to: "README.md"
      via: "language switch link at top"
      pattern: "README\\.md"
---

<objective>
Optimize the project README.md (Chinese) and create a companion English version (README.en.md).

Purpose: The current README is entirely in Traditional Chinese and the architecture diagram is outdated — it doesn't reflect the new Go-based ingest layer completed in v1.0. An English version broadens accessibility for international contributors and users.

Output: Updated README.md + new README.en.md with language-switch links.
</objective>

<execution_context>
@$HOME/.config/opencode/get-shit-done/workflows/execute-plan.md
@$HOME/.config/opencode/get-shit-done/templates/summary.md
</execution_context>

<context>
@README.md
@ingest/go.mod
@frontend/README.md
@backend/README.md
@worker/README.md
</context>

<tasks>

<task type="auto">
  <name>Task 1: Optimize README.md (Chinese) with updated architecture</name>
  <files>README.md</files>
  <action>
Update the existing README.md with the following improvements:

1. **Add language switch link** at the very top:
   ```
   [English](README.en.md) | 繁體中文
   ```

2. **Update the architecture diagram** to include the Go ingest layer. The current diagram shows:
   ```
   User → GitHub Pages (React) → FastAPI → MinIO + Supabase + RabbitMQ
   ```
   It should reflect the new architecture with the Go ingest service sitting between the frontend and backend:
   ```
   User → GitHub Pages (React) → Go Ingest Service → MinIO + RabbitMQ
                                                           ↓
                                       FastAPI (Backend) ← Supabase PostgreSQL
                                                           ↓
                                                      Worker(s) ← clamscan/yara CLI
                                                           ↓
                                                      Supabase (reports)
   ```
   The Go ingest layer (built with chi router, pgx, minio-go, amqp091-go) handles file upload, stores to MinIO, writes job metadata to PostgreSQL, and publishes to RabbitMQ. The FastAPI backend handles job status queries and report retrieval.

3. **Update the tech stack section** to include:
   - **Ingest:** Go 1.25 + chi + pgx + minio-go + amqp091-go (file ingestion layer)

4. **Add ingest-related content to local development section** — add a step for starting the ingest service:
   ```bash
   cd ingest
   go run ./cmd/server
   ```

5. **Update API endpoints table** to clarify which service handles what:
   - POST `/api/v1/files` → handled by Go Ingest Service
   - GET `/api/v1/jobs/{job_id}` → handled by FastAPI
   - GET `/api/v1/reports/{job_id}` → handled by FastAPI

6. **General cleanup**: Ensure consistent formatting, check for any broken references.

Preserve ALL existing content and structure. Only ADD or UPDATE — do not remove any existing sections.
  </action>
  <verify>
    <automated>grep -q "ingest" README.md && grep -q "README.en.md" README.md && echo "PASS" || echo "FAIL"</automated>
  </verify>
  <done>README.md contains updated architecture with Go ingest layer, language switch link, updated tech stack, and ingest dev instructions.</done>
</task>

<task type="auto">
  <name>Task 2: Create README.en.md (English version)</name>
  <files>README.en.md</files>
  <action>
Create README.en.md as a complete English translation of the optimized README.md (from Task 1).

1. **Add language switch link** at the very top:
   ```
   English | [繁體中文](README.md)
   ```

2. **Translate ALL sections** from the optimized Chinese README into natural, idiomatic English. This is NOT a machine-translation dump — write it as if a native English speaker authored it:

   - Project title and description
   - Architecture diagram (keep ASCII art, translate labels)
   - Quick Start (prerequisites, deployment steps)
   - VirtualBox networking note
   - Full deployment steps (all 7 subsections)
   - Cloudflare Tunnel section
   - Local development section (including ghost consumer warning)
   - API endpoints table
   - Tech stack section
   - License

3. **Keep all code blocks, commands, and URLs identical** — only translate surrounding prose and table headers.

4. **Translate warning/tip callouts** (⚠️, 💡, 🔍, 📦) — keep the emoji, translate the text.

5. Match the structure and heading hierarchy of README.md exactly so users can cross-reference between languages.
  </action>
  <verify>
    <automated>test -f README.en.md && grep -q "README.md" README.en.md && grep -q "ingest" README.en.md && echo "PASS" || echo "FAIL"</automated>
  </verify>
  <done>README.en.md exists with complete English translation, language switch link back to README.md, and identical structure to the Chinese version.</done>
</task>

</tasks>

<verification>
- Both README.md and README.en.md exist at project root
- README.md contains "ingest" references (architecture updated)
- Both files cross-link to each other at the top
- README.en.md is in English (no Chinese characters in prose sections)
- Both files have identical section structure
</verification>

<success_criteria>
- README.md is optimized with Go ingest layer in architecture, tech stack, and dev instructions
- README.en.md is a complete, natural English translation
- Both READMEs have language-switch links at the top
- All code blocks and commands are preserved identically in both versions
</success_criteria>

<output>
After completion, create `.planning/quick/260328-tcw-readme-md/260328-tcw-SUMMARY.md`
</output>
