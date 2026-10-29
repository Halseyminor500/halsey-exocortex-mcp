# ============================================================================
# FILE: server.py (Unified All-in-One Stateless MCP Gateway + Engines)
# Exposes:
#   - /mcp/vault      (Full Exocortex + Docket Clocks + Sub-Agents + Adversarial Engine)
#   - /mcp/whiteboard (Air-Gapped Zero-Context Clean-Room Sandbox)
#   - /mcp/bridge     (Civil/Venture Read-Write + Criminal Read-Only Bridge)
# ============================================================================
import os
import json
import hashlib
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Request, HTTPException
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from supabase import create_client, Client
from openai import OpenAI
import anthropic
from google import genai

# ----------------------------------------------------------------------------
# ENVIRONMENT & CLIENTS INITIALIZATION
# ----------------------------------------------------------------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
BEARER_TOKEN = os.environ.get("EXOCORTEX_BEARER_TOKEN", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

supabase: Optional[Client] = (
    create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None
)
oai_client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None
ant_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY) if ANTHROPIC_API_KEY else None
gem_client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None

MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "00_CANONICAL_TRUTH_MANIFEST.md")
CANONICAL_MANIFEST = ""
if os.path.exists(MANIFEST_PATH):
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        CANONICAL_MANIFEST = f.read()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------------
# SUB-AGENT 500-EMAIL SCANNER & 7-PHASE ADVERSARIAL ENGINE FUNCTIONS
# ----------------------------------------------------------------------------
def execute_subagent_scan(
    search_directive: str,
    case_or_vault: Optional[str] = None,
    sql_keyword_prefilter: Optional[str] = None,
    batch_size: int = 25
) -> Dict[str, Any]:
    if not supabase:
        return {"error": "Supabase client not initialized."}

    query = supabase.table("forensic_messages").select("*")
    if case_or_vault:
        query = query.eq("case_or_vault", case_or_vault)
    if sql_keyword_prefilter:
        query = query.or_(
            f"verbatim_body.ilike.%{sql_keyword_prefilter}%,"
            f"subject_or_summary.ilike.%{sql_keyword_prefilter}%,"
            f"external_id.ilike.%{sql_keyword_prefilter}%"
        )

    candidates = query.limit(500).execute().data or []
    total_scanned = len(candidates)

    if total_scanned == 0:
        return {
            "status": "ZERO_HITS_IN_SQL_PREFILTER",
            "total_records_scanned": 0,
            "search_directive": search_directive,
            "verified_matches": []
        }

    verified_matches = []
    for i in range(0, total_scanned, batch_size):
        batch = candidates[i : i + batch_size]
        compact_batch = [
            {
                "external_id": r["external_id"],
                "channel": r["channel"],
                "date": r["sent_timestamp_utc"],
                "sender": r["sender"],
                "recipient": r["recipient"],
                "sha256": r["sha256_hash"],
                "verbatim_body": r["verbatim_body"]
            }
            for r in batch
        ]
        prompt = (
            f"You are a deterministic forensic extraction sub-agent.\n"
            f"DIRECTIVE: {search_directive}\n\n"
            f"RULES:\n"
            f"1. Inspect the following {len(compact_batch)} records.\n"
            f"2. Return ONLY a JSON array of objects that strictly match the directive.\n"
            f"3. For each match, include: 'external_id', 'date', 'sender', 'exact_verbatim_quote', "
            f"'sha256', and 'relevance_reason'. Never paraphrase quotes.\n\n"
            f"RECORDS:\n{json.dumps(compact_batch)}"
        )

        raw_json = "[]"
        if gem_client:
            resp = gem_client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
            )
            raw_json = resp.text or "[]"
        elif ant_client:
            resp = ant_client.messages.create(
                model="claude-3-5-haiku-latest",
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}]
            )
            raw_json = resp.content[0].text

        start = raw_json.find("[")
        end = raw_json.rfind("]")
        if start != -1 and end != -1:
            try:
                parsed = json.loads(raw_json[start : end + 1])
                if isinstance(parsed, list):
                    verified_matches.extend(parsed)
            except Exception:
                pass

    receipt_hash = sha256_text(json.dumps(verified_matches, sort_keys=True))
    return {
        "status": "SUBAGENT_SCAN_COMPLETE",
        "total_records_scanned": total_scanned,
        "matched_count": len(verified_matches),
        "reading_receipt_sha256": receipt_hash,
        "search_directive": search_directive,
        "verified_matches_with_locators": verified_matches
    }


def _call_claude_opus(system_prompt: str, user_prompt: str) -> str:
    if not ant_client:
        return "[Anthropic API Key not set]"
    msg = ant_client.messages.create(
        model="claude-3-7-sonnet-latest",
        max_tokens=4096,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}]
    )
    return msg.content[0].text


def _call_gpt_frontier(system_prompt: str, user_prompt: str) -> str:
    if not oai_client:
        return "[OpenAI API Key not set]"
    resp = oai_client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
    )
    return resp.choices[0].message.content or ""


def _call_gemini_judge(prompt: str) -> str:
    if not gem_client:
        return "[Gemini API Key not set]"
    resp = gem_client.models.generate_content(
        model="gemini-2.5-pro",
        contents=prompt
    )
    return resp.text or ""


def execute_7_phase_adversarial_engine(
    vault_namespace: str,
    motion_or_decision_title: str,
    case_instructions: str,
    verified_evidence_packet: str
) -> Dict[str, Any]:
    sys_epistemic = (
        "Enforce Halsey Minor's Epistemic Protocol: [U] firsthand statements and [Q] verbatim quotes "
        "with P-locators/Message IDs are ground truth. Never fabricate citations."
    )

    p1_framing = _call_claude_opus(
        sys_epistemic,
        f"PHASE 1 PROMPT ENGINEER: Frame the exact legal/strategic issues, governing standards, and burdens for:\n"
        f"TITLE: {motion_or_decision_title}\nINSTRUCTIONS: {case_instructions}\nEVIDENCE:\n{verified_evidence_packet}"
    )

    r_a = _call_claude_opus(sys_epistemic, f"PHASE 2 INDEPENDENT RESEARCH A:\n{p1_framing}")
    r_b = _call_gpt_frontier(sys_epistemic, f"PHASE 2 INDEPENDENT RESEARCH B:\n{p1_framing}")

    r1_halsey = _call_claude_opus(
        sys_epistemic,
        f"PHASE 3 (R1 HALSEY'S BRIEF): Write the strongest affirmative brief for Halsey Minor.\n"
        f"Framing:\n{p1_framing}\nResearch:\n{r_a}\n{r_b}\nEvidence:\n{verified_evidence_packet}"
    )
    r1_opponent = _call_gpt_frontier(
        sys_epistemic,
        f"PHASE 3 (R1 OPPOSING COUNSEL BRIEF): Attack every weakness in Halsey's position as opposing counsel.\n"
        f"Halsey's R1 Brief:\n{r1_halsey}\nEvidence:\n{verified_evidence_packet}"
    )
    r1_judge = _call_gemini_judge(
        f"PHASE 3 (R1 JUDGE EVALUATION): Evaluate both briefs harshly. Identify what worked, what failed, "
        f"and what vulnerabilities remain.\n\nHALSEY R1:\n{r1_halsey}\n\nOPPONENT R1:\n{r1_opponent}"
    )

    r2_halsey_swapped = _call_gpt_frontier(
        sys_epistemic,
        f"PHASE 4 (R2 HALSEY'S BRIEF - SWAPPED MODEL): You were opposing counsel in R1; now represent Halsey Minor. "
        f"Fortify the brief against every attack raised in R1.\nR1 Judge Notes:\n{r1_judge}\nEvidence:\n{verified_evidence_packet}"
    )
    r2_opponent_swapped = _call_claude_opus(
        sys_epistemic,
        f"PHASE 4 (R2 OPPOSING BRIEF - SWAPPED MODEL): You wrote Halsey's R1 brief; now attack your own prior work "
        f"and R2 Halsey's brief.\nR2 Halsey Brief:\n{r2_halsey_swapped}\nR1 Judge Notes:\n{r1_judge}"
    )
    the_nectar = _call_gemini_judge(
        f"PHASE 4 — PRODUCE 'THE NECTAR': Synthesize the undefeated arguments, exact statutory holdings, "
        f"and verbatim [Q]/[U] evidence that survived two adversarial rounds and model-swapping.\n\n"
        f"R1 Judge:\n{r1_judge}\n\nR2 Halsey:\n{r2_halsey_swapped}\n\nR2 Opponent:\n{r2_opponent_swapped}"
    )

    final_draft_a = _call_claude_opus(
        sys_epistemic,
        f"PHASE 5 (FINAL DRAFT A): Write the complete, filing-ready motion/memo using ONLY surviving arguments in THE NECTAR.\n\n{the_nectar}"
    )
    final_draft_b = _call_gpt_frontier(
        sys_epistemic,
        f"PHASE 5 (FINAL DRAFT B): Write a competing, filing-ready motion/memo using ONLY surviving arguments in THE NECTAR.\n\n{the_nectar}"
    )

    scorecard = _call_gemini_judge(
        f"PHASE 7 — 30-POINT JUDICIAL SCORECARD:\n"
        f"Score Final Draft A and Final Draft B on 6 dimensions (0-5 points each, 30 max):\n"
        f"1. Jurisdiction/Standing  2. Factual Record & [Q]/[U] Precision  3. Issue Preservation  "
        f"4. Statutory/Case Authority  5. Prejudice/Equities  6. Remedy Clarity.\n"
        f"State whether >=22/30 threshold with zero fatal defects is met, and synthesize the best paragraphs.\n\n"
        f"DRAFT A:\n{final_draft_a}\n\nDRAFT B:\n{final_draft_b}"
    )

    compiled_markdown = (
        f"# ADVERSARIAL ENGINE OUTPUT: {motion_or_decision_title}\n"
        f"**Generated UTC:** {datetime.now(timezone.utc).isoformat()}\n\n"
        f"---\n## I. THE NECTAR (Undefeated Core Synthesis)\n{the_nectar}\n\n"
        f"---\n## II. 30-POINT JUDICIAL SCORECARD & COMPARATIVE ANALYSIS\n{scorecard}\n\n"
        f"---\n## III. FINAL DRAFT A (Claude Opus/Sonnet Track)\n{final_draft_a}\n\n"
        f"---\n## IV. FINAL DRAFT B (GPT Track)\n{final_draft_b}\n"
    )

    slug = motion_or_decision_title.lower().replace(" ", "_")[:50]
    file_path = f"adversarial_outputs/{slug}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.md"

    if supabase:
        supabase.table("vault_artifacts").upsert({
            "vault_namespace": vault_namespace,
            "tier": 6,
            "file_path": file_path,
            "title": f"[Adversarial Engine] {motion_or_decision_title}",
            "content_markdown": compiled_markdown,
            "epistemic_tag": "[V]",
            "u_keyboard_edit_locked": False,
            "sha256_hash": sha256_text(compiled_markdown),
            "last_modified_by": "adversarial-motion-engine",
            "updated_at": datetime.now(timezone.utc).isoformat()
        }, on_conflict="vault_namespace,file_path").execute()

    return {
        "status": "ADVERSARIAL_TOURNAMENT_COMPLETE",
        "saved_to_vault": vault_namespace,
        "file_path": file_path,
        "the_nectar_preview": the_nectar[:1500],
        "scorecard_summary": scorecard
    }


# ============================================================================
# CREATE THREE STATELESS MCP SERVERS FOR THE THREE WORKSPACE MODES
# ============================================================================
vault_mcp = FastMCP("Halsey-Exocortex-Vault", stateless_http=True)
whiteboard_mcp = FastMCP("Halsey-CleanRoom-Whiteboard", stateless_http=True)
bridge_mcp = FastMCP("Halsey-CrossVault-Bridge", stateless_http=True)


# ----------------------------------------------------------------------------
# TOOL 1: boot_workspace (Mode-Aware Bootloader)
# ----------------------------------------------------------------------------
@vault_mcp.tool(
    annotations=ToolAnnotations(
        title="Boot Canonical Workspace & Docket Clocks",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def boot_workspace(active_focus: str = "all") -> str:
    """
    Loads Tier 1 Canonical Truth Manifest ([U]/[Q]/[V] rules), Today's Active Statutory Docket Clocks,
    Open Reconciliation Mismatches, and Recent Voice Sparks. Call this first in any Vault session.
    """
    clocks_data, recon_data, sparks_data = [], [], []
    if supabase:
        clocks_res = supabase.table("docket_clocks").select("*").neq("status", "COMPLETED").order("statutory_deadline_date").execute()
        clocks_data = clocks_res.data or []
        recon_res = supabase.table("reconciliation_queue").select("*").eq("status", "OPEN").execute()
        recon_data = recon_res.data or []
        sparks_res = supabase.table("spark_inbox").select("*").order("created_at", desc=True).limit(10).execute()
        sparks_data = sparks_res.data or []

    return json.dumps({
        "mode": "CANONICAL_VAULT_MODE",
        "boot_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "active_focus": active_focus,
        "tier_1_canonical_manifest": CANONICAL_MANIFEST,
        "live_docket_clocks": clocks_data,
        "open_reconciliation_mismatches": recon_data,
        "recent_voice_sparks": sparks_data
    }, indent=2)


@whiteboard_mcp.tool(
    annotations=ToolAnnotations(
        title="Boot Air-Gapped Clean-Room Whiteboard",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def boot_clean_room_whiteboard(whiteboard_id: str = "WB-default") -> str:
    """
    Initializes a zero-context, air-gapped Clean-Room Whiteboard. 
    Intentionally withholds all prior biographical, criminal, and venture files to prevent question bias.
    """
    wb_files = []
    if supabase:
        res = supabase.table("vault_artifacts").select("file_path, title, content_markdown, updated_at").eq("vault_namespace", f"whiteboard/{whiteboard_id}").execute()
        wb_files = res.data or []

    return json.dumps({
        "mode": "AIR_GAPPED_CLEAN_ROOM_WHITEBOARD",
        "whiteboard_namespace": f"whiteboard/{whiteboard_id}",
        "epistemic_instruction": (
            "CLEAN-ROOM MODE ACTIVE: Evaluate the user's question from first principles and primary authorities only. "
            "Do NOT import prior assumptions. Treat user-supplied facts in this session as [U] primary truth."
        ),
        "existing_whiteboard_notes": wb_files
    }, indent=2)


# ----------------------------------------------------------------------------
# TOOL 2: save_spark (Universal iPad Voice Spark Capture - Available in ALL Modes)
# ----------------------------------------------------------------------------
def _save_spark_impl(
    title: str,
    dictated_text: str,
    source_model: str = "iPad-Assistant",
    active_vault: str = "general",
    project_tags: Optional[List[str]] = None
) -> str:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m%d-%H%M%S")
    spark_code = f"SPARK-{now_str}"
    tags = project_tags or []
    record = {
        "spark_code": spark_code,
        "title": title,
        "dictated_text": dictated_text,
        "source_model": source_model,
        "active_vault": active_vault,
        "project_tags": tags,
    }
    if supabase:
        supabase.table("spark_inbox").insert(record).execute()
    return json.dumps({
        "status": "CAPTURED_TO_00_SPARK_INBOX",
        "spark_code": spark_code,
        "confirmation": f"Saved '{title}' ({spark_code}) from {source_model} with tags {tags}. You may immediately resume your current line of thought."
    })

for _mcp in (vault_mcp, whiteboard_mcp, bridge_mcp):
    @_mcp.tool(
        name="save_spark",
        annotations=ToolAnnotations(
            title="Save Tangential Voice Spark to 00_SPARK_INBOX",
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=False,
        )
    )
    def save_spark(
        title: str,
        dictated_text: str,
        source_model: str = "iPad-Assistant",
        active_vault: str = "general",
        project_tags: Optional[List[str]] = None
    ) -> str:
        """
        Captures any tangential realization, product idea, or legal angle dictated mid-session into 00_SPARK_INBOX
        without derailing the current chat. Works across Claude, ChatGPT, and Gemini on iPad.
        """
        return _save_spark_impl(title, dictated_text, source_model, active_vault, project_tags)


# ----------------------------------------------------------------------------
# TOOL 3: search_all_work (Unified Search Across Sparks, Artifacts & Forensics)
# ----------------------------------------------------------------------------
def _search_all_work_impl(query: str, vault_filter: Optional[str] = None) -> str:
    if not supabase:
        return json.dumps({"error": "Supabase not configured."})

    sparks = supabase.table("spark_inbox").select("*").or_(f"title.ilike.%{query}%,dictated_text.ilike.%{query}%").limit(15).execute().data

    art_q = supabase.table("vault_artifacts").select(
        "vault_namespace, tier, file_path, title, content_markdown, epistemic_tag, u_keyboard_edit_locked, sha256_hash, updated_at"
    ).or_(f"title.ilike.%{query}%,content_markdown.ilike.%{query}%")
    if vault_filter:
        art_q = art_q.ilike("vault_namespace", f"%{vault_filter}%")
    artifacts = art_q.limit(15).execute().data

    forensics = supabase.table("forensic_messages").select(
        "case_or_vault, channel, external_id, sent_timestamp_utc, sender, recipient, subject_or_summary, verbatim_body, sha256_hash, spoliation_flag"
    ).or_(f"verbatim_body.ilike.%{query}%,external_id.ilike.%{query}%,subject_or_summary.ilike.%{query}%").limit(20).execute().data

    return json.dumps({
        "query": query,
        "matching_sparks": sparks,
        "matching_vault_artifacts": artifacts,
        "matching_forensic_records": forensics
    }, indent=2)

for _mcp in (vault_mcp, bridge_mcp):
    @_mcp.tool(
        name="search_all_work",
        annotations=ToolAnnotations(
            title="Search All Sparks, Vaults, and Forensic Records",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        )
    )
    def search_all_work(query: str, vault_filter: Optional[str] = None) -> str:
        """
        Searches across 00_SPARK_INBOX, all 7 Vault Tiers, and the Forensic Correspondence Ledger
        by keyword, Gmail Message ID, WhatsApp frame number, or P-locator.
        """
        return _search_all_work_impl(query, vault_filter)


# ----------------------------------------------------------------------------
# TOOL 4: commit_vault_artifact (Respects [U-KEYBOARD-EDIT] Locks)
# ----------------------------------------------------------------------------
def _commit_artifact_impl(
    vault_namespace: str,
    file_path: str,
    title: str,
    content_markdown: str,
    tier: int = 5,
    epistemic_tag: str = "[U]",
    modified_by: str = "ai-assistant",
    set_keyboard_lock: bool = False
) -> str:
    if not supabase:
        return json.dumps({"error": "Supabase not configured."})

    existing = supabase.table("vault_artifacts").select("u_keyboard_edit_locked, sha256_hash").eq(
        "vault_namespace", vault_namespace
    ).eq("file_path", file_path).execute().data
    if existing and existing[0].get("u_keyboard_edit_locked") and modified_by != "halsey-ipad-keyboard":
        file_path = f"{file_path}.ai_draft_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md"

    new_hash = sha256_text(content_markdown)
    payload = {
        "vault_namespace": vault_namespace,
        "tier": tier,
        "file_path": file_path,
        "title": title,
        "content_markdown": content_markdown,
        "epistemic_tag": epistemic_tag,
        "u_keyboard_edit_locked": set_keyboard_lock,
        "sha256_hash": new_hash,
        "last_modified_by": modified_by,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    supabase.table("vault_artifacts").upsert(payload, on_conflict="vault_namespace,file_path").execute()
    return json.dumps({
        "status": "COMMITTED",
        "vault_namespace": vault_namespace,
        "file_path": file_path,
        "sha256_hash": new_hash,
        "u_keyboard_edit_locked": set_keyboard_lock
    }, indent=2)

for _mcp in (vault_mcp, whiteboard_mcp):
    @_mcp.tool(
        name="commit_vault_artifact",
        annotations=ToolAnnotations(
            title="Commit or Update Artifact in Vault / Whiteboard",
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=False,
        )
    )
    def commit_vault_artifact(
        vault_namespace: str,
        file_path: str,
        title: str,
        content_markdown: str,
        tier: int = 5,
        epistemic_tag: str = "[U]",
        modified_by: str = "ai-assistant",
        set_keyboard_lock: bool = False
    ) -> str:
        """
        Saves a document, motion draft, venture memo, or whiteboard note into the canonical repository.
        Automatically preserves [U-KEYBOARD-EDIT] locked files by branching instead of overwriting.
        """
        return _commit_artifact_impl(vault_namespace, file_path, title, content_markdown, tier, epistemic_tag, modified_by, set_keyboard_lock)


# ----------------------------------------------------------------------------
# TOOL 5: promote_or_bridge_whiteboard (Connects Independent Ideas Later)
# ----------------------------------------------------------------------------
@bridge_mcp.tool(
    annotations=ToolAnnotations(
        title="Promote Clean-Room Whiteboard or Bridge Read-Only Vaults",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
@vault_mcp.tool(
    annotations=ToolAnnotations(
        title="Promote Clean-Room Whiteboard or Bridge Read-Only Vaults",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def promote_or_bridge_whiteboard(
    source_whiteboard_or_vault: str,
    target_primary_vault: str,
    attach_read_only_vaults: Optional[List[str]] = None
) -> str:
    """
    Promotes an isolated Clean-Room Whiteboard (e.g. 'whiteboard/WB-judicial-disqualification') into a dedicated
    domain repository (e.g. 'legal/civil-disqualification-24stfl00432') AND optionally attaches read-only bridges
    to other vaults (e.g. ['legal/bhpd-2025-14983']) so timing crossovers can be queried without merging folders.
    """
    if not supabase:
        return json.dumps({"error": "Supabase not configured."})

    bridges = attach_read_only_vaults or []
    rows = supabase.table("vault_artifacts").select("*").eq("vault_namespace", source_whiteboard_or_vault).execute().data
    promoted_files = []
    for row in rows:
        new_payload = {
            "vault_namespace": target_primary_vault,
            "tier": row["tier"],
            "file_path": row["file_path"],
            "title": row["title"],
            "content_markdown": row["content_markdown"],
            "epistemic_tag": row["epistemic_tag"],
            "u_keyboard_edit_locked": row["u_keyboard_edit_locked"],
            "sha256_hash": row["sha256_hash"],
            "last_modified_by": "vault-bridge-promotion",
            "bridged_read_only_vaults": bridges,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        supabase.table("vault_artifacts").upsert(new_payload, on_conflict="vault_namespace,file_path").execute()
        promoted_files.append(row["file_path"])

    return json.dumps({
        "status": "PROMOTED_AND_BRIDGED",
        "primary_read_write_vault": target_primary_vault,
        "bridged_read_only_vaults": bridges,
        "promoted_files": promoted_files
    }, indent=2)


# ----------------------------------------------------------------------------
# TOOL 6: flag_reconciliation (Non-Adversarial Mismatch Logger)
# ----------------------------------------------------------------------------
@vault_mcp.tool(
    annotations=ToolAnnotations(
        title="Flag Internal Document/Date Mismatch for Reconciliation",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=False,
    )
)
def flag_reconciliation(
    category: str,
    vault_domain: str,
    primary_truth_u_or_q: str,
    conflicting_artifact_text: str,
    root_cause_diagnosis: str,
    recommended_remedy: str
) -> str:
    """
    Logs a date, exhibit, or opposing-counsel discrepancy into 12A_RECONCILIATION_QUEUE
    without questioning Halsey Minor's [U] firsthand testimony.
    Valid categories: 'RECONCILE-DATE', 'OPPONENT-DEFECT', 'PROCEDURAL-ALIGN', 'CLARIFY-INTENT', 'ARITHMETIC-OVERRIDE'
    """
    code = f"RECON-{datetime.now(timezone.utc).strftime('%m%d-%H%M%S')}"
    payload = {
        "mismatch_code": code,
        "category": category,
        "vault_domain": vault_domain,
        "primary_truth_u_or_q": primary_truth_u_or_q,
        "conflicting_artifact_text": conflicting_artifact_text,
        "root_cause_diagnosis": root_cause_diagnosis,
        "recommended_remedy": recommended_remedy,
        "status": "OPEN"
    }
    if supabase:
        supabase.table("reconciliation_queue").insert(payload).execute()
    return json.dumps({"status": "LOGGED_FOR_RECONCILIATION", "reconciliation_item": payload}, indent=2)


# ----------------------------------------------------------------------------
# TOOL 7: run_subagent_scan (500-Email / Exhibit Map-Reduce Scanner)
# ----------------------------------------------------------------------------
@vault_mcp.tool(
    annotations=ToolAnnotations(
        title="Run Sub-Agent 500-Email / Exhibit Scan",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def run_subagent_scan(
    search_directive: str,
    case_or_vault: Optional[str] = None,
    sql_keyword_prefilter: Optional[str] = None
) -> str:
    """
    Uses deterministic SQL + cheap sub-agents (Gemini Flash / Haiku) to scan 500+ forensic emails,
    WhatsApp frames, or bank lines and returns a condensed SHA-256 Reading Receipt.
    """
    return json.dumps(execute_subagent_scan(search_directive, case_or_vault, sql_keyword_prefilter), indent=2)


# ----------------------------------------------------------------------------
# TOOL 8: run_adversarial_engine (7-Phase Adversarial Motion Engine)
# ----------------------------------------------------------------------------
@vault_mcp.tool(
    annotations=ToolAnnotations(
        title="Run 7-Phase Adversarial Motion Engine",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True,
    )
)
def run_adversarial_engine(
    vault_namespace: str,
    motion_or_decision_title: str,
    case_instructions: str,
    verified_evidence_packet: str
) -> str:
    """
    Launches the 7-Phase Adversarial Motion Engine (Opus vs. GPT + Gemini Judge, Round 2 Model Swap,
    'The Nectar', and 30-Point Scorecard) and saves the output to the vault.
    """
    return json.dumps(
        execute_7_phase_adversarial_engine(
            vault_namespace, motion_or_decision_title, case_instructions, verified_evidence_packet
        ),
        indent=2
    )


# ============================================================================
# FASTAPI APP MOUNTING ALL THREE STATELESS MCP ENDPOINTS
# ============================================================================
app = FastAPI(title="Halsey Minor Multi-Model Exocortex Gateway")

@app.middleware("http")
async def verify_auth(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)
    if BEARER_TOKEN:
        auth_header = request.headers.get("Authorization", "")
        if auth_header != f"Bearer {BEARER_TOKEN}":
            raise HTTPException(status_code=401, detail="Unauthorized Exocortex Access")
    return await call_next(request)

@app.get("/health")
async def health():
    return {"status": "ok", "date": "2026-10-28", "endpoints": ["/mcp/vault", "/mcp/whiteboard", "/mcp/bridge"]}

app.mount("/mcp/vault", vault_mcp.streamable_http_app())
app.mount("/mcp/whiteboard", whiteboard_mcp.streamable_http_app())
app.mount("/mcp/bridge", bridge_mcp.streamable_http_app())
