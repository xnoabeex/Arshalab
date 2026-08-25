# web_app.py
"""
Web Interface for TSK-MCP-Forensics
Modern Detective Theme - Sherlock Holmes inspired
"""

import os
import sys
import json
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Optional
import threading

from fastapi import FastAPI, Request, UploadFile, File, Form, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from etl_pipeline import ETLPipeline
from src.parsers import PARSERS
from src.llm.claude_analyzer import ClaudeAnalyzer
from src.llm.opus_analyzer import OpusAnalyzer
from src.llm.groq_analyzer import GroqAnalyzer
from src.llm.deepseek_analyzer import DeepSeekAnalyzer

app = FastAPI(title="ArshaLab", version="2.0.0")


def _build_artifact_checkboxes() -> str:
    """Generate HTML checkboxes from PARSERS registry."""
    # Default-checked artifacts
    default_checked = {"prefetch", "eventlog"}
    lines = []
    for key, parser_cls in PARSERS.items():
        parser = parser_cls.__new__(parser_cls)
        checked = " checked" if key in default_checked else ""
        lines.append(
            f'<label class="flex items-center gap-3 p-2.5 rounded-lg bg-arsha-forest/40 '
            f'hover:bg-arsha-mint/10 cursor-pointer transition-colors">'
            f'<input type="checkbox" value="{key}"{checked} class="artifact-checkbox">'
            f'<span class="text-sm text-white/80">{parser.description}</span></label>'
        )
    return "\n                            ".join(lines)


ARTIFACT_CHECKBOXES_HTML = _build_artifact_checkboxes()

# LLM Analyzer classes mapping
LLM_ANALYZERS = {
    "claude": ClaudeAnalyzer,      # Sonnet 4.5
    "opus": OpusAnalyzer,           # Opus 4.5
    "groq": GroqAnalyzer,
    "deepseek": DeepSeekAnalyzer
}

# Store for active WebSocket connections
active_connections: list = []
# Store for processing status
processing_status = {"status": "idle", "message": "", "progress": 0, "logs": []}
# Store for chat analyzers per session (maintains conversation history)
chat_analyzers: dict = {}
# Track last activity time per session for TTL cleanup
chat_session_timestamps: dict = {}
# Session TTL in seconds (1 hour)
CHAT_SESSION_TTL = 3600


def _cleanup_stale_sessions():
    """Remove chat sessions older than CHAT_SESSION_TTL."""
    now = datetime.now()
    stale_keys = [
        key for key, ts in chat_session_timestamps.items()
        if (now - ts).total_seconds() > CHAT_SESSION_TTL
    ]
    for key in stale_keys:
        chat_analyzers.pop(key, None)
        chat_session_timestamps.pop(key, None)
    if stale_keys:
        print(f"[Chat] Cleaned up {len(stale_keys)} stale sessions")


# HTML template - ArshaLab Digital Forensics Theme
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ArshaLab - Digital Forensics</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        arsha: {
                            dark: '#0a0f0d',
                            darker: '#050807',
                            deep: '#0f2620',
                            forest: '#1a3a2a',
                            pine: '#234d3a',
                            mint: '#10b981',
                            glow: '#34d399',
                            light: '#6ee7b7',
                            text: '#e2e8f0',
                            muted: '#94a3b8',
                        }
                    },
                    fontFamily: {
                        sans: ['Inter', 'system-ui', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace'],
                    },
                }
            }
        }
    </script>
    <style>
        body { font-family: 'Inter', sans-serif; }

        /* Dark forest background */
        .arsha-bg {
            background: linear-gradient(135deg, #0a0f0d 0%, #0f2620 50%, #0a0f0d 100%);
            background-attachment: fixed;
        }

        /* Glass card with green tint */
        .glass-card {
            background: rgba(15, 38, 32, 0.7);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(16, 185, 129, 0.15);
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
        }

        .glass-card-dark {
            background: rgba(10, 15, 13, 0.8);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(16, 185, 129, 0.1);
            border-radius: 12px;
        }

        /* Document card - dark for AI responses */
        .document-card {
            background: linear-gradient(145deg, #1a3a2a 0%, #0f2620 100%);
            border: 1px solid rgba(16, 185, 129, 0.2);
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        }

        /* Green accent border */
        .accent-border {
            border: 1px solid rgba(16, 185, 129, 0.3);
            box-shadow: 0 0 30px rgba(16, 185, 129, 0.08);
        }

        /* Button styles - green gradient */
        .btn-primary {
            background: linear-gradient(135deg, #059669 0%, #10b981 50%, #059669 100%);
            border: 1px solid rgba(16, 185, 129, 0.5);
            color: #ffffff;
            font-weight: 500;
            transition: all 0.3s ease;
        }

        .btn-primary:hover {
            background: linear-gradient(135deg, #10b981 0%, #34d399 50%, #10b981 100%);
            box-shadow: 0 4px 20px rgba(16, 185, 129, 0.4);
            transform: translateY(-2px);
        }

        /* Input styles */
        .input-field {
            background: rgba(10, 15, 13, 0.7);
            border: 1px solid rgba(16, 185, 129, 0.25);
            color: #e2e8f0;
            border-radius: 8px;
            transition: all 0.3s ease;
        }

        .input-field:focus {
            outline: none;
            border-color: #10b981;
            box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.15);
        }

        .input-field::placeholder {
            color: rgba(148, 163, 184, 0.5);
        }

        /* Chat message animations */
        .message-enter {
            animation: messageSlide 0.4s ease-out;
        }

        @keyframes messageSlide {
            from { opacity: 0; transform: translateY(15px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Typing indicator */
        .typing-dot {
            animation: typingBounce 1.2s ease-in-out infinite;
        }
        .typing-dot:nth-child(2) { animation-delay: 0.15s; }
        .typing-dot:nth-child(3) { animation-delay: 0.3s; }

        @keyframes typingBounce {
            0%, 60%, 100% { transform: translateY(0); }
            30% { transform: translateY(-8px); }
        }

        /* Status pulse */
        .status-pulse {
            animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        /* Scrollbar - green theme */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: rgba(15, 38, 32, 0.5); border-radius: 4px; }
        ::-webkit-scrollbar-thumb { background: rgba(16, 185, 129, 0.4); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(16, 185, 129, 0.6); }

        /* Checkbox - green style */
        input[type="checkbox"] {
            appearance: none;
            width: 20px;
            height: 20px;
            border: 2px solid rgba(16, 185, 129, 0.4);
            border-radius: 4px;
            background: rgba(10, 15, 13, 0.7);
            cursor: pointer;
            transition: all 0.2s ease;
        }

        input[type="checkbox"]:hover {
            border-color: #10b981;
            background: rgba(16, 185, 129, 0.1);
        }

        input[type="checkbox"]:checked {
            background: linear-gradient(135deg, #059669 0%, #10b981 100%);
            border-color: #10b981;
        }

        input[type="checkbox"]:checked::after {
            content: '';
            display: block;
            width: 5px;
            height: 10px;
            border: solid #ffffff;
            border-width: 0 2.5px 2.5px 0;
            transform: rotate(45deg) translate(-1px, -1px);
            margin: 1px 0 0 6px;
        }

        /* User message bubble */
        .user-bubble {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(5, 150, 105, 0.25) 100%);
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: 12px 12px 4px 12px;
        }

        /* Logo styling */
        .logo-symbol {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            color: #10b981;
            text-shadow: 0 0 20px rgba(16, 185, 129, 0.5);
        }
    </style>
</head>
<body class="h-full arsha-bg text-arsha-text overflow-hidden">

    <div class="h-screen flex flex-col p-5 gap-4">
        <!-- Header -->
        <header class="glass-card accent-border px-6 py-4">
            <div class="flex items-center justify-between">
                <div class="flex items-center gap-4">
                    <!-- Logo -->
                    <div class="flex items-center justify-center">
                        <span class="logo-symbol text-3xl">◢◤</span>
                    </div>
                    <div>
                        <h1 class="text-xl font-semibold text-white tracking-wide">
                            ARSHALAB
                        </h1>
                        <p class="text-sm text-arsha-mint/70 font-light">Digital Forensics</p>
                    </div>
                </div>

                <!-- Status -->
                <div id="status-badge" class="flex items-center gap-3 px-4 py-2 glass-card-dark">
                    <div class="w-2 h-2 bg-arsha-mint rounded-full status-pulse"></div>
                    <span class="text-sm text-arsha-mint font-medium">System Ready</span>
                </div>
            </div>
        </header>

        <!-- Main Content -->
        <main class="flex-1 flex gap-4 overflow-hidden">
            <!-- Left Panel: Evidence Control -->
            <div class="w-[380px] flex flex-col gap-4">
                <!-- Evidence Upload -->
                <div class="glass-card p-5 flex-shrink-0">
                    <div class="flex items-center gap-3 mb-4">
                        <div class="w-9 h-9 rounded-lg bg-arsha-mint/20 flex items-center justify-center">
                            <svg class="w-5 h-5 text-arsha-mint" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4"/>
                            </svg>
                        </div>
                        <h2 class="text-base font-medium text-white">Evidence Intake</h2>
                    </div>

                    <!-- Drop Zone -->
                    <div id="drop-zone"
                        class="border-2 border-dashed border-arsha-mint/30 rounded-lg p-5 text-center bg-arsha-forest/30 hover:bg-arsha-mint/10 hover:border-arsha-mint/50 transition-all cursor-pointer mb-4"
                        ondragover="handleDragOver(event)"
                        ondragleave="handleDragLeave(event)"
                        ondrop="handleDrop(event)"
                        onclick="document.getElementById('file-input').click()">
                        <input type="file" id="file-input" class="hidden" accept=".E01,.e01,.dd,.raw,.001,.img" onchange="handleFileSelect(event)">
                        <div class="w-12 h-12 mx-auto mb-3 rounded-full bg-arsha-mint/20 flex items-center justify-center">
                            <svg class="w-6 h-6 text-arsha-mint" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
                            </svg>
                        </div>
                        <p class="text-sm font-medium text-white/80">Drop evidence file here</p>
                        <p class="text-xs text-arsha-muted/60 mt-1">E01, DD, RAW, 001, IMG</p>
                    </div>

                    <div id="file-info" class="hidden mb-4 p-3 bg-arsha-mint/10 border border-arsha-mint/30 rounded-lg">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center gap-2">
                                <svg class="w-5 h-5 text-arsha-mint" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                                </svg>
                                <div>
                                    <p id="file-name" class="text-sm font-medium text-arsha-mint"></p>
                                    <p id="file-size" class="text-xs text-arsha-mint/60"></p>
                                </div>
                            </div>
                            <button onclick="clearFile(event)" class="p-1.5 rounded hover:bg-red-500/20 transition-colors">
                                <svg class="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                                </svg>
                            </button>
                        </div>
                    </div>

                    <!-- Path Input -->
                    <div class="mb-4">
                        <label class="block text-xs font-medium text-arsha-muted/70 mb-2 uppercase tracking-wider">Image Path</label>
                        <input type="text" id="image-path"
                            placeholder="C:\\evidence\\image.E01"
                            value="images/test.E01"
                            class="w-full input-field px-4 py-2.5 text-sm font-mono">
                    </div>

                    <!-- Artifact Selection (generated from PARSERS registry) -->
                    <div class="mb-4">
                        <label class="block text-xs font-medium text-arsha-muted/70 mb-3 uppercase tracking-wider">Artifacts to Extract (""" + str(len(PARSERS)) + """ types)</label>
                        <div class="space-y-2 max-h-[320px] overflow-y-auto pr-2">
                            """ + ARTIFACT_CHECKBOXES_HTML + """
                        </div>
                    </div>

                    <!-- Start Button -->
                    <button id="process-btn" onclick="startProcessing()"
                        class="w-full btn-primary font-medium py-3 px-4 rounded-lg flex items-center justify-center gap-2">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                        </svg>
                        <span>Begin Investigation</span>
                    </button>
                </div>

                <!-- Operation Log -->
                <div class="flex-1 glass-card p-4 overflow-hidden flex flex-col">
                    <div class="flex items-center gap-2 mb-3">
                        <svg class="w-4 h-4 text-arsha-mint" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                        </svg>
                        <h3 class="text-xs font-medium text-arsha-muted/70 uppercase tracking-wider">Activity Log</h3>
                    </div>
                    <div id="log-container" class="flex-1 bg-arsha-dark/60 rounded-lg p-3 overflow-y-auto font-mono text-xs">
                        <div class="text-arsha-muted/40">[System] Awaiting instructions...</div>
                    </div>
                </div>
            </div>

            <!-- Right Panel: Investigation Chat -->
            <div class="flex-1 glass-card accent-border flex flex-col overflow-hidden">
                <!-- Chat Header -->
                <div class="px-5 py-4 border-b border-arsha-mint/15 flex items-center justify-between">
                    <div class="flex items-center gap-3">
                        <div class="flex items-center justify-center">
                            <span class="logo-symbol text-2xl">◢◤</span>
                        </div>
                        <div>
                            <h2 class="text-base font-medium text-white">Investigation Assistant</h2>
                            <p class="text-xs text-arsha-muted/50">AI-Powered Forensic Analysis</p>
                        </div>
                    </div>
                    <div class="flex items-center gap-3">
                        <!-- Case Selector -->
                        <div class="flex items-center gap-2">
                            <span class="text-xs text-arsha-muted/50">Case:</span>
                            <select id="case-selector" onchange="switchCase()"
                                class="px-3 py-1.5 rounded-lg bg-arsha-forest/60 border border-arsha-mint/20 text-xs text-arsha-text cursor-pointer focus:outline-none focus:border-arsha-mint/50">
                                <option value="">All Cases</option>
                            </select>
                        </div>
                        <!-- LLM Provider Selector -->
                        <div class="flex items-center gap-2">
                            <span class="text-xs text-arsha-muted/50">LLM:</span>
                            <select id="llm-provider" onchange="switchLLM()"
                                class="px-3 py-1.5 rounded-lg bg-arsha-forest/60 border border-arsha-mint/20 text-xs text-arsha-text cursor-pointer focus:outline-none focus:border-arsha-mint/50">
                                <option value="claude">Claude Sonnet 4.5</option>
                                <option value="opus">Claude Opus 4.5</option>
                                <option value="deepseek">DeepSeek</option>
                                <option value="groq">Groq (Free)</option>
                            </select>
                        </div>
                        <div id="data-status" class="px-3 py-1.5 rounded-lg glass-card-dark flex items-center gap-2 cursor-pointer text-xs" onclick="checkDataStatus()">
                            <svg class="w-3.5 h-3.5 text-arsha-muted/40" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2 1 3 3 3h10c2 0 3-1 3-3V7c0-2-1-3-3-3H7c-2 0-3 1-3 3z"/>
                            </svg>
                            <span class="text-arsha-muted/40">Loading...</span>
                        </div>
                        <div id="chat-status" class="px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center gap-2">
                            <div class="w-1.5 h-1.5 bg-amber-400 rounded-full"></div>
                            <span class="text-xs text-amber-400">Standby</span>
                        </div>
                    </div>
                </div>

                <!-- Chat Messages -->
                <div id="chat-messages" class="flex-1 overflow-y-auto p-5 space-y-4">
                    <!-- Welcome message -->
                    <div class="message-enter flex items-start gap-3">
                        <div class="flex items-center justify-center flex-shrink-0">
                            <span class="logo-symbol text-xl">◢◤</span>
                        </div>
                        <div class="document-card px-4 py-3 max-w-[85%]">
                            <p class="text-arsha-text font-semibold text-base mb-2">Welcome to ArshaLab</p>
                            <p class="text-arsha-muted text-sm leading-relaxed mb-3">
                                I'm your forensic analysis assistant. I can help you investigate digital evidence from Windows disk images.
                            </p>
                            <div class="text-xs text-arsha-muted/70 space-y-1 border-t border-arsha-mint/20 pt-2 mt-2">
                                <p>1. Load your evidence image on the left panel</p>
                                <p>2. Select artifacts to extract and click "Begin Investigation"</p>
                                <p>3. Ask me questions about the evidence or provide case details</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Chat Input -->
                <div class="p-4 border-t border-arsha-mint/15">
                    <div class="text-xs text-white/50 mb-2 px-1">
                        💡 Tip: Ask short questions ("What is the username?") for brief answers, or ask for details ("Reconstruct the complete timeline") for thorough analysis.
                    </div>
                    <div class="flex gap-3">
                        <input type="text" id="chat-input"
                            placeholder="Describe your case or ask a question..."
                            class="flex-1 input-field px-4 py-3 text-sm"
                            onkeypress="if(event.key==='Enter')sendMessage()">
                        <button onclick="sendMessage()"
                            class="btn-primary px-5 py-3 rounded-lg flex items-center gap-2 font-medium">
                            <span>Send</span>
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"/>
                            </svg>
                        </button>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script>
        let ws = null;
        let caseId = 'default';
        let currentLLM = 'claude';

        function switchLLM() {
            const select = document.getElementById('llm-provider');
            currentLLM = select.value;
            addLog(`Switched to ${currentLLM.toUpperCase()} API`, 'info');
        }

        let currentCaseId = '';  // Empty = all cases

        function switchCase() {
            const select = document.getElementById('case-selector');
            currentCaseId = select.value;
            if (currentCaseId) {
                addLog(`Filtering to case: ${currentCaseId}`, 'info');
            } else {
                addLog('Showing all cases', 'info');
            }
        }

        async function loadCases() {
            try {
                const response = await fetch('/api/cases');
                const data = await response.json();
                const select = document.getElementById('case-selector');

                // Clear existing options except first
                select.innerHTML = '<option value="">All Cases</option>';

                if (data.cases && data.cases.length > 0) {
                    data.cases.forEach(c => {
                        const opt = document.createElement('option');
                        opt.value = c.case_id;
                        const label = c.case_name || c.case_id;
                        opt.textContent = `${label} (${c.record_count.toLocaleString()})`;
                        select.appendChild(opt);
                    });
                }
            } catch (e) {
                console.error('Failed to load cases:', e);
            }
        }

        // Load cases on page load
        document.addEventListener('DOMContentLoaded', loadCases);

        async function checkDataStatus() {
            const statusEl = document.getElementById('data-status');
            statusEl.innerHTML = `
                <svg class="w-3.5 h-3.5 text-arsha-muted/40 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <span class="text-arsha-muted/40">Checking...</span>
            `;

            try {
                const response = await fetch('/api/data-status');
                const data = await response.json();

                if (data.elasticsearch_online && data.total_records > 0) {
                    const count = data.total_records.toLocaleString();
                    statusEl.className = 'px-3 py-1.5 rounded-lg bg-arsha-mint/10 border border-arsha-mint/20 flex items-center gap-2 cursor-pointer text-xs';
                    statusEl.innerHTML = `
                        <svg class="w-3.5 h-3.5 text-arsha-mint" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                        </svg>
                        <span class="text-arsha-mint">${count} records</span>
                    `;
                    updateChatStatus(true);
                } else if (data.elasticsearch_online) {
                    statusEl.className = 'px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center gap-2 cursor-pointer text-xs';
                    statusEl.innerHTML = `
                        <svg class="w-3.5 h-3.5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                        </svg>
                        <span class="text-amber-400">No data</span>
                    `;
                } else {
                    statusEl.className = 'px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center gap-2 cursor-pointer text-xs';
                    statusEl.innerHTML = `
                        <svg class="w-3.5 h-3.5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                        </svg>
                        <span class="text-red-400">Offline</span>
                    `;
                }
            } catch (e) {
                statusEl.className = 'px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center gap-2 cursor-pointer text-xs';
                statusEl.innerHTML = `<span class="text-red-400">Error</span>`;
            }
        }

        function connectWebSocket() {
            ws = new WebSocket(`ws://${window.location.host}/ws`);

            ws.onopen = () => {
                console.log('Connected');
                checkDataStatus();
            };

            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                handleMessage(data);
            };

            ws.onclose = () => {
                console.log('Disconnected, reconnecting...');
                setTimeout(connectWebSocket, 2000);
            };
        }

        function handleMessage(data) {
            if (data.type === 'log') {
                addLog(data.message, data.level);
            } else if (data.type === 'status') {
                updateStatus(data.status, data.message);
            } else if (data.type === 'complete') {
                caseId = data.case_id;
                updateChatStatus(true);
                addLog('Investigation data loaded successfully', 'success');
                checkDataStatus();
            } else if (data.type === 'chat_response') {
                addChatMessage(data.message, 'assistant');
                hideTypingIndicator();
            } else if (data.type === 'error') {
                addLog('Error: ' + data.message, 'error');
            }
        }

        function addLog(message, level = 'info') {
            const container = document.getElementById('log-container');
            const colors = {
                'info': 'text-arsha-text/60',
                'success': 'text-arsha-mint',
                'warning': 'text-amber-400',
                'error': 'text-red-400'
            };

            const timestamp = new Date().toLocaleTimeString('en-US', {hour12: false});
            const div = document.createElement('div');
            div.className = `${colors[level] || colors.info} py-0.5`;
            div.innerHTML = `<span class="text-arsha-muted/40">[${timestamp}]</span> ${message}`;
            container.appendChild(div);
            container.scrollTop = container.scrollHeight;
        }

        function updateStatus(status, message) {
            const badge = document.getElementById('status-badge');
            const configs = {
                'idle': { color: 'arsha-mint', text: 'System Ready' },
                'processing': { color: 'amber-400', text: 'Processing...' },
                'complete': { color: 'arsha-mint', text: 'Complete' },
                'error': { color: 'red-400', text: 'Error' }
            };

            const config = configs[status] || configs.idle;
            badge.innerHTML = `
                <div class="w-2 h-2 bg-${config.color} rounded-full ${status === 'processing' ? 'status-pulse' : ''}"></div>
                <span class="text-sm text-${config.color} font-medium">${message || config.text}</span>
            `;
        }

        function updateChatStatus(ready) {
            const status = document.getElementById('chat-status');
            if (ready) {
                status.className = 'px-3 py-1.5 rounded-lg bg-arsha-mint/10 border border-arsha-mint/20 flex items-center gap-2';
                status.innerHTML = '<div class="w-1.5 h-1.5 bg-arsha-mint rounded-full"></div><span class="text-xs text-arsha-mint">Ready</span>';
            }
        }

        function sendMessage() {
            const input = document.getElementById('chat-input');
            const message = input.value.trim();

            if (!message) return;

            addChatMessage(message, 'user');
            input.value = '';
            showTypingIndicator();

            ws.send(JSON.stringify({
                type: 'chat',
                message: message,
                case_id: currentCaseId || caseId,  // Use selected case filter, or ETL case
                llm_provider: currentLLM
            }));
        }

        function addChatMessage(message, role) {
            const container = document.getElementById('chat-messages');
            const isUser = role === 'user';

            const html = isUser ? `
                <div class="message-enter flex items-start gap-3 justify-end">
                    <div class="user-bubble px-4 py-3 max-w-[85%]">
                        <p class="text-arsha-text text-sm leading-relaxed whitespace-pre-wrap">${message}</p>
                    </div>
                    <div class="w-9 h-9 rounded-lg bg-arsha-mint/20 flex items-center justify-center flex-shrink-0 border border-arsha-mint/30">
                        <svg class="w-4 h-4 text-arsha-mint" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                        </svg>
                    </div>
                </div>
            ` : `
                <div class="message-enter flex items-start gap-3">
                    <div class="flex items-center justify-center flex-shrink-0">
                        <span class="logo-symbol text-xl">◢◤</span>
                    </div>
                    <div class="document-card px-4 py-3 max-w-[85%]">
                        <p class="text-arsha-text text-sm leading-relaxed whitespace-pre-wrap">${message}</p>
                    </div>
                </div>
            `;

            container.insertAdjacentHTML('beforeend', html);
            container.scrollTop = container.scrollHeight;
        }

        function showTypingIndicator() {
            const container = document.getElementById('chat-messages');
            const html = `
                <div id="typing-indicator" class="message-enter flex items-start gap-3">
                    <div class="flex items-center justify-center flex-shrink-0">
                        <span class="logo-symbol text-xl">◢◤</span>
                    </div>
                    <div class="glass-card-dark px-4 py-3">
                        <div class="flex items-center gap-2">
                            <span class="text-arsha-muted/70 text-sm">Investigating</span>
                            <span class="flex gap-1">
                                <span class="w-1.5 h-1.5 bg-arsha-mint rounded-full typing-dot"></span>
                                <span class="w-1.5 h-1.5 bg-arsha-mint rounded-full typing-dot"></span>
                                <span class="w-1.5 h-1.5 bg-arsha-mint rounded-full typing-dot"></span>
                            </span>
                        </div>
                    </div>
                </div>
            `;
            container.insertAdjacentHTML('beforeend', html);
            container.scrollTop = container.scrollHeight;
        }

        function hideTypingIndicator() {
            const indicator = document.getElementById('typing-indicator');
            if (indicator) indicator.remove();
        }

        // File handlers
        let uploadedFile = null;

        function handleDragOver(event) {
            event.preventDefault();
            document.getElementById('drop-zone').classList.add('border-arsha-mint/60', 'bg-arsha-mint/20');
        }

        function handleDragLeave(event) {
            event.preventDefault();
            document.getElementById('drop-zone').classList.remove('border-arsha-mint/60', 'bg-arsha-mint/20');
        }

        function handleDrop(event) {
            event.preventDefault();
            handleDragLeave(event);
            if (event.dataTransfer.files.length > 0) {
                processFile(event.dataTransfer.files[0]);
            }
        }

        function handleFileSelect(event) {
            if (event.target.files.length > 0) {
                processFile(event.target.files[0]);
            }
        }

        function processFile(file) {
            const validExts = ['.e01', '.dd', '.raw', '.001', '.img'];
            const fileName = file.name.toLowerCase();
            if (!validExts.some(ext => fileName.endsWith(ext))) {
                addLog('Invalid file format', 'error');
                return;
            }

            uploadedFile = file;
            document.getElementById('drop-zone').classList.add('hidden');
            document.getElementById('file-info').classList.remove('hidden');
            document.getElementById('file-name').textContent = file.name;
            document.getElementById('file-size').textContent = formatFileSize(file.size);
            addLog(`Evidence loaded: ${file.name}`, 'success');
        }

        function clearFile(event) {
            event.stopPropagation();
            uploadedFile = null;
            document.getElementById('file-input').value = '';
            document.getElementById('drop-zone').classList.remove('hidden');
            document.getElementById('file-info').classList.add('hidden');
            addLog('Evidence cleared', 'info');
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        async function uploadFile() {
            if (!uploadedFile) return null;

            const formData = new FormData();
            formData.append('file', uploadedFile);

            addLog('Uploading evidence...', 'info');
            updateStatus('processing', 'Uploading...');

            try {
                const response = await fetch('/upload', { method: 'POST', body: formData });
                if (!response.ok) throw new Error('Upload failed');
                const result = await response.json();
                addLog(`Evidence uploaded: ${result.path}`, 'success');
                return result.path;
            } catch (error) {
                addLog(`Upload error: ${error.message}`, 'error');
                return null;
            }
        }

        async function startProcessing() {
            let imagePath = document.getElementById('image-path').value;

            if (uploadedFile) {
                imagePath = await uploadFile();
                if (!imagePath) {
                    updateStatus('error', 'Upload Failed');
                    return;
                }
            }

            const artifacts = Array.from(document.querySelectorAll('.artifact-checkbox:checked')).map(cb => cb.value);

            if (!imagePath) {
                addLog('Please select evidence first', 'warning');
                return;
            }

            if (artifacts.length === 0) {
                addLog('Select at least one artifact type', 'warning');
                return;
            }

            document.getElementById('log-container').innerHTML = '';

            ws.send(JSON.stringify({
                type: 'start_processing',
                image_path: imagePath,
                artifacts: artifacts
            }));

            updateStatus('processing', 'Investigation Started');
            addLog('Beginning forensic analysis...', 'info');
        }

        connectWebSocket();
    </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def home():
    return HTML_TEMPLATE


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)

    try:
        while True:
            data = await websocket.receive_json()

            if data.get("type") == "start_processing":
                asyncio.create_task(
                    run_etl_pipeline(websocket, data["image_path"], data["artifacts"])
                )

            elif data.get("type") == "chat":
                asyncio.create_task(
                    handle_chat(
                        websocket,
                        data["message"],
                        data.get("case_id"),
                        data.get("llm_provider", "claude")
                    )
                )

    except WebSocketDisconnect:
        active_connections.remove(websocket)
        session_id = id(websocket)
        if session_id in chat_analyzers:
            del chat_analyzers[session_id]


async def _safe_send(websocket: WebSocket, data: dict) -> bool:
    """Send JSON to websocket, return False if client disconnected."""
    try:
        await websocket.send_json(data)
        return True
    except Exception:
        return False


async def run_etl_pipeline(websocket: WebSocket, image_path: str, artifacts: list):
    """Run ETL pipeline with progress updates. Pipeline continues even if client disconnects."""
    import queue
    import concurrent.futures
    import requests
    from pathlib import Path

    log_queue = queue.Queue()
    client_connected = True

    # Validate image_path
    resolved_path = Path(image_path).resolve()
    if not resolved_path.exists():
        await _safe_send(websocket, {
            "type": "error",
            "message": f"Image file not found: {image_path}"
        })
        return

    # Validate artifacts list
    from src.parsers import PARSERS as VALID_PARSERS
    valid_artifacts = [a for a in artifacts if a in VALID_PARSERS]
    if not valid_artifacts:
        await _safe_send(websocket, {
            "type": "error",
            "message": "No valid artifact types selected"
        })
        return
    artifacts = valid_artifacts

    # Check if this image was already processed
    image_name = resolved_path.name
    es_url = "http://localhost:9200"

    await _safe_send(websocket, {
        "type": "log",
        "message": f"Checking if {image_name} was already analyzed...",
        "level": "info"
    })

    # Check existing data (info only, don't skip processing)
    try:
        r = requests.get(f"{es_url}/forensic-*/_count", timeout=5)
        if r.status_code == 200:
            total_records = r.json().get("count", 0)
            if total_records > 0:
                await _safe_send(websocket, {
                    "type": "log",
                    "message": f"Found {total_records:,} existing records in database",
                    "level": "info"
                })
    except Exception:
        pass  # Ignore ES check errors

    await _safe_send(websocket, {
        "type": "log",
        "message": f"Analyzing: {image_path}",
        "level": "info"
    })

    output_dir = "output/web_pipeline"

    def status_callback(msg):
        log_queue.put(msg)

    # Use image filename (without extension) as case name
    case_name = resolved_path.stem

    def run_pipeline():
        pipeline = ETLPipeline(
            image_path=image_path,
            output_dir=output_dir,
            artifacts=artifacts,
            es_url="http://localhost:9200",
            case_name=case_name
        )
        pipeline.run(status_callback=status_callback)
        return pipeline.case_id

    pipeline_error = None
    case_id = None

    try:
        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = loop.run_in_executor(executor, run_pipeline)

            # Poll for log messages while pipeline runs
            while not future.done():
                while not log_queue.empty():
                    try:
                        msg = log_queue.get_nowait()
                        if client_connected:
                            sent = await _safe_send(websocket, {
                                "type": "log",
                                "message": msg,
                                "level": "info"
                            })
                            if not sent:
                                client_connected = False
                                print(f"[Pipeline] Client disconnected, pipeline continues in background")
                    except queue.Empty:
                        break
                await asyncio.sleep(0.1)

            # Get pipeline result (may raise if pipeline failed)
            case_id = await future

            # Drain remaining log messages
            while not log_queue.empty():
                try:
                    msg = log_queue.get_nowait()
                    if client_connected:
                        sent = await _safe_send(websocket, {
                            "type": "log",
                            "message": msg,
                            "level": "info"
                        })
                        if not sent:
                            client_connected = False
                except queue.Empty:
                    break

    except Exception as e:
        pipeline_error = str(e)
        print(f"[Pipeline] Error: {pipeline_error}")

    # Send completion/error status (only if client still connected)
    if client_connected:
        if pipeline_error:
            await _safe_send(websocket, {
                "type": "error",
                "message": pipeline_error
            })
            await _safe_send(websocket, {
                "type": "status",
                "status": "error",
                "message": "Error"
            })
        else:
            await _safe_send(websocket, {
                "type": "complete",
                "case_id": case_id,
                "message": "Investigation complete"
            })
            await _safe_send(websocket, {
                "type": "status",
                "status": "complete",
                "message": "Complete"
            })
    else:
        if pipeline_error:
            print(f"[Pipeline] Completed with error (client disconnected): {pipeline_error}")
        else:
            print(f"[Pipeline] Completed successfully (client disconnected): case_id={case_id}")


async def handle_chat(websocket: WebSocket, message: str, case_id: str = None, llm_provider: str = "claude"):
    """Handle chat with LLM - session persists per case_id + provider"""
    try:
        # Cleanup stale sessions periodically
        _cleanup_stale_sessions()

        # Use case_id + provider as session key
        session_key = f"{case_id or 'ws_' + str(id(websocket))}_{llm_provider}"

        # Get analyzer class for selected provider
        AnalyzerClass = LLM_ANALYZERS.get(llm_provider, ClaudeAnalyzer)

        # Create new analyzer if not exists or if provider changed
        if session_key not in chat_analyzers:
            # Pass case_id to analyzer to filter ES queries to this case only
            if llm_provider in ["claude", "opus"]:
                chat_analyzers[session_key] = AnalyzerClass(session_id=session_key, case_id=case_id)
            else:
                chat_analyzers[session_key] = AnalyzerClass(case_id=case_id)
            print(f"[Chat] New {llm_provider.upper()} session: {session_key} (case: {case_id})")
        else:
            print(f"[Chat] Continuing {llm_provider.upper()} session: {session_key}")

        # Update session timestamp
        chat_session_timestamps[session_key] = datetime.now()

        analyzer = chat_analyzers[session_key]

        response = await asyncio.to_thread(
            analyzer.analyze,
            message,
            case_id
        )

        await _safe_send(websocket, {
            "type": "chat_response",
            "message": response
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        await _safe_send(websocket, {
            "type": "chat_response",
            "message": f"Error ({llm_provider}): {str(e)}"
        })


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """Handle file upload with path traversal protection."""
    try:
        images_dir = Path("images").resolve()
        images_dir.mkdir(exist_ok=True)

        # Sanitize filename to prevent path traversal
        safe_name = Path(file.filename).name
        if not safe_name or safe_name.startswith("."):
            return JSONResponse(
                {"status": "error", "message": "Invalid filename"},
                status_code=400
            )

        file_path = (images_dir / safe_name).resolve()

        # Ensure the resolved path is still inside images_dir
        if not str(file_path).startswith(str(images_dir)):
            return JSONResponse(
                {"status": "error", "message": "Invalid file path"},
                status_code=400
            )

        with open(file_path, "wb") as buffer:
            while chunk := await file.read(1024 * 1024):
                buffer.write(chunk)

        return JSONResponse({
            "status": "success",
            "path": str(file_path),
            "filename": safe_name,
            "size": file_path.stat().st_size
        })

    except Exception as e:
        return JSONResponse(
            {"status": "error", "message": str(e)},
            status_code=500
        )


@app.get("/api/status")
async def get_status():
    return {"status": "running", "version": "2.0.0"}


@app.get("/api/artifacts")
async def get_artifacts():
    """Return available artifact types from PARSERS registry."""
    artifacts = []
    for key, parser_cls in PARSERS.items():
        parser = parser_cls.__new__(parser_cls)
        artifacts.append({
            "key": key,
            "name": parser.name,
            "description": parser.description,
            "index_name": parser.index_name,
            "database_table": parser.database_table,
            "field_count": len(parser.fields),
        })
    return {"artifacts": artifacts, "count": len(artifacts)}


@app.get("/api/cases")
async def get_cases():
    """Return available cases with names from Elasticsearch."""
    import requests

    es_url = "http://localhost:9200"
    try:
        body = {
            "size": 0,
            "aggs": {
                "cases": {
                    "terms": {"field": "case_id.keyword", "size": 100},
                    "aggs": {
                        "name": {"terms": {"field": "case_name.keyword", "size": 1}}
                    }
                }
            }
        }
        r = requests.post(f"{es_url}/forensic-*/_search", json=body, timeout=5)
        if r.status_code == 200:
            buckets = r.json().get("aggregations", {}).get("cases", {}).get("buckets", [])
            cases = []
            for b in buckets:
                case = {"case_id": b["key"], "record_count": b["doc_count"]}
                name_buckets = b.get("name", {}).get("buckets", [])
                if name_buckets:
                    case["case_name"] = name_buckets[0]["key"]
                cases.append(case)
            return {"cases": cases, "count": len(cases)}
    except Exception as e:
        return {"cases": [], "count": 0, "error": str(e)}


@app.get("/api/data-status")
async def get_data_status():
    """Check Elasticsearch data for all 13 artifact types"""
    import requests

    es_url = "http://localhost:9200"
    # Index list from PARSERS registry (single source of truth)
    indices = [
        parser_cls.__new__(parser_cls).index_name
        for parser_cls in PARSERS.values()
    ]

    result = {
        "elasticsearch_online": False,
        "total_records": 0,
        "indices": {}
    }

    try:
        r = requests.get(f"{es_url}/_cluster/health", timeout=2)
        if r.status_code == 200:
            result["elasticsearch_online"] = True

        for idx in indices:
            try:
                r = requests.get(f"{es_url}/{idx}/_count", timeout=2)
                if r.status_code == 200:
                    count = r.json().get("count", 0)
                    result["indices"][idx] = count
                    result["total_records"] += count
                else:
                    result["indices"][idx] = 0
            except:
                result["indices"][idx] = 0

    except Exception as e:
        result["error"] = str(e)

    return result


if __name__ == "__main__":
    print("\n" + "="*50)
    print("ArshaLab - Digital Forensics Platform")
    print("="*50)
    print("Starting server at http://localhost:8080")
    print("="*50 + "\n")

    uvicorn.run(app, host="0.0.0.0", port=8080)
