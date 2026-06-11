"""Chạy Attack-Defense Arena UI từ notebook (KHÔNG sửa nội dung notebook).

Exec đúng các cell ĐỊNH NGHĨA của arena theo thứ tự, rồi launch Gradio (share=True).
Bỏ qua các cell demo gọi LLM (utility-run, try_attack mẫu, score mẫu) để khỏi tốn quota;
giáo viên/đối thủ sẽ thao tác trực tiếp trên web UI.
"""
import json
import sys
from pathlib import Path

nb = json.loads(Path("notebooks/attack_defense_arena.ipynb").read_text(encoding="utf-8"))

# Chỉ exec các cell có chứa các định nghĩa cần cho UI (giữ nguyên thứ tự trong notebook).
WHITELIST = [
    "client = genai.Client()",   # §0 setup + client + MODEL
    "def build_system_prompt",    # §1 core: ask_agent, check_leak, SECRET_CODE...
    "def judge_answer",           # §2 utility: run_utility_check
    "DEFENDER_ADDON =",           # §3 defender (đã điền) -> current_system_prompt
    "attack_log = []",            # §4 attack_log, scores, register_team, show_scoreboard
    "def try_attack",             # §5 try_attack
    "def run_regression",         # §6 run_regression, score_defense
    "import gradio as gr",        # §9 build UI + arena_ui.launch(share=True)
]

ns = {}
for c in nb["cells"]:
    if c["cell_type"] != "code":
        continue
    src = "".join(c["source"])
    if not any(m in src for m in WHITELIST):
        continue
    # Bỏ các dòng magic/shell (%pip, !pip ...) — không hợp lệ ngoài notebook.
    src = "\n".join(ln for ln in src.splitlines()
                    if not ln.lstrip().startswith(("%", "!")))
    print(f">>> exec cell starting: {src.strip().splitlines()[0][:60]}", flush=True)
    exec(compile(src, "<arena-cell>", "exec"), ns)
