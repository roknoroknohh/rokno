#!/usr/bin/env python3
# rokno_a3 - Terminal UI Module (COLORED + SMART)

import sys
import time
import shutil

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"

class TerminalUI:
    TOTAL_STEPS = 6
    STEP_NAMES = [
        "التحقق من الرابط",
        "WHOIS",
        "تحليل التقنية",
        "HTTPX",
        "جمع الروابط",
        "معالجة + AI"
    ]

    def __init__(self, target: str):
        self.target = target
        self.current_step = 0
        self.start_time = time.time()
        self.terminal_width = shutil.get_terminal_size().columns
        self.bar_width = min(40, self.terminal_width - 35)
        self.step_status = ["pending"] * self.TOTAL_STEPS

    def _color(self, text: str, color: str) -> str:
        return f"{color}{text}{Colors.RESET}"

    def show_banner(self):
        print(self._color("""
╔══════════════════════════════════════════════════════════════╗
║     ██████╗  ██████╗ ██╗  ██╗███╗   ██╗ ██████╗     █████╗ ██████╗ ║
║     ██╔══██╗██╔═══██╗██║ ██╔╝████╗  ██║██╔═══██╗   ██╔══██╗╚════██╗║
║     ██████╔╝██║   ██║█████╔╝ ██╔██╗ ██║██║   ██║   ███████║ █████╔╝║
║     ██╔══██╗██║   ██║██╔═██╗ ██║╚██╗██║██║   ██║   ██╔══██║██╔═══╝ ║
║     ██║  ██║╚██████╔╝██║  ██╗██║ ╚████║╚██████╔╝   ██║  ██║███████╗║
║     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝    ╚═╝  ╚═╝╚══════╝║
║                                                              ║
║     WEB INTELLIGENCE ANALYZER  |  Passive Recon Only         ║
╚══════════════════════════════════════════════════════════════╝""", Colors.CYAN + Colors.BOLD))
        print(self._color(f"    Target: {self.target}", Colors.YELLOW))
        print(self._color(f"    Mode:   Single Target | ARM64 | Low Resource\n", Colors.DIM))

    def update_progress(self, step_index: int, status: str = "running"):
        self.current_step = step_index
        if status == "done":
            self.step_status[step_index] = "done"
        elif status == "error":
            self.step_status[step_index] = "error"
        elif status == "warning":
            self.step_status[step_index] = "warning"
        else:
            self.step_status[step_index] = "running"

        percent = int(((step_index + (1 if status=="done" else 0)) / self.TOTAL_STEPS) * 100)
        filled = int((percent / 100) * self.bar_width)
        empty = self.bar_width - filled

        bar_color = Colors.GREEN if percent >= 80 else (Colors.YELLOW if percent >= 40 else Colors.BLUE)
        bar = self._color("█" * filled, bar_color) + self._color("░" * empty, Colors.DIM)

        elapsed = time.time() - self.start_time
        if step_index > 0 and status != "done":
            avg = elapsed / max(step_index, 1)
            remaining = avg * (self.TOTAL_STEPS - step_index)
            eta = f"~{int(remaining)}s"
        else:
            eta = "calculating..."

        sys.stdout.write("\r")
        sys.stdout.write(f"  {bar} {self._color(str(percent)+'%', Colors.BOLD + bar_color)}  ETA: {self._color(eta, Colors.DIM)}  ")
        sys.stdout.flush()

    def show_status_list(self):
        print("\n")
        print(self._color("  ┌─────────────────────────────────────────┐", Colors.DIM))
        print(self._color("  │  حالة التنفيذ                           │", Colors.BOLD + Colors.WHITE))
        print(self._color("  ├─────────────────────────────────────────┤", Colors.DIM))

        for i, name in enumerate(self.STEP_NAMES):
            status = self.step_status[i] if i < len(self.step_status) else "pending"

            if status == "done":
                symbol = "✓"
                sym_color = Colors.GREEN
                name_color = Colors.GREEN
            elif status == "error":
                symbol = "✗"
                sym_color = Colors.RED
                name_color = Colors.RED
            elif status == "warning":
                symbol = "⚠"
                sym_color = Colors.YELLOW
                name_color = Colors.YELLOW
            elif status == "running":
                symbol = "►"
                sym_color = Colors.CYAN
                name_color = Colors.CYAN + Colors.BOLD
            else:
                symbol = "○"
                sym_color = Colors.DIM
                name_color = Colors.DIM

            print(f"  │  {self._color(symbol, sym_color)} {self._color(name, name_color):<35} │")

        print(self._color("  └─────────────────────────────────────────┘", Colors.DIM))

    def mark_complete(self, step_index: int, success: bool = True):
        status = "done" if success else "error"
        self.step_status[step_index] = status
        self.update_progress(step_index + 1)

    def mark_warning(self, step_index: int):
        self.step_status[step_index] = "warning"

    def show_final_stats(self):
        elapsed = time.time() - self.start_time
        print(f"\n")
        print(self._color("  ╔═════════════════════════════════════════╗", Colors.GREEN))
        print(self._color("  ║  ✓ التحليل مكتمل!                      ║", Colors.GREEN + Colors.BOLD))
        print(self._color(f"  ║  الوقت: {elapsed:.1f} ثانية{' '*23}║", Colors.WHITE))
        print(self._color(f"  ║  الهدف: {self.target[:30]:<30}║", Colors.WHITE))
        print(self._color("  ╚═════════════════════════════════════════╝", Colors.GREEN))

    def show_critical_alert(self, findings: list):
        if not findings:
            return
        print("\n")
        print(self._color("  ╔═════════════════════════════════════════╗", Colors.RED))
        print(self._color("  ║  ⚠️  تنبيه: معلومات تقنية مهمة         ║", Colors.RED + Colors.BOLD))
        print(self._color("  ╠═════════════════════════════════════════╣", Colors.RED))
        for f in findings[:5]:
            line = f"  ║  ! {f[:38]:<38}║"
            print(self._color(line, Colors.YELLOW))
        print(self._color("  ╚═════════════════════════════════════════╝", Colors.RED))

    def show_info(self, msg: str):
        print(self._color(f"  [i] {msg}", Colors.BLUE))

    def show_success(self, msg: str):
        print(self._color(f"  [✓] {msg}", Colors.GREEN))

    def show_error(self, msg: str):
        print(self._color(f"  [✗] {msg}", Colors.RED))

    def show_warning(self, msg: str):
        print(self._color(f"  [⚠] {msg}", Colors.YELLOW))
