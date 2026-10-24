import { getCurrentWindow } from "@tauri-apps/api/window";
import { once } from "@tauri-apps/api/event";
import "./screen-capture.css";

type Point = { x: number; y: number };
type Region = { x: number; y: number; width: number; height: number };

const root = document.querySelector<HTMLDivElement>("#screen-capture-root")!;
root.innerHTML = `
  <main class="selection-shell" aria-label="Screen QR selection">
    <div class="selection-instructions" role="status"><span>Drag to select the QR code. Use arrows to move; Shift + arrows to resize.</span><button class="selection-cancel" type="button">Cancel scan</button></div>
    <div class="selection-box" role="application" tabindex="0" aria-label="QR selection frame">
      <span class="selection-corner corner-tl"></span><span class="selection-corner corner-tr"></span>
      <span class="selection-corner corner-bl"></span><span class="selection-corner corner-br"></span>
      <button class="selection-scan" type="button">Scan QR</button>
    </div>
  </main>`;

const box = root.querySelector<HTMLDivElement>(".selection-box")!;
const shell = root.querySelector<HTMLElement>(".selection-shell")!;
const scan = root.querySelector<HTMLButtonElement>(".selection-scan")!;
const cancel = root.querySelector<HTMLButtonElement>(".selection-cancel")!;
let drawing: { start: Point; initial: Region; mode: "draw" | "move" } | null = null;
let bounds: Region = { x: Math.round(window.innerWidth * 0.3), y: Math.round(window.innerHeight * 0.3), width: Math.round(window.innerWidth * 0.4), height: Math.round(window.innerHeight * 0.4) };

function render() {
  box.style.left = `${bounds.x}px`;
  box.style.top = `${bounds.y}px`;
  box.style.width = `${bounds.width}px`;
  box.style.height = `${bounds.height}px`;
}
function point(event: PointerEvent): Point { return { x: event.clientX, y: event.clientY }; }
function clamp(value: number, min: number, max: number) { return Math.max(min, Math.min(max, value)); }
function setFromCorners(a: Point, b: Point) {
  const x = Math.min(a.x, b.x), y = Math.min(a.y, b.y);
  bounds = { x, y, width: Math.max(40, Math.abs(a.x - b.x)), height: Math.max(40, Math.abs(a.y - b.y)) };
  bounds.x = clamp(bounds.x, 0, Math.max(0, window.innerWidth - 40));
  bounds.y = clamp(bounds.y, 0, Math.max(0, window.innerHeight - 40));
  bounds.width = Math.min(bounds.width, window.innerWidth - bounds.x);
  bounds.height = Math.min(bounds.height, window.innerHeight - bounds.y);
  render();
}
async function submit() {
  if (bounds.width < 40 || bounds.height < 40) return;
  const request: Region = {
    x: Math.round(bounds.x),
    y: Math.round(bounds.y),
    width: Math.round(bounds.width),
    height: Math.round(bounds.height),
  };
  try {
    await getCurrentWindow().emit("screen-capture-region", request);
  } catch (error) {
    await getCurrentWindow().emit("screen-capture-error", error instanceof Error ? error.message : "Could not start screen capture.");
  }
}

shell.addEventListener("pointerdown", (event) => {
  const target = event.target as HTMLElement;
  if (target.closest("button")) return;
  const p = point(event);
  const inside = p.x >= bounds.x && p.x <= bounds.x + bounds.width && p.y >= bounds.y && p.y <= bounds.y + bounds.height;
  drawing = { start: p, initial: { ...bounds }, mode: inside ? "move" : "draw" };
  shell.setPointerCapture(event.pointerId);
  if (!inside) { bounds = { x: p.x, y: p.y, width: 40, height: 40 }; render(); }
});
shell.addEventListener("pointermove", (event) => {
  if (!drawing) return;
  const p = point(event);
  if (drawing.mode === "move") {
    bounds.x = clamp(drawing.initial.x + p.x - drawing.start.x, 0, window.innerWidth - bounds.width);
    bounds.y = clamp(drawing.initial.y + p.y - drawing.start.y, 0, window.innerHeight - bounds.height);
    render();
  } else setFromCorners(drawing.start, p);
});
shell.addEventListener("pointerup", () => { drawing = null; });
scan.addEventListener("click", () => void submit());
cancel.addEventListener("click", () => void cancelSelection());
box.addEventListener("keydown", (event) => {
  if (event.key === "Enter") { event.preventDefault(); void submit(); return; }
  if (event.key === "Escape") { event.preventDefault(); void cancelSelection(); return; }
  const delta = event.shiftKey ? 10 : 2;
  const resize = event.shiftKey;
  if (!["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(event.key)) return;
  event.preventDefault();
  if (resize) {
    if (event.key === "ArrowLeft") bounds.width = Math.max(40, bounds.width - delta);
    if (event.key === "ArrowRight") bounds.width = Math.min(window.innerWidth - bounds.x, bounds.width + delta);
    if (event.key === "ArrowUp") bounds.height = Math.max(40, bounds.height - delta);
    if (event.key === "ArrowDown") bounds.height = Math.min(window.innerHeight - bounds.y, bounds.height + delta);
  } else {
    if (event.key === "ArrowLeft") bounds.x = Math.max(0, bounds.x - delta);
    if (event.key === "ArrowRight") bounds.x = Math.min(window.innerWidth - bounds.width, bounds.x + delta);
    if (event.key === "ArrowUp") bounds.y = Math.max(0, bounds.y - delta);
    if (event.key === "ArrowDown") bounds.y = Math.min(window.innerHeight - bounds.height, bounds.y + delta);
  }
  render();
});

async function cancelSelection() {
  const window = getCurrentWindow();
  try { await window.emit("screen-capture-cancelled"); }
  finally { await window.destroy().catch(() => undefined); }
}

void once("screen-capture-ready", () => {
  requestAnimationFrame(() => {
    render();
    box.focus();
  });
});

void getCurrentWindow().onCloseRequested((event) => {
  event.preventDefault();
  void cancelSelection();
});
render();
box.focus();
