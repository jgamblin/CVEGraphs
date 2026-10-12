#!/usr/bin/env python3
"""
Record the CVE tornado's growth animation to a shareable GIF and MP4.

Loads graphs/cvenado.html in headless Chromium (Playwright), hides the control
bar, steps the spiral's head one frame at a time while slowly orbiting the
camera, screenshots each frame, then encodes with ffmpeg:

    graphs/cvenado.gif   palette-optimized GIF (Slack, Twitter, email)
    graphs/cvenado.mp4   H.264 (LinkedIn plays video but flattens GIFs)

    python tools/cvenado/build.py        # first, so graphs/cvenado.html is current
    python tools/cvenado/record.py       # ~1 minute
    python tools/cvenado/record.py --preview   # one end-state frame, to check framing

The page is Ben Edwards' template (github.com/empiricalsec/cvenado); this script
only adds a small hook so the head and camera can be set per frame.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "graphs" / "cvenado.html"
OUT_GIF = ROOT / "graphs" / "cvenado.gif"
OUT_MP4 = ROOT / "graphs" / "cvenado.mp4"

W, H = 1080, 1350          # 4:5 portrait, the LinkedIn/phone-friendly frame
FPS = 24
SECONDS = 12               # growth from 2000 to the newest day
HOLD = 2.5                 # seconds to hold the finished spiral
ORBIT = 1.1                # radians of camera orbit over the whole clip
ZOOM = 1.3                 # camera pull-back from the page's tilt view
LIFT = 2.5                 # scene units the camera looks above the spiral's middle
GIF_WIDTH = 720            # downscale for the GIF; MP4 stays full size
GIF_FPS = 16

HOOK = """
window.__cvet = {
  n: () => n,
  setup(zoom, lift) {
    setSpin(false); controls.enableDamping = false; view('tilt');
    // Pull back so the widest coil clears the frame, and look a little higher so the spiral sits under the header.
    const dir = camera.position.clone().sub(controls.target);
    controls.target.y += lift;
    camera.position.copy(controls.target).addScaledVector(dir, zoom);
    controls.update();
    return controls.getAzimuthalAngle();
  },
  frame(k, theta) {
    const dist = camera.position.distanceTo(controls.target), phi = controls.getPolarAngle();
    camera.position.setFromSphericalCoords(dist, phi, theta).add(controls.target);
    controls.update();
    setHead(k);
  },
};
"""
HIDE = "<style>#cvet .controls{display:none !important}</style>"


def prepare(src: Path, dst: Path):
    page = src.read_text()
    anchor = "view('tilt');\n"
    assert anchor in page, "template changed: start-up anchor not found"
    page = page.replace(anchor, anchor + HOOK, 1)
    page = page.replace("</style>", "</style>" + HIDE, 1)
    dst.write_text(page)


def capture(html: Path, frames_dir: Path):
    total = FPS * SECONDS
    hold = int(FPS * HOLD)
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--use-angle=swiftshader", "--enable-unsafe-swiftshader", "--ignore-gpu-blocklist"])
        page = browser.new_page(viewport={"width": W, "height": H}, device_scale_factor=1)
        page.goto(html.as_uri())
        page.wait_for_function("window.__cvet !== undefined")
        page.wait_for_timeout(1500)                       # fonts + first render
        theta0 = page.evaluate("([z, l]) => window.__cvet.setup(z, l)", [ZOOM, LIFT])
        n = page.evaluate("window.__cvet.n()")
        for f in range(total + hold):
            t = min(f, total - 1) / (total - 1)
            k = 1 + round(t * (n - 2))
            theta = theta0 + ORBIT * f / (total + hold - 1)
            page.evaluate("([k, th]) => window.__cvet.frame(k, th)", [k, theta])
            page.evaluate("() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))")
            page.screenshot(path=str(frames_dir / f"f{f:04d}.png"))
            if f % 48 == 0:
                print(f"  frame {f}/{total + hold}", flush=True)
        browser.close()


def encode(frames_dir: Path):
    pattern = str(frames_dir / "f%04d.png")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(FPS), "-i", pattern,
                    "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "20", "-movflags", "+faststart", str(OUT_MP4)], check=True)
    vf = (f"fps={GIF_FPS},scale={GIF_WIDTH}:-1:flags=lanczos,split[s0][s1];"
          "[s0]palettegen=max_colors=128:stats_mode=diff[p];[s1][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(FPS), "-i", pattern,
                    "-vf", vf, "-loop", "0", str(OUT_GIF)], check=True)
    for out in (OUT_MP4, OUT_GIF):
        print(f"wrote {out.relative_to(ROOT)} ({out.stat().st_size / 1e6:.1f} MB)")


def preview(html: Path, out: Path):
    """One screenshot of the finished spiral in the recording framing, for checking layout."""
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--use-angle=swiftshader", "--enable-unsafe-swiftshader", "--ignore-gpu-blocklist"])
        page = browser.new_page(viewport={"width": W, "height": H}, device_scale_factor=1)
        page.goto(html.as_uri())
        page.wait_for_function("window.__cvet !== undefined")
        page.wait_for_timeout(1500)
        theta0 = page.evaluate("([z, l]) => window.__cvet.setup(z, l)", [ZOOM, LIFT])
        n = page.evaluate("window.__cvet.n()")
        page.evaluate("([k, th]) => window.__cvet.frame(k, th)", [n - 1, theta0 + ORBIT])
        page.evaluate("() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))")
        page.screenshot(path=str(out))
        browser.close()
    print(f"wrote {out}")


def main():
    if not PAGE.exists():
        sys.exit("graphs/cvenado.html missing; run tools/cvenado/build.py first")
    work = Path(os.environ.get("CVENADO_WORK") or tempfile.mkdtemp(prefix="cvenado-"))
    frames = work / "frames"
    if frames.exists():
        shutil.rmtree(frames)
    frames.mkdir(parents=True)
    html = work / "cvenado-record.html"
    prepare(PAGE, html)
    if "--preview" in sys.argv:
        return preview(html, work / "preview.png")
    print(f"capturing {FPS * SECONDS + int(FPS * HOLD)} frames at {W}x{H} -> {frames}")
    capture(html, frames)
    encode(frames)


if __name__ == "__main__":
    main()
