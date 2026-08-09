// Matrix-style rain behind the login card. Simulation is the product, so the reference is the
// point — but it is drawn in the MAYA teal (#4ec9b0) rather than the classic bright green, and
// kept at low opacity, so it reads as the same theme as the rest of the app rather than a
// costume bolted onto it.
//
// Self-contained and defensive: it does nothing at all unless #matrix-rain is on the page, so it
// is safe to load from the global host page alongside every other route.
//
// It re-binds rather than starting once. Blazor prerenders the page, then REPLACES the DOM when
// the interactive circuit connects — so the canvas this script first sees is thrown away a
// moment later. A one-shot start binds to the detached element and silently draws nothing.
(() => {
    'use strict';

    const CHARS = 'アイウエオカキクケコサシスセソタチツテトナニヌネノ0123456789ABCDEF<>[]{}/\\|=+*';
    const FONT_SIZE = 16;
    const TEAL = '#4ec9b0';
    const FRAME_MS = 50;   // ~20fps: the effect wants discrete stepping, not smooth motion.

    // The canvas currently being animated, or null. Identity comparison against the live DOM is
    // what tells us Blazor swapped the element out from under us.
    let active = null;

    function stop() {
        if (!active) {
            return;
        }

        window.cancelAnimationFrame(active.rafId);
        window.removeEventListener('resize', active.resize);
        active = null;
    }

    function attach(canvas) {
        const ctx = canvas.getContext('2d');
        if (!ctx) {
            return;
        }

        let columns = 0;
        let drops = [];
        let lastFrame = 0;

        function resize() {
            // Backing store in device pixels, CSS box in layout pixels — otherwise the glyphs
            // blur on a HiDPI display.
            const dpr = window.devicePixelRatio || 1;
            canvas.width = Math.floor(window.innerWidth * dpr);
            canvas.height = Math.floor(window.innerHeight * dpr);
            canvas.style.width = window.innerWidth + 'px';
            canvas.style.height = window.innerHeight + 'px';
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

            columns = Math.ceil(window.innerWidth / FONT_SIZE);

            // Random start heights so the first frame is already mid-fall, rather than one hard
            // line sweeping down the screen.
            drops = new Array(columns);
            for (let i = 0; i < columns; i++) {
                drops[i] = Math.random() * -100;
            }
        }

        function draw(now) {
            if (!active || active.canvas !== canvas) {
                return;   // superseded; let this loop die.
            }

            active.rafId = window.requestAnimationFrame(draw);

            if (now - lastFrame < FRAME_MS) {
                return;
            }
            lastFrame = now;

            // Translucent wash rather than a clear: this is what leaves the fading tail behind
            // each glyph. It must match the page background or the trails tint over time.
            ctx.fillStyle = 'rgba(17, 17, 17, 0.08)';
            ctx.fillRect(0, 0, window.innerWidth, window.innerHeight);

            ctx.font = FONT_SIZE + 'px "Cascadia Mono", "Consolas", monospace';

            for (let i = 0; i < columns; i++) {
                const char = CHARS[Math.floor(Math.random() * CHARS.length)];
                const lead = Math.random() > 0.975;

                // Leading glyph brighter than its tail, which is what gives the rain direction.
                ctx.fillStyle = lead ? '#d4d4d4' : TEAL;
                ctx.globalAlpha = lead ? 0.55 : 0.28;
                ctx.fillText(char, i * FONT_SIZE, drops[i] * FONT_SIZE);

                if (drops[i] * FONT_SIZE > window.innerHeight && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }

            ctx.globalAlpha = 1;
        }

        active = { canvas: canvas, resize: resize, rafId: 0 };
        resize();
        window.addEventListener('resize', resize);
        active.rafId = window.requestAnimationFrame(draw);
    }

    // Binds whatever #matrix-rain is live right now, and lets go of one that has been replaced or
    // removed. Cheap enough to run on every DOM mutation: an id lookup and a reference compare.
    function sync() {
        const canvas = document.getElementById('matrix-rain');

        if (active && active.canvas !== canvas) {
            stop();
        }

        if (canvas && !active) {
            // Someone who asked the OS for less motion should not get a full-screen animation.
            const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)');
            if (reduced && reduced.matches) {
                return;
            }

            attach(canvas);
        }
    }

    function boot() {
        sync();
        new MutationObserver(sync).observe(document.body, { childList: true, subtree: true });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
