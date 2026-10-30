import { syncStory } from './sync-story';

type StoryRoot = HTMLElement & { storyController?: AbortController };

function initializeStories() {
  document.querySelectorAll<StoryRoot>('[data-sync-story]').forEach((root) => {
    if (root.storyController && !root.storyController.signal.aborted) return;
    const controller = new AbortController();
    root.storyController = controller;
    const { signal } = controller;
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
    const play = root.querySelector<HTMLButtonElement>('[data-play]')!;
    const next = root.querySelector<HTMLButtonElement>('[data-next]')!;
    const title = root.querySelector<HTMLElement>('[data-title]')!;
    const detail = root.querySelector<HTMLElement>('[data-detail]')!;
    const logs = root.querySelector<HTMLElement>('[data-logs]')!;
    const steps = root.querySelectorAll<HTMLButtonElement>('[data-step]');
    let index = reducedMotion.matches ? syncStory.length - 1 : 0;
    let playing = !reducedMotion.matches;
    let inView = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let typingTimer: ReturnType<typeof setTimeout> | undefined;

    const stopTimers = () => {
      clearTimeout(timer);
      clearTimeout(typingTimer);
    };

    const draw = (animate = false) => {
      clearTimeout(typingTimer);
      const frame = syncStory[index];
      root.dataset.phase = String(index);
      root.dataset.connection = frame.connection;
      title.textContent = frame.label;
      detail.textContent = frame.detail;
      logs.replaceChildren(...frame.logs.map((line) => {
        const code = document.createElement('code');
        code.textContent = line;
        return code;
      }));
      steps.forEach((step, stepIndex) => {
        step.disabled = false;
        if (stepIndex === index) step.setAttribute('aria-current', 'step');
        else step.removeAttribute('aria-current');
      });
      for (const side of ['a', 'b'] as const) {
        const badge = root.querySelector<HTMLElement>(`[data-network="${side}"]`)!;
        const connection = side === 'a' ? 'online' : frame.connection;
        badge.dataset.connection = connection;
        badge.textContent = connection === 'offline'
          ? '○ Offline'
          : connection === 'syncing' ? '↔ Syncing' : '● Online';
      }
      const field = index === 1 ? 'title' : 'status';
      const typing = animate && (index === 1 || index === 3);
      const typeState = (count: number) => {
        for (const side of ['a', 'b'] as const) {
          const value: {
            title: string;
            status: string;
            tasks: readonly string[];
          } = { ...frame[side] };
          if (typing) {
            value[field] = value[field].slice(0, count);
          }
          root.querySelector<HTMLElement>(`[data-state="${side}"]`)!.textContent =
            JSON.stringify(value, null, 2);
        }
        if (typing && count < Math.max(frame.a[field].length, frame.b[field].length)) {
          typingTimer = setTimeout(() => typeState(count + 1), 55);
        }
      };
      typeState(animate ? 0 : 100);
      play.textContent = playing ? 'Pause' : index === syncStory.length - 1 ? 'Replay' : 'Play';
      play.setAttribute('aria-label', `${play.textContent} sync story`);
    };

    const schedule = () => {
      clearTimeout(timer);
      if (!playing || !inView || document.hidden || signal.aborted) return;
      timer = setTimeout(() => {
        if (index === syncStory.length - 1) {
          playing = false;
        } else {
          index += 1;
        }
        draw(!reducedMotion.matches);
        schedule();
      }, syncStory[index].duration);
    };

    play.addEventListener('click', () => {
      playing = !playing;
      if (playing && index === syncStory.length - 1) index = 0;
      stopTimers();
      draw();
      schedule();
    }, { signal });
    next.addEventListener('click', () => {
      playing = false;
      index = (index + 1) % syncStory.length;
      stopTimers();
      draw();
    }, { signal });
    steps.forEach((step, stepIndex) => step.addEventListener('click', () => {
      playing = false;
      index = stepIndex;
      stopTimers();
      draw();
    }, { signal }));
    document.addEventListener('visibilitychange', () => {
      stopTimers();
      draw();
      schedule();
    }, { signal });
    reducedMotion.addEventListener('change', () => {
      playing = false;
      stopTimers();
      draw();
    }, { signal });
    const observer = new IntersectionObserver(([entry]) => {
      inView = entry.isIntersecting;
      stopTimers();
      draw();
      schedule();
    });
    observer.observe(root);
    signal.addEventListener('abort', () => {
      stopTimers();
      observer.disconnect();
    }, { once: true });
    root.querySelector<HTMLElement>('[data-controls]')!.hidden = false;
    draw();
  });
}

document.addEventListener('astro:before-swap', () => {
  document.querySelectorAll<StoryRoot>('[data-sync-story]').forEach((root) => {
    root.storyController?.abort();
  });
});
document.addEventListener('astro:page-load', initializeStories);
initializeStories();
