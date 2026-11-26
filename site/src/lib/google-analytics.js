if (location.hostname === 'peerborne.io') {
  const measurementId = 'G-JMJLN1YM4N';
  window.dataLayer = window.dataLayer || [];
  window.gtag = function gtag() {
    dataLayer.push(arguments);
  };
  gtag('js', new Date());
  gtag('config', measurementId);
  const script = document.createElement('script');
  script.async = true;
  script.src = `https://www.googletagmanager.com/gtag/js?id=${measurementId}`;
  document.head.append(script);

  document.addEventListener('click', (event) => {
    const link =
      event.target instanceof Element ? event.target.closest('a[href]') : null;
    if (link?.hostname === 'try.peerborne.io') {
      gtag('event', 'open_demo', { link_url: link.href });
    }
  });

  let searchTimer;
  document.addEventListener('input', (event) => {
    const input = event.target;
    if (
      !(input instanceof HTMLInputElement) ||
      !input.closest('#starlight__search')
    ) {
      return;
    }
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      const term = input.value.trim();
      if (term.length >= 2) {
        gtag('event', 'search', { search_term: term.slice(0, 100) });
      }
    }, 1500);
  });
}
