'use strict';

/* 主题在首帧前生效，避免浅色用户看到深色闪烁。
   偏好写在 localStorage：system | dark | light */
(function () {
  const KEY = 'qsecret-theme';
  const mq = window.matchMedia('(prefers-color-scheme: light)');

  function pref() {
    try {
      const v = localStorage.getItem(KEY);
      return v === 'light' || v === 'dark' ? v : 'system';
    } catch {
      return 'system';
    }
  }

  function resolve(p) {
    return p === 'system' ? (mq.matches ? 'light' : 'dark') : p;
  }

  function apply(p) {
    const wanted = p || pref();
    const actual = resolve(wanted);
    document.documentElement.dataset.theme = actual;
    document.documentElement.style.colorScheme = actual;
    window.dispatchEvent(new CustomEvent('qsecret:theme', { detail: { pref: wanted, actual } }));
  }

  window.QsecretTheme = { KEY, pref, resolve, apply };

  apply();

  mq.addEventListener('change', () => {
    if (pref() === 'system') apply('system');
  });
})();
