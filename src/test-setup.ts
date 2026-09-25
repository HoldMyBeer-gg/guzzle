// Replace jsdom's broken localStorage (the --localstorage-file warning
// indicates its Storage implementation is non-functional) with a proper
// in-memory implementation. This must run before any test module is imported
// so that Zustand's persist middleware finds a working storage on first load.
const buildLocalStorage = (): Storage => {
  let store: Record<string, string> = {};
  return {
    getItem:    (key)       => store[key] ?? null,
    setItem:    (key, val)  => { store[key] = val; },
    removeItem: (key)       => { delete store[key]; },
    clear:      ()          => { store = {}; },
    get length()            { return Object.keys(store).length; },
    key:        (i)         => Object.keys(store)[i] ?? null,
  };
};

Object.defineProperty(globalThis, "localStorage", {
  value: buildLocalStorage(),
  writable: false,
});
