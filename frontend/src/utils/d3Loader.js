const D3_CDN_URL = "https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js";

let d3LoadPromise = null;

function loadD3FromCdn() {
  if (typeof window === "undefined" || typeof document === "undefined") {
    return Promise.reject(new Error("D3 loader is only available in browser contexts"));
  }
  if (window.d3) {
    return Promise.resolve(window.d3);
  }
  if (d3LoadPromise) {
    return d3LoadPromise;
  }

  d3LoadPromise = new Promise((resolve, reject) => {
    const existing = document.querySelector("script[data-porthound-d3='1']");
    if (existing) {
      existing.addEventListener("load", () => resolve(window.d3));
      existing.addEventListener("error", () => reject(new Error("Failed to load D3.js")));
      return;
    }

    const script = document.createElement("script");
    script.src = D3_CDN_URL;
    script.async = true;
    script.defer = true;
    script.dataset.porthoundD3 = "1";
    script.onload = () => {
      if (window.d3) {
        resolve(window.d3);
        return;
      }
      reject(new Error("D3.js loaded but window.d3 is missing"));
    };
    script.onerror = () => reject(new Error("Failed to load D3.js from CDN"));
    document.head.appendChild(script);
  });

  return d3LoadPromise;
}

export { loadD3FromCdn };
