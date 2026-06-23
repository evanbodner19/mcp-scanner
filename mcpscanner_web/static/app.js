fetch("/api/config")
  .then((r) => r.json())
  .then((cfg) => {
    document.getElementById("status").textContent =
      "Connected — version " + cfg.version;
  });
