(function () {
  function loadJson(url) {
    return fetch(url, { cache: "no-store" })
      .then(function (resp) {
        if (!resp.ok) return null;
        return resp.json();
      })
      .catch(function () {
        return null;
      });
  }

  function renderBadge(frontendCommit, backendCommit) {
    if (!frontendCommit && !backendCommit) {
      return;
    }

    var badge = document.createElement("div");
    badge.className = "deployment-badge";
    badge.setAttribute("aria-label", "Informace o nasazeni");

    var frontLine = document.createElement("div");
    frontLine.textContent = "Hotel Frontend: " + (frontendCommit || "-");
    badge.appendChild(frontLine);

    var backLine = document.createElement("div");
    backLine.textContent = "Hotel Backend: " + (backendCommit || "-");
    badge.appendChild(backLine);

    document.body.appendChild(badge);
  }

  document.addEventListener("DOMContentLoaded", function () {
    Promise.all([
      loadJson("/static/frontend-version.json"),
      loadJson("/api/version"),
    ]).then(function (values) {
      var frontendCommit = values[0] && values[0].frontend_commit;
      var backendCommit = values[1] && values[1].backend_deploy_tag;
      renderBadge(frontendCommit, backendCommit);
    });
  });
})();
