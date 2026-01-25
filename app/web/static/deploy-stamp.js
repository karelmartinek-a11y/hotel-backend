(function () {
  function pad2(n) {
    return String(n).padStart(2, "0");
  }

  function formatTag(dt) {
    return "".concat(String(dt.getFullYear()).slice(-2)).concat(pad2(dt.getMonth() + 1)).concat(pad2(dt.getDate())).concat(pad2(dt.getHours())).concat(pad2(dt.getMinutes()));
  }

  function computeFrontTag() {
    var dt = new Date(document.lastModified);
    if (Number.isNaN(dt.getTime())) return "??????";
    return formatTag(dt);
  }

  function createBox(frontTag) {
    var box = document.createElement("div");
    box.style.position = "fixed";
    box.style.top = "8px";
    box.style.right = "8px";
    box.style.zIndex = "9999";
    box.style.fontSize = "11px";
    box.style.fontWeight = "700";
    box.style.color = "#0f172a";
    box.style.background = "rgba(255,255,255,0.4)";
    box.style.border = "1px solid rgba(15,23,42,0.12)";
    box.style.opacity = "0.4";
    box.style.borderRadius = "10px";
    box.style.padding = "6px 10px";
    box.style.boxShadow = "0 8px 20px rgba(0,0,0,0.08)";
    box.style.display = "grid";
    box.style.gap = "4px";
    box.style.pointerEvents = "none";
    box.setAttribute("aria-label", "Informace o nasazení");

    var front = document.createElement("div");
    front.style.display = "flex";
    front.style.gap = "6px";
    front.textContent = "Front: ".concat(frontTag);

    var back = document.createElement("div");
    back.style.display = "flex";
    back.style.gap = "6px";
    back.dataset.backLine = "true";
    back.textContent = "Back: …";

    box.appendChild(front);
    box.appendChild(back);
    return box;
  }

  var frontTag = computeFrontTag();
  var box = createBox(frontTag);
  document.addEventListener("DOMContentLoaded", function () {
    document.body.appendChild(box);
  });

  fetch("/api/version", { cache: "no-store" })
    .then(function (resp) {
      if (!resp.ok) return null;
      return resp.json();
    })
    .then(function (data) {
      var backLine = box.querySelector("[data-back-line]");
      if (!backLine) return;
      var tag = data && typeof data.backend_deploy_tag === "string" ? data.backend_deploy_tag : "???";
      backLine.textContent = "Back: ".concat(tag);
    })
    .catch(function () {
      var backLine = box.querySelector("[data-back-line]");
      if (!backLine) return;
      backLine.textContent = "Back: ???";
    });
})();
