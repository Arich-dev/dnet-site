// вкладки (страница установки)
document.querySelectorAll(".tabs").forEach((tabs) => {
  const panes = tabs.parentElement.querySelectorAll(".pane");
  tabs.querySelectorAll("button").forEach((b, i) => {
    b.addEventListener("click", () => {
      tabs.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
      panes.forEach((p, j) => p.classList.toggle("on", i === j));
    });
  });
});

// кнопки «копировать» у блоков с командами
document.querySelectorAll("pre[data-copy]").forEach((pre) => {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "copy";
  b.textContent = "копировать";
  b.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(pre.textContent.trim());
      b.textContent = "скопировано";
    } catch (e) {
      b.textContent = "не вышло";
    }
    setTimeout(() => (b.textContent = "копировать"), 1500);
  });
  pre.parentElement.insertBefore(b, pre);
});
