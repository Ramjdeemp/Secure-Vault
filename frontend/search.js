const SearchModule = (() => {
  function normalize(text) {
    return (text || "")
      .toLowerCase()
      .trim();
  }
  function filterNotes(notes, query) {
    const q = normalize(query);
    if (!q) return notes;
    return notes.filter(note =>
      normalize(note.title).includes(q)
    );
  }
  function attachSearch(inputElement, onSearch) {
    if (!inputElement) return;
    inputElement.addEventListener("input", () => {
      const query = inputElement.value;
      onSearch(query);
    });
  }
  function clearSearch(inputElement, onSearch) {
    if (!inputElement) return;
    inputElement.value = "";
    onSearch("");
  }
  function highlight(text, query) {
    if (!query) return text;
    const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(`(${escaped})`, "gi");
    return text.replace(regex, "<mark>$1</mark>");
  }
  return {
    filterNotes,
    attachSearch,
    clearSearch,
    highlight
  };

})();