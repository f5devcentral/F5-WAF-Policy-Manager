/**
 * JSON Code Editor & Diff Management for F5 WAF Policies and Logging Profiles
 */

function createCodeEditorHelper() {
  return {
    cmInstance: null,

    init(elementId, initialValue = "", onChangeCallback = null, theme = "material-darker") {
      const textarea = document.getElementById(elementId);
      if (!textarea) return null;

      if (this.cmInstance) {
        this.cmInstance.toTextArea();
        this.cmInstance = null;
      }

      if (window.CodeMirror) {
        const isLarge = (initialValue || "").length > 250000;
        this.cmInstance = window.CodeMirror.fromTextArea(textarea, {
          mode: { name: "javascript", json: true },
          theme: theme,
          lineNumbers: true,
          matchBrackets: !isLarge,
          autoCloseBrackets: !isLarge,
          foldGutter: !isLarge,
          gutters: isLarge ? ["CodeMirror-linenumbers"] : ["CodeMirror-linenumbers", "CodeMirror-foldgutter"],
          tabSize: 2,
          indentUnit: 2,
          lineWrapping: false, // Disabling lineWrapping is crucial for smooth performance on large policies
          viewportMargin: isLarge ? 10 : 10,
        });

        this.cmInstance.setValue(initialValue || "");

        if (onChangeCallback) {
          this.cmInstance.on("change", (cm) => {
            onChangeCallback(cm.getValue());
          });
        }

        this.cmInstance.on("focus", (cm) => {
          cm.refresh();
        });

        this.refresh();
        setTimeout(() => this.refresh(), 50);
      }

      return this.cmInstance;
    },

    setTheme(theme) {
      if (this.cmInstance) {
        this.cmInstance.setOption("theme", theme);
        this.refresh();
      }
    },

    getValue() {
      return this.cmInstance ? this.cmInstance.getValue() : "";
    },

    setValue(val) {
      if (this.cmInstance) {
        const valLen = (val || "").length;
        const isLarge = valLen > 250000;
        this.cmInstance.setOption("lineWrapping", false);
        this.cmInstance.setOption("foldGutter", !isLarge);
        this.cmInstance.setOption("matchBrackets", !isLarge);
        this.cmInstance.setOption("autoCloseBrackets", !isLarge);
        if (isLarge || this.cmInstance.getValue() !== val) {
          this.cmInstance.setValue(val || "");
        }
        this.refresh();
        setTimeout(() => this.refresh(), 30);
      }
    },

    refresh() {
      if (this.cmInstance) {
        this.cmInstance.refresh();
      }
    },

    format() {
      if (!this.cmInstance) return false;
      try {
        const text = this.cmInstance.getValue();
        const parsed = JSON.parse(text);
        const formatted = JSON.stringify(parsed, null, 2);
        this.cmInstance.setValue(formatted);
        this.refresh();
        return true;
      } catch (e) {
        return false;
      }
    },

    computeSimpleDiff(originalText, modifiedText) {
      const origLines = (originalText || "").split("\n");
      const modLines = (modifiedText || "").split("\n");
      const diff = [];

      const max = Math.max(origLines.length, modLines.length);

      // If document is small (<= 1000 lines), standard line-by-line diff
      if (max <= 1000) {
        for (let i = 0; i < max; i++) {
          const o = origLines[i];
          const m = modLines[i];
          if (o === undefined) {
            diff.push({ type: "added", lineNum: i + 1, content: m });
          } else if (m === undefined) {
            diff.push({ type: "removed", lineNum: i + 1, content: o });
          } else if (o !== m) {
            diff.push({ type: "removed", lineNum: i + 1, content: o });
            diff.push({ type: "added", lineNum: i + 1, content: m });
          } else {
            diff.push({ type: "unchanged", lineNum: i + 1, content: o });
          }
        }
        return diff;
      }

      // For large documents (> 1000 lines): summarize / compact unchanged blocks
      // to keep DOM node count low and maintain fast UI rendering
      let unchangedCount = 0;
      const MAX_DIFF_ROWS = 1000;

      for (let i = 0; i < max; i++) {
        if (diff.length >= MAX_DIFF_ROWS) {
          diff.push({
            type: "truncated",
            lineNum: i + 1,
            content: `... Diff truncated: ${max - i} additional lines not shown to keep browser responsive.`,
          });
          break;
        }

        const o = origLines[i];
        const m = modLines[i];

        if (o === m) {
          unchangedCount++;
        } else {
          if (unchangedCount > 0) {
            if (unchangedCount <= 3) {
              for (let k = i - unchangedCount; k < i; k++) {
                diff.push({ type: "unchanged", lineNum: k + 1, content: origLines[k] });
              }
            } else {
              diff.push({
                type: "collapsed",
                lineNum: i,
                content: `... [ ${unchangedCount} unchanged lines collapsed ] ...`,
              });
            }
            unchangedCount = 0;
          }

          if (o === undefined) {
            diff.push({ type: "added", lineNum: i + 1, content: m });
          } else if (m === undefined) {
            diff.push({ type: "removed", lineNum: i + 1, content: o });
          } else {
            diff.push({ type: "removed", lineNum: i + 1, content: o });
            diff.push({ type: "added", lineNum: i + 1, content: m });
          }
        }
      }

      if (unchangedCount > 0 && diff.length < MAX_DIFF_ROWS) {
        if (unchangedCount <= 3) {
          for (let k = max - unchangedCount; k < max; k++) {
            diff.push({ type: "unchanged", lineNum: k + 1, content: origLines[k] });
          }
        } else {
          diff.push({
            type: "collapsed",
            lineNum: max,
            content: `... [ ${unchangedCount} unchanged lines collapsed at end ] ...`,
          });
        }
      }

      if (diff.length === 0) {
        diff.push({ type: "unchanged", lineNum: 1, content: "(No differences detected - policies are identical)" });
      }

      return diff;
    }
  };
}

window.WAF_EDITOR = createCodeEditorHelper();
window.LOG_EDITOR = createCodeEditorHelper();

window.addEventListener("resize", () => {
  if (window.WAF_EDITOR) window.WAF_EDITOR.refresh();
  if (window.LOG_EDITOR) window.LOG_EDITOR.refresh();
});

