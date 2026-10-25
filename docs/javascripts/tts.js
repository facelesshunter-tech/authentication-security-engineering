(function () {
  "use strict";

  if (!("speechSynthesis" in window) || typeof SpeechSynthesisUtterance === "undefined") {
    return;
  }

  var STORAGE_KEY = "tts-prefs-v1";
  var BLOCK_SELECTOR = "h1, h2, h3, h4, h5, h6, p, li, blockquote, figcaption";
  var SKIP_SELECTOR = "pre, code, details, table, .headerlink, .md-typeset .md-button";

  function loadPrefs() {
    try {
      var raw = window.localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : {};
    } catch (e) {
      return {};
    }
  }

  function savePrefs(prefs) {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
    } catch (e) {}
  }

  var prefs = loadPrefs();

  var article = document.querySelector(".md-content__inner");
  if (!article) return;

  window.speechSynthesis.cancel();

  function isSkippable(node) {
    while (node && node !== article) {
      if (node.nodeType === 1 && node.matches && node.matches(SKIP_SELECTOR)) {
        return true;
      }
      node = node.parentNode;
    }
    return false;
  }

  function wrapWords(block) {
    var walker = document.createTreeWalker(block, NodeFilter.SHOW_TEXT, {
      acceptNode: function (node) {
        if (!node.nodeValue || !/\S/.test(node.nodeValue)) {
          return NodeFilter.FILTER_REJECT;
        }
        if (isSkippable(node.parentNode)) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      }
    });

    var textNodes = [];
    var n;
    while ((n = walker.nextNode())) {
      textNodes.push(n);
    }

    textNodes.forEach(function (textNode) {
      var frag = document.createDocumentFragment();
      var parts = textNode.nodeValue.split(/(\s+)/);
      parts.forEach(function (part) {
        if (part === "") return;
        if (/^\s+$/.test(part)) {
          frag.appendChild(document.createTextNode(part));
        } else {
          var span = document.createElement("span");
          span.className = "tts-word";
          span.textContent = part;
          frag.appendChild(span);
        }
      });
      textNode.parentNode.replaceChild(frag, textNode);
    });
  }

  function collectBlocks() {
    var candidates = Array.prototype.slice.call(article.querySelectorAll(BLOCK_SELECTOR));
    var blocks = candidates.filter(function (el) {
      if (isSkippable(el)) return false;
      var parent = el.parentElement;
      while (parent && parent !== article) {
        if (candidates.indexOf(parent) !== -1) return false;
        parent = parent.parentElement;
      }
      return /\S/.test(el.textContent);
    });
    blocks.forEach(function (block) {
      wrapWords(block);
      block.classList.add("tts-block");
    });
    return blocks;
  }

  function blockWords(block) {
    return Array.prototype.slice.call(block.querySelectorAll(".tts-word"));
  }

  function buildOffsets(words) {
    var offsets = [];
    var pos = 0;
    words.forEach(function (w) {
      offsets.push(pos);
      pos += w.textContent.length + 1;
    });
    return offsets;
  }

  function findWordIndex(offsets, charIndex) {
    var lo = 0, hi = offsets.length - 1, ans = 0;
    while (lo <= hi) {
      var mid = (lo + hi) >> 1;
      if (offsets[mid] <= charIndex) {
        ans = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return ans;
  }

  var engine = {
    blocks: collectBlocks(),
    playing: false,
    paused: false,
    blockIndex: -1,
    rate: prefs.rate || 1,
    voice: null,
    currentWordSpan: null,
    currentBlockEl: null,
    activeUtterance: null
  };

  if (engine.blocks.length === 0) return;

  function clearWordHighlight() {
    if (engine.currentWordSpan) {
      engine.currentWordSpan.classList.remove("tts-current");
      engine.currentWordSpan = null;
    }
  }

  function clearBlockHighlight() {
    if (engine.currentBlockEl) {
      engine.currentBlockEl.classList.remove("tts-active-block");
      engine.currentBlockEl = null;
    }
  }

  function stopReading() {
    engine.playing = false;
    engine.paused = false;
    engine.blockIndex = -1;
    engine.activeUtterance = null;
    window.speechSynthesis.cancel();
    clearWordHighlight();
    clearBlockHighlight();
    updateUI();
  }

  function speakBlock(index) {
    if (!engine.playing) return;
    if (index < 0 || index >= engine.blocks.length) {
      stopReading();
      return;
    }

    clearWordHighlight();
    clearBlockHighlight();

    var block = engine.blocks[index];
    var words = blockWords(block);

    if (words.length === 0) {
      speakBlock(index + 1);
      return;
    }

    engine.blockIndex = index;
    engine.currentBlockEl = block;
    block.classList.add("tts-active-block");
    block.scrollIntoView({ behavior: "smooth", block: "center" });

    var offsets = buildOffsets(words);
    var text = words.map(function (w) { return w.textContent; }).join(" ");

    var utterance = new SpeechSynthesisUtterance(text);
    utterance.rate = engine.rate;
    if (engine.voice) utterance.voice = engine.voice;

    utterance.onboundary = function (event) {
      if (engine.activeUtterance !== utterance) return;
      if (event.name && event.name !== "word") return;
      var idx = findWordIndex(offsets, event.charIndex);
      clearWordHighlight();
      var span = words[idx];
      if (span) {
        span.classList.add("tts-current");
        engine.currentWordSpan = span;
      }
    };

    utterance.onend = function () {
      if (engine.activeUtterance !== utterance || !engine.playing) return;
      speakBlock(index + 1);
    };

    utterance.onerror = function () {
      if (engine.activeUtterance !== utterance) return;
      stopReading();
    };

    engine.activeUtterance = utterance;
    window.speechSynthesis.speak(utterance);
  }

  function playFromBlock(index) {
    window.speechSynthesis.cancel();
    engine.playing = true;
    engine.paused = false;
    speakBlock(index);
    updateUI();
  }

  function togglePause() {
    if (!engine.playing) return;
    if (engine.paused) {
      window.speechSynthesis.resume();
      engine.paused = false;
    } else {
      window.speechSynthesis.pause();
      engine.paused = true;
    }
    updateUI();
  }

  var dock = document.createElement("div");
  dock.className = "tts-dock";
  dock.innerHTML =
    '<button type="button" class="tts-toggle" aria-label="Listen to this page" aria-expanded="false" title="Listen to this page">♫</button>' +
    '<div class="tts-panel" hidden>' +
      '<div class="tts-panel-row tts-panel-main">' +
        '<button type="button" class="tts-play" aria-label="Play">▶</button>' +
        '<button type="button" class="tts-stop" aria-label="Stop">■</button>' +
      '</div>' +
      '<label class="tts-panel-row">Speed' +
        '<select class="tts-rate">' +
          '<option value="0.75">0.75x</option>' +
          '<option value="1" selected>1x</option>' +
          '<option value="1.25">1.25x</option>' +
          '<option value="1.5">1.5x</option>' +
          '<option value="2">2x</option>' +
        '</select>' +
      '</label>' +
      '<label class="tts-panel-row">Voice' +
        '<select class="tts-voice"><option>Default</option></select>' +
      '</label>' +
      '<p class="tts-hint">Reads this page aloud and highlights each word. Click any paragraph to start reading from there. Uses your browser, nothing leaves your device.</p>' +
    '</div>';
  document.body.appendChild(dock);

  var toggleBtn = dock.querySelector(".tts-toggle");
  var panel = dock.querySelector(".tts-panel");
  var playBtn = dock.querySelector(".tts-play");
  var stopBtn = dock.querySelector(".tts-stop");
  var rateSelect = dock.querySelector(".tts-rate");
  var voiceSelect = dock.querySelector(".tts-voice");

  if (prefs.rate) {
    rateSelect.value = String(prefs.rate);
  }

  function updateUI() {
    if (engine.playing && !engine.paused) {
      playBtn.textContent = "❚❚";
      playBtn.setAttribute("aria-label", "Pause");
    } else {
      playBtn.textContent = "▶";
      playBtn.setAttribute("aria-label", engine.paused ? "Resume" : "Play");
    }
  }

  var panelOpen = false;
  toggleBtn.addEventListener("click", function () {
    panelOpen = !panelOpen;
    panel.hidden = !panelOpen;
    toggleBtn.setAttribute("aria-expanded", String(panelOpen));
    document.body.classList.toggle("tts-panel-open", panelOpen);
  });

  playBtn.addEventListener("click", function () {
    if (engine.playing) {
      togglePause();
    } else {
      var start = engine.blockIndex >= 0 ? engine.blockIndex : 0;
      playFromBlock(start);
    }
  });

  stopBtn.addEventListener("click", stopReading);

  rateSelect.addEventListener("change", function () {
    engine.rate = parseFloat(rateSelect.value) || 1;
    prefs.rate = engine.rate;
    savePrefs(prefs);
  });

  voiceSelect.addEventListener("change", function () {
    var voices = window.speechSynthesis.getVoices();
    var match = voices.filter(function (v) { return v.voiceURI === voiceSelect.value; })[0];
    if (match) {
      engine.voice = match;
      prefs.voiceURI = match.voiceURI;
      savePrefs(prefs);
    }
  });

  function populateVoices() {
    var all = window.speechSynthesis.getVoices();
    if (!all.length) return;

    var english = all.filter(function (v) { return /^en/i.test(v.lang); });
    var list = english.length ? english : all;

    voiceSelect.innerHTML = "";
    list.forEach(function (v) {
      var opt = document.createElement("option");
      opt.value = v.voiceURI;
      opt.textContent = v.name + " (" + v.lang + ")";
      voiceSelect.appendChild(opt);
    });

    var preferred = prefs.voiceURI && list.some(function (v) { return v.voiceURI === prefs.voiceURI; })
      ? prefs.voiceURI
      : list[0].voiceURI;
    voiceSelect.value = preferred;
    engine.voice = list.filter(function (v) { return v.voiceURI === preferred; })[0];
  }

  populateVoices();
  if (typeof window.speechSynthesis.onvoiceschanged !== "undefined") {
    window.speechSynthesis.onvoiceschanged = populateVoices;
  }

  engine.blocks.forEach(function (block, idx) {
    block.addEventListener("click", function (event) {
      if (!panelOpen) return;
      if (event.target.closest("a")) return;
      playFromBlock(idx);
    });
  });

  window.addEventListener("beforeunload", function () {
    window.speechSynthesis.cancel();
  });

  updateUI();
})();
