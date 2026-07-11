/* grokbuild Admin SPA — hash routes, sessionStorage admin key, textContent-only DOM */
(function () {
  "use strict";

  var STORAGE_KEY = "grokbuild_admin_key";
  var API_BASE = "";

  var state = {
    key: "",
    route: "login",
    system: null,
    busy: false,
    credentialOffset: 0,
    credentialLimit: 100,
    credentialTotal: 0,
  };

  // ---------- DOM helpers (no innerHTML for untrusted data) ----------

  function $(id) {
    return document.getElementById(id);
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null && text !== "") node.textContent = String(text);
    return node;
  }

  function clear(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function show(node, on) {
    if (!node) return;
    node.classList.toggle("hidden", !on);
  }

  function setText(node, text) {
    if (node) node.textContent = text == null ? "" : String(text);
  }

  // ---------- Storage ----------

  function loadKey() {
    try {
      return sessionStorage.getItem(STORAGE_KEY) || "";
    } catch (_) {
      return "";
    }
  }

  function saveKey(key) {
    try {
      if (key) sessionStorage.setItem(STORAGE_KEY, key);
      else sessionStorage.removeItem(STORAGE_KEY);
    } catch (_) {
      /* ignore quota / private mode */
    }
  }

  // ---------- Toast ----------

  function toast(message, kind) {
    var host = $("toast-host");
    if (!host) return;
    var t = el("div", "toast " + (kind || ""));
    t.textContent = message;
    host.appendChild(t);
    setTimeout(function () {
      if (t.parentNode) t.parentNode.removeChild(t);
    }, 3200);
  }

  // ---------- Modal ----------

  function openModal(title, bodyNode, footNodes) {
    var modal = $("modal");
    setText($("modal-title"), title || "对话框");
    var body = $("modal-body");
    clear(body);
    if (bodyNode) body.appendChild(bodyNode);
    var foot = $("modal-foot");
    clear(foot);
    (footNodes || []).forEach(function (n) {
      foot.appendChild(n);
    });
    show(modal, true);
  }

  function closeModal() {
    show($("modal"), false);
    clear($("modal-body"));
    clear($("modal-foot"));
  }

  // ---------- API ----------

  function apiErrorMessage(data, status) {
    if (data && data.error) {
      if (typeof data.error === "string") return data.error;
      if (data.error.message) return data.error.message;
    }
    if (data && data.message) return data.message;
    return "请求失败 HTTP " + status;
  }

  function api(method, path, body) {
    var headers = {
      Accept: "application/json",
    };
    if (state.key) {
      headers.Authorization = "Bearer " + state.key;
    }
    var opts = { method: method, headers: headers };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      opts.body = typeof body === "string" ? body : JSON.stringify(body);
    }
    return fetch(API_BASE + path, opts).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        if (text) {
          try {
            data = JSON.parse(text);
          } catch (_) {
            data = { raw: text };
          }
        }
        if (res.status === 401) {
          logout(true);
          var err401 = new Error(apiErrorMessage(data, res.status) || "未授权");
          err401.status = 401;
          throw err401;
        }
        if (!res.ok) {
          var err = new Error(apiErrorMessage(data, res.status));
          err.status = res.status;
          err.data = data;
          throw err;
        }
        return data;
      });
    });
  }

  function uploadJSONFile(path, file) {
    var headers = { Accept: "application/json" };
    if (state.key) headers.Authorization = "Bearer " + state.key;
    var form = new FormData();
    form.append("file", file, file.name);
    return fetch(API_BASE + path, {
      method: "POST",
      headers: headers,
      body: form,
    }).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        if (text) {
          try {
            data = JSON.parse(text);
          } catch (_) {
            data = { raw: text };
          }
        }
        if (res.status === 401) {
          logout(true);
          var err401 = new Error(apiErrorMessage(data, res.status));
          err401.status = 401;
          throw err401;
        }
        if (!res.ok) {
          var err = new Error(apiErrorMessage(data, res.status));
          err.status = res.status;
          err.data = data;
          throw err;
        }
        return data;
      });
    });
  }

  // ---------- Routing ----------

  function parseRoute() {
    var hash = (location.hash || "").replace(/^#\/?/, "");
    var name = (hash.split("?")[0] || "").split("/")[0] || "";
    if (!name) name = state.key ? "credentials" : "login";
    return name;
  }

  function navigate(route) {
    if (!route) route = "credentials";
    location.hash = "#/" + route;
  }

  function requireAuth(route) {
    if (route === "login") return "login";
    if (!state.key) return "login";
    return route;
  }

  function setActiveNav(route) {
    var links = document.querySelectorAll("#main-nav a");
    for (var i = 0; i < links.length; i++) {
      var a = links[i];
      a.classList.toggle("active", a.getAttribute("data-route") === route);
    }
  }

  function render() {
    var route = requireAuth(parseRoute());
    state.route = route;

    show($("view-login"), route === "login");
    show($("view-shell"), route !== "login");

    if (route === "login") {
      if (state.key) {
        navigate("credentials");
      }
      return;
    }

    setActiveNav(route);
    show($("page-credentials"), route === "credentials");
    show($("page-clients"), route === "clients");
    show($("page-system"), route === "system");
    show($("page-integration"), route === "integration");

    if (route === "credentials") loadCredentials();
    else if (route === "clients") loadClients();
    else if (route === "system") loadSystem();
    else if (route === "integration") renderIntegration();
  }

  // ---------- Auth ----------

  function logout(silent) {
    state.key = "";
    state.system = null;
    saveKey("");
    if (!silent) toast("已退出", "ok");
    navigate("login");
    render();
  }

  function login(key) {
    key = (key || "").trim();
    if (!key) {
      setText($("login-error"), "请输入管理员密钥");
      show($("login-error"), true);
      return Promise.resolve();
    }
    var btn = $("login-submit");
    if (btn) btn.disabled = true;
    show($("login-error"), false);
    var prev = state.key;
    state.key = key;
    return api("GET", "/admin/system")
      .then(function (sys) {
        state.system = sys;
        saveKey(key);
        setText($("shell-version"), (sys && sys.version) || "管理后台");
        toast("登录成功", "ok");
        navigate("credentials");
        render();
      })
      .catch(function (err) {
        state.key = prev;
        setText($("login-error"), err.message || "登录失败");
        show($("login-error"), true);
      })
      .finally(function () {
        if (btn) btn.disabled = false;
      });
  }

  // ---------- Format helpers ----------

  function fmtTime(v) {
    if (!v) return "—";
    try {
      var d = new Date(v);
      if (isNaN(d.getTime())) return String(v);
      return d.toLocaleString();
    } catch (_) {
      return String(v);
    }
  }

  function shortId(id) {
    if (!id) return "—";
    if (id.length <= 12) return id;
    return id.slice(0, 6) + "…" + id.slice(-4);
  }

  // ---------- Credentials ----------

  function loadCredentials(reset) {
    var list = $("cred-list");
    var empty = $("cred-empty");
    if (!list) return;
    if (reset === true) state.credentialOffset = 0;
    clear(list);
    show(empty, false);
    api("GET", "/admin/credentials?limit=" + state.credentialLimit + "&offset=" + state.credentialOffset)
      .then(function (data) {
        var creds = (data && data.credentials) || [];
        state.credentialTotal = Number((data && data.total) || creds.length);
        var start = creds.length ? state.credentialOffset + 1 : 0;
        var end = state.credentialOffset + creds.length;
        setText($("cred-page-status"), start + "-" + end + " / " + state.credentialTotal);
        var prev = $("btn-cred-prev");
        var next = $("btn-cred-next");
        if (prev) prev.disabled = state.credentialOffset <= 0;
        if (next) next.disabled = end >= state.credentialTotal;
        if (!creds.length) {
          show(empty, true);
          return;
        }
        creds.forEach(function (c) {
          list.appendChild(renderCredentialCard(c));
        });
      })
      .catch(function (err) {
        toast("加载凭证失败: " + err.message, "err");
      });
  }

  function renderCredentialCard(c) {
    var card = el("article", "card cred-card");
    card.dataset.id = c.id || "";

    var top = el("div", "cred-top");
    var left = el("div");
    var title = el("h3", "cred-title", c.name || c.email || c.id || "（未命名）");
    left.appendChild(title);
    if (c.email && c.email !== c.name) {
      left.appendChild(el("div", "muted", c.email));
    }
    top.appendChild(left);

    var badge = el(
      "span",
      "badge " + (c.enabled ? "badge-ok" : "badge-off"),
      c.enabled ? "已启用" : "已禁用"
    );
    top.appendChild(badge);
    card.appendChild(top);

    var meta = el("div", "cred-meta");
    meta.appendChild(lineMeta("编号", shortId(c.id)));
    meta.appendChild(lineMeta("优先级", String(c.priority != null ? c.priority : 0)));
    meta.appendChild(lineMeta("过期时间", fmtTime(c.expires_at)));
    meta.appendChild(
      lineMeta(
        "令牌",
        (c.has_access_token ? "访问令牌" : "—") +
          " / " +
          (c.has_refresh_token ? "刷新令牌" : "—")
      )
    );
    if (c.failure_count) {
      meta.appendChild(lineMeta("失败次数", String(c.failure_count)));
    }
    if (c.last_error) {
      var errLine = el("div");
      errLine.appendChild(el("span", "badge badge-danger", "错误"));
      errLine.appendChild(document.createTextNode(" "));
      errLine.appendChild(el("span", "", c.last_error));
      meta.appendChild(errLine);
    }
    if (c.cooldown_until) {
      meta.appendChild(lineMeta("冷却至", fmtTime(c.cooldown_until)));
    }
    if (c.access_token) {
      meta.appendChild(lineMeta("访问令牌(脱敏)", c.access_token));
    }
    card.appendChild(meta);

    var prioRow = el("div", "priority-row");
    prioRow.appendChild(el("span", "label", "优先级"));
    var prioInput = el("input");
    prioInput.type = "number";
    prioInput.value = String(c.priority != null ? c.priority : 0);
    prioInput.setAttribute("aria-label", "优先级");
    var prioBtn = el("button", "btn btn-sm", "保存");
    prioBtn.type = "button";
    prioBtn.addEventListener("click", function () {
      var n = parseInt(prioInput.value, 10);
      if (isNaN(n)) {
        toast("优先级必须是数字", "err");
        return;
      }
      prioBtn.disabled = true;
      // PUT /admin/credentials/{id}/priority  body: {"priority":n}
      api("PUT", "/admin/credentials/" + encodeURIComponent(c.id) + "/priority", {
        priority: n,
      })
        .then(function () {
          toast("优先级已更新", "ok");
          loadCredentials();
        })
        .catch(function (err) {
          toast("更新失败: " + err.message, "err");
        })
        .finally(function () {
          prioBtn.disabled = false;
        });
    });
    prioRow.appendChild(prioInput);
    prioRow.appendChild(prioBtn);
    card.appendChild(prioRow);

    var actions = el("div", "cred-actions");

    var toggle = el("button", "btn btn-sm", c.enabled ? "禁用" : "启用");
    toggle.type = "button";
    toggle.addEventListener("click", function () {
      toggle.disabled = true;
      // POST /admin/credentials/{id}/disable  body: {"enabled": true|false}
      api("POST", "/admin/credentials/" + encodeURIComponent(c.id) + "/disable", {
        enabled: !c.enabled,
      })
        .then(function () {
          toast(c.enabled ? "已禁用" : "已启用", "ok");
          loadCredentials();
        })
        .catch(function (err) {
          toast("切换失败: " + err.message, "err");
        })
        .finally(function () {
          toggle.disabled = false;
        });
    });
    actions.appendChild(toggle);

    var refresh = el("button", "btn btn-sm", "刷新令牌");
    refresh.type = "button";
    refresh.addEventListener("click", function () {
      refresh.disabled = true;
      api("POST", "/admin/credentials/" + encodeURIComponent(c.id) + "/refresh")
        .then(function () {
          toast("令牌已刷新", "ok");
          loadCredentials();
        })
        .catch(function (err) {
          toast("刷新令牌失败: " + err.message, "err");
        })
        .finally(function () {
          refresh.disabled = false;
        });
    });
    actions.appendChild(refresh);

    var billing = el("button", "btn btn-sm", "账单");
    billing.type = "button";
    billing.addEventListener("click", function () {
      showBilling(c);
    });
    actions.appendChild(billing);

    var del = el("button", "btn btn-sm btn-danger", "删除");
    del.type = "button";
    del.addEventListener("click", function () {
      if (!confirm("确认删除凭证 " + (c.name || c.id) + " ?")) return;
      del.disabled = true;
      api("DELETE", "/admin/credentials/" + encodeURIComponent(c.id))
        .then(function () {
          toast("已删除", "ok");
          loadCredentials();
        })
        .catch(function (err) {
          toast("删除失败: " + err.message, "err");
        })
        .finally(function () {
          del.disabled = false;
        });
    });
    actions.appendChild(del);

    card.appendChild(actions);
    return card;
  }

  function lineMeta(label, value) {
    var row = el("div");
    row.appendChild(el("strong", "", label + ": "));
    row.appendChild(el("code", "", value));
    return row;
  }

  function showBilling(c) {
    var body = el("div", "stack");
    body.appendChild(el("p", "muted", "加载账单…"));
    var closeBtn = el("button", "btn", "关闭");
    closeBtn.type = "button";
    closeBtn.addEventListener("click", closeModal);
    var reloadBtn = el("button", "btn btn-primary", "刷新");
    reloadBtn.type = "button";
    openModal("账单 · " + (c.name || c.email || shortId(c.id)), body, [
      reloadBtn,
      closeBtn,
    ]);

    function load() {
      clear(body);
      body.appendChild(el("p", "muted", "加载账单…"));
      reloadBtn.disabled = true;
      api("GET", "/admin/credentials/" + encodeURIComponent(c.id) + "/billing")
        .then(function (snap) {
          clear(body);
          body.appendChild(renderBillingDashboard(snap));
          // Raw JSON is optional debug only — collapsed by default.
          var details = el("details", "raw-details");
          var summary = el("summary", "", "调试：原始 JSON（默认折叠）");
          details.appendChild(summary);
          var pre = el("pre", "code");
          pre.textContent = JSON.stringify(snap, null, 2);
          details.appendChild(pre);
          body.appendChild(details);
        })
        .catch(function (err) {
          clear(body);
          body.appendChild(el("p", "error", err.message || "账单加载失败"));
        })
        .finally(function () {
          reloadBtn.disabled = false;
        });
    }
    reloadBtn.addEventListener("click", load);
    load();
  }

  function fillCredentialUsage(box, credId) {
    if (!box || !credId) return;
    api("GET", "/admin/credentials/" + encodeURIComponent(credId) + "/billing")
      .then(function (snap) {
        clear(box);
        var u = parseUsage(snap);
        box.appendChild(usageBar("月额度", u.monthPct, u.monthLabel, u.monthTone));
        box.appendChild(usageBar("周额度", u.weekPct, u.weekLabel, u.weekTone));
      })
      .catch(function (err) {
        clear(box);
        box.appendChild(el("div", "error", "额度: " + (err.message || "失败")));
      });
  }

  function parseUsage(snap) {
    var m = (snap && snap.monthly) || {};
    var w = (snap && snap.weekly) || {};
    var limit = num(m.monthlyLimit);
    var used = num(m.used);
    var rem = Math.max(0, limit - used);
    var monthPct = limit > 0 ? (used / limit) * 100 : 0;
    var weekPct = num(w.creditUsagePercent);
    return {
      limit: limit,
      used: used,
      rem: rem,
      monthPct: monthPct,
      weekPct: weekPct,
      monthLabel:
        limit > 0
          ? fmtNum(used) + " / " + fmtNum(limit) + "（剩 " + fmtNum(rem) + "）"
          : used > 0
            ? "已用 " + fmtNum(used) + "（无限额字段）"
            : "暂无月额度数据",
      weekLabel: weekPct > 0 || weekPct === 0 ? weekPct.toFixed(1) + "%" : "暂无",
      monthTone: toneFromPct(monthPct),
      weekTone: toneFromPct(weekPct),
      period:
        (m.billingPeriodStart || "") && (m.billingPeriodEnd || "")
          ? fmtDay(m.billingPeriodStart) + " → " + fmtDay(m.billingPeriodEnd)
          : m.billingPeriodEnd
            ? "至 " + fmtDay(m.billingPeriodEnd)
            : "",
      weekEnd: w.billingPeriodEnd ? fmtDay(w.billingPeriodEnd) : "",
      products: parseProductUsage(w.productUsage),
    };
  }

  function parseProductUsage(raw) {
    if (!raw) return [];
    try {
      var arr = typeof raw === "string" ? JSON.parse(raw) : raw;
      if (!Array.isArray(arr)) return [];
      return arr
        .map(function (p) {
          return {
            name: p.product || p.name || "?",
            pct: num(p.usagePercent != null ? p.usagePercent : p.usage_percent),
          };
        })
        .filter(function (p) {
          return p.name;
        });
    } catch (_) {
      return [];
    }
  }

  function renderBillingDashboard(snap) {
    var u = parseUsage(snap);
    var wrap = el("div", "stack billing-dash");

    var hero = el("div", "billing-hero");
    hero.appendChild(el("div", "billing-hero-title", "Grok Build 额度"));
    hero.appendChild(
      el(
        "div",
        "billing-hero-value",
        u.limit > 0 ? fmtNum(u.rem) + " 剩余" : "—"
      )
    );
    hero.appendChild(
      el(
        "div",
        "muted",
        u.limit > 0
          ? "本月已用 " + fmtNum(u.used) + " / " + fmtNum(u.limit)
          : "上游未返回月额度上限"
      )
    );
    wrap.appendChild(hero);

    wrap.appendChild(usageBar("月额度使用", u.monthPct, u.monthLabel, u.monthTone));
    wrap.appendChild(usageBar("周额度使用", u.weekPct, u.weekLabel, u.weekTone));

    var grid = el("div", "billing-grid");
    grid.appendChild(statCard("月已用", fmtNum(u.used)));
    grid.appendChild(statCard("月上限", u.limit > 0 ? fmtNum(u.limit) : "—"));
    grid.appendChild(statCard("月剩余", u.limit > 0 ? fmtNum(u.rem) : "—"));
    grid.appendChild(statCard("周用量", u.weekPct.toFixed(1) + "%"));
    wrap.appendChild(grid);

    if (u.period) {
      wrap.appendChild(lineMeta("月账期", u.period));
    }
    if (u.weekEnd) {
      wrap.appendChild(lineMeta("周账期结束", u.weekEnd));
    }

    if (u.products.length) {
      wrap.appendChild(el("div", "section-label", "产品用量"));
      u.products.forEach(function (p) {
        wrap.appendChild(
          usageBar(p.name, p.pct, p.pct.toFixed(1) + "%", toneFromPct(p.pct))
        );
      });
    }

    if (u.limit === 0 && u.used === 0 && u.weekPct === 0) {
      wrap.appendChild(
        el("p", "error", "未解析到有效额度。请点「刷新」；若仍为空，检查账号是否有 Build 订阅。")
      );
    } else if (u.weekPct >= 100) {
      wrap.appendChild(
        el("p", "error", "周额度已用尽（上游可能返回 402 账单错误）。")
      );
    } else if (u.monthPct >= 95) {
      wrap.appendChild(el("p", "error", "月额度即将用尽，请留意切换账号。"));
    }

    return wrap;
  }

  function usageBar(label, pct, detail, tone) {
    var box = el("div", "usage-bar-wrap");
    var head = el("div", "usage-bar-head");
    head.appendChild(el("span", "", label));
    head.appendChild(el("span", "muted", detail || ""));
    box.appendChild(head);
    var track = el("div", "usage-track");
    var fill = el("div", "usage-fill " + (tone || "tone-ok"));
    var width = Math.max(0, Math.min(100, Number(pct) || 0));
    fill.style.width = width.toFixed(1) + "%";
    track.appendChild(fill);
    box.appendChild(track);
    return box;
  }

  function statCard(label, value) {
    var card = el("div", "stat-card");
    card.appendChild(el("div", "muted", label));
    card.appendChild(el("div", "stat-value", value));
    return card;
  }

  function num(v) {
    var n = Number(v);
    return isFinite(n) ? n : 0;
  }

  function fmtNum(n) {
    n = num(n);
    try {
      return n.toLocaleString("zh-CN", { maximumFractionDigits: 1 });
    } catch (_) {
      return String(n);
    }
  }

  function fmtDay(iso) {
    if (!iso) return "";
    // Keep date part readable without forcing timezone conversion surprises.
    var s = String(iso);
    if (s.length >= 10) return s.slice(0, 10);
    return s;
  }

  function toneFromPct(pct) {
    pct = num(pct);
    if (pct >= 95) return "tone-danger";
    if (pct >= 70) return "tone-warn";
    return "tone-ok";
  }

  function importDefaultGrok() {
    // POST /admin/credentials/import-grok with empty/{} body → default ~/.grok path
    api("POST", "/admin/credentials/import-grok", {})
      .then(function (data) {
        var n = (data && data.imported) || 0;
        toast("已导入 " + n + " 条凭证", "ok");
        loadCredentials();
      })
      .catch(function (err) {
        toast("导入失败: " + err.message, "err");
      });
  }

  function startDeviceLogin() {
    api("POST", "/admin/oauth/device/start", {})
      .then(function (data) {
        var body = el("div", "stack");
        body.appendChild(el("p", "muted", "在 xAI 页面完成授权，此窗口会自动检测结果。"));
        var code = el("code", "code-block", data.user_code || "");
        body.appendChild(code);
        var link = el("a", "btn btn-primary", "打开授权页面");
        link.href = data.verification_uri_complete || data.verification_uri || "#";
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        body.appendChild(link);
        var status = el("p", "muted", "等待授权…");
        status.id = "device-login-status";
        body.appendChild(status);
        var cancel = el("button", "btn", "取消");
        cancel.type = "button";
        cancel.addEventListener("click", closeModal);
        openModal("浏览器登录", body, [cancel]);

        var interval = Math.max(1, Number(data.interval) || 5) * 1000;
        function poll() {
          if (!$("device-login-status")) return;
          api("POST", "/admin/oauth/device/poll", { session_id: data.session_id })
            .then(function (result) {
              if (result && result.status === "authorized") {
                toast("账号授权成功", "ok");
                closeModal();
                loadCredentials();
                return;
              }
              setText($("device-login-status"), "等待授权…");
              var delay = Math.max(1, Number(result && result.retry_after) || interval / 1000) * 1000;
              setTimeout(poll, delay);
            })
            .catch(function (err) {
              if (err.status === 429) {
                var retry = Number(err.data && err.data.retry_after) || interval / 1000;
                setTimeout(poll, Math.max(1, retry) * 1000);
                return;
              }
              setText($("device-login-status"), "授权失败: " + err.message);
            });
        }
        setTimeout(poll, interval);
      })
      .catch(function (err) {
        toast("启动浏览器登录失败: " + err.message, "err");
      });
  }

  function openImportRawModal() {
    var body = el("div", "stack");
    body.appendChild(
      el(
        "p",
        "muted",
        "粘贴 grok auth JSON。将作为 {\"raw\": <JSON>} 提交到 import-grok。"
      )
    );
    var ta = el("textarea");
    ta.placeholder = '{"accounts": ...} 或 auth.json 全文';
    body.appendChild(ta);

    var cancel = el("button", "btn", "取消");
    cancel.type = "button";
    cancel.addEventListener("click", closeModal);

    var ok = el("button", "btn btn-primary", "导入");
    ok.type = "button";
    ok.addEventListener("click", function () {
      var rawText = (ta.value || "").trim();
      if (!rawText) {
        toast("请粘贴 JSON", "err");
        return;
      }
      var parsed;
      try {
        parsed = JSON.parse(rawText);
      } catch (e) {
        toast("JSON 无效: " + e.message, "err");
        return;
      }
      ok.disabled = true;
      // Align with handlers.ImportGrok body.Raw json.RawMessage via {"raw": object}
      api("POST", "/admin/credentials/import-grok", { raw: parsed })
        .then(function (data) {
          var n = (data && data.imported) || 0;
          toast("已导入 " + n + " 条凭证", "ok");
          closeModal();
          loadCredentials();
        })
        .catch(function (err) {
          toast("导入失败: " + err.message, "err");
        })
        .finally(function () {
          ok.disabled = false;
        });
    });

    openModal("导入 Grok JSON", body, [cancel, ok]);
  }

  function importGrokFile(file) {
    if (!file) return;
    if (!/\.json$/i.test(file.name || "")) {
      toast("请选择 JSON 文件", "err");
      return;
    }
    var button = $("btn-import-file");
    if (button) button.disabled = true;
    toast("正在导入 " + file.name + "…", "");
    uploadJSONFile("/admin/credentials/import-grok", file)
      .then(function (data) {
        var n = (data && data.imported) || 0;
        toast("已导入 " + n + " 条凭证", "ok");
        loadCredentials();
      })
      .catch(function (err) {
        toast("导入失败: " + err.message, "err");
      })
      .finally(function () {
        if (button) button.disabled = false;
        var input = $("import-file-input");
        if (input) input.value = "";
      });
  }

  // ---------- Clients ----------

  function loadClients() {
    var wrap = $("client-list");
    var empty = $("client-empty");
    if (!wrap) return;
    clear(wrap);
    show(empty, false);
    show(wrap, true);
    api("GET", "/admin/clients")
      .then(function (data) {
        var clients = (data && data.clients) || [];
        if (!clients.length) {
          show(empty, true);
          show(wrap, false);
          return;
        }
        wrap.appendChild(renderClientTable(clients));
      })
      .catch(function (err) {
        toast("加载客户端失败: " + err.message, "err");
      });
  }

  function renderClientTable(clients) {
    var table = el("table");
    var thead = el("thead");
    var hr = el("tr");
    ["名称", "编号", "前缀", "创建时间", "状态", ""].forEach(function (h) {
      hr.appendChild(el("th", "", h));
    });
    thead.appendChild(hr);
    table.appendChild(thead);

    var tbody = el("tbody");
    clients.forEach(function (c) {
      var tr = el("tr");
      tr.appendChild(el("td", "", c.name || "—"));
      var idTd = el("td");
      idTd.appendChild(el("code", "", shortId(c.id)));
      tr.appendChild(idTd);
      var prefTd = el("td");
      prefTd.appendChild(el("code", "", c.prefix || "—"));
      tr.appendChild(prefTd);
      tr.appendChild(el("td", "", fmtTime(c.created_at)));
      var st = el("td");
      st.appendChild(
        el(
          "span",
          "badge " + (c.disabled ? "badge-off" : "badge-ok"),
          c.disabled ? "已停用" : "可用"
        )
      );
      tr.appendChild(st);

      var act = el("td");
      var del = el("button", "btn btn-sm btn-danger", "删除");
      del.type = "button";
      del.addEventListener("click", function () {
        if (!confirm("确认吊销客户端密钥 " + (c.name || c.id) + " ？")) return;
        del.disabled = true;
        api("DELETE", "/admin/clients/" + encodeURIComponent(c.id))
          .then(function () {
            toast("已删除客户端密钥", "ok");
            loadClients();
          })
          .catch(function (err) {
            toast("删除失败: " + err.message, "err");
          })
          .finally(function () {
            del.disabled = false;
          });
      });
      act.appendChild(del);
      tr.appendChild(act);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    return table;
  }

  function openCreateClientModal() {
    var body = el("div", "stack");
    var field = el("label", "field");
    field.appendChild(el("span", "label", "名称（可选）"));
    var input = el("input");
    input.type = "text";
    input.placeholder = "例如：claude-code-本机";
    field.appendChild(input);
    body.appendChild(field);

    var cancel = el("button", "btn", "取消");
    cancel.type = "button";
    cancel.addEventListener("click", closeModal);

    var ok = el("button", "btn btn-primary", "创建");
    ok.type = "button";
    ok.addEventListener("click", function () {
      ok.disabled = true;
      api("POST", "/admin/clients", { name: (input.value || "").trim() })
        .then(function (data) {
          var plain = (data && (data.plaintext || data.api_key)) || "";
          showOncePlaintext(plain, data && data.client);
          loadClients();
        })
        .catch(function (err) {
          toast("创建失败: " + err.message, "err");
        })
        .finally(function () {
          ok.disabled = false;
        });
    });

    openModal("创建客户端密钥", body, [cancel, ok]);
  }

  function showOncePlaintext(plain, client) {
    var body = el("div", "stack");
    body.appendChild(
      el(
        "div",
        "warn-note",
        "明文 API Key 仅此一次展示，关闭后无法再次查看。请立即复制保存。"
      )
    );
    if (client && client.name) {
      body.appendChild(el("div", "muted", "名称: " + client.name));
    }
    body.appendChild(el("div", "plaintext-box", plain || "（空）"));

    var copy = el("button", "btn btn-primary", "复制");
    copy.type = "button";
    copy.addEventListener("click", function () {
      copyText(plain).then(
        function () {
          toast("已复制", "ok");
        },
        function () {
          toast("复制失败，请手动选择", "err");
        }
      );
    });
    var close = el("button", "btn", "我已保存");
    close.type = "button";
    close.addEventListener("click", closeModal);
    openModal("客户端密钥", body, [copy, close]);
  }

  // ---------- System ----------

  function loadSystem() {
    var host = $("system-body");
    if (!host) return;
    clear(host);
    host.appendChild(el("p", "muted", "加载中…"));
    api("GET", "/admin/system")
      .then(function (sys) {
        state.system = sys;
        setText($("shell-version"), (sys && sys.version) || "管理后台");
        clear(host);
        host.appendChild(renderSystem(sys));
      })
      .catch(function (err) {
        clear(host);
        host.appendChild(el("p", "error", err.message || "加载失败"));
      });
  }

  function renderSystem(sys) {
    var wrap = el("div", "stack");
    var dl = el("dl", "kv");
    addKV(dl, "版本", sys.version);
    addKV(dl, "监听地址", sys.listen);
    addKV(dl, "数据目录", sys.data_dir);
    addKV(dl, "对话后端", sys.chat_backend);
    if (sys.upstream) {
      addKV(dl, "上游地址", sys.upstream.base_url);
      addKV(dl, "客户端版本", sys.upstream.client_version);
      addKV(dl, "客户端标识", sys.upstream.client_identifier);
      addKV(dl, "User-Agent", sys.upstream.user_agent);
      addKV(dl, "Token 鉴权头", String(!!sys.upstream.token_auth));
    }
    if (sys.anthropic) {
      addKV(dl, "Anthropic 入口", sys.anthropic.enabled ? "已启用" : "已关闭");
    }
    if (sys.pool) {
      var pool = sys.pool;
      addKV(dl, "账号池可用", String(pool.available || 0) + " / " + String(pool.total || 0));
      addKV(dl, "冷却中", pool.cooling || 0);
      addKV(dl, "已禁用", pool.disabled || 0);
      addKV(dl, "令牌已过期", pool.expired || 0);
      addKV(dl, "下次恢复", pool.next_recovery_at ? fmtTime(pool.next_recovery_at) : "—");
      addKV(dl, "最近成功", pool.last_success_at ? fmtTime(pool.last_success_at) : "—");
    }
    if (sys.limits) {
      var lim = sys.limits;
      addKV(dl, "最大请求体", String(lim.MaxBodyBytes != null ? lim.MaxBodyBytes : lim.max_body_bytes || "—"));
      addKV(dl, "请求超时(秒)", String(lim.RequestTimeoutSec != null ? lim.RequestTimeoutSec : lim.request_timeout_sec || "—"));
      addKV(dl, "最大并发", String(lim.MaxConcurrent != null ? lim.MaxConcurrent : lim.max_concurrent || "—"));
    }
    wrap.appendChild(dl);

    var raw = el("details");
    raw.appendChild(el("summary", "", "调试：原始 JSON"));
    var pre = el("pre", "code");
    pre.textContent = JSON.stringify(sys, null, 2);
    raw.appendChild(pre);
    wrap.appendChild(raw);
    return wrap;
  }

  function addKV(dl, k, v) {
    dl.appendChild(el("dt", "", k));
    dl.appendChild(el("dd", "", v == null || v === "" ? "—" : String(v)));
  }

  // ---------- Integration ----------

  function renderIntegration() {
    var origin = location.origin || "http://127.0.0.1:8080";
    var anthropic =
      'export ANTHROPIC_BASE_URL="' +
      origin +
      '"\n' +
      'export ANTHROPIC_AUTH_TOKEN="<客户端密钥>"';
    var openai =
      'export OPENAI_BASE_URL="' +
      origin +
      '/v1"\n' +
      'export OPENAI_API_KEY="<客户端密钥>"';
    setText($("snippet-anthropic"), anthropic);
    setText($("snippet-openai"), openai);
  }

  function copyIntegration() {
    var a = ($("snippet-anthropic") && $("snippet-anthropic").textContent) || "";
    var o = ($("snippet-openai") && $("snippet-openai").textContent) || "";
    var all = a + "\n\n" + o;
    copyText(all).then(
      function () {
        toast("已复制接入片段", "ok");
      },
      function () {
        toast("复制失败", "err");
      }
    );
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand("copy");
        document.body.removeChild(ta);
        if (ok) resolve();
        else reject(new Error("复制失败"));
      } catch (e) {
        reject(e);
      }
    });
  }

  // ---------- Wire events ----------

  function bind() {
    var loginForm = $("login-form");
    if (loginForm) {
      loginForm.addEventListener("submit", function (e) {
        e.preventDefault();
        login(($("login-key") && $("login-key").value) || "");
      });
    }

    var logoutBtn = $("btn-logout");
    if (logoutBtn) {
      logoutBtn.addEventListener("click", function () {
        logout(false);
      });
    }

    var credRefresh = $("btn-cred-refresh-list");
    if (credRefresh) credRefresh.addEventListener("click", function () { loadCredentials(true); });

    var credPrev = $("btn-cred-prev");
    if (credPrev) credPrev.addEventListener("click", function () {
      state.credentialOffset = Math.max(0, state.credentialOffset - state.credentialLimit);
      loadCredentials(false);
    });
    var credNext = $("btn-cred-next");
    if (credNext) credNext.addEventListener("click", function () {
      if (state.credentialOffset + state.credentialLimit < state.credentialTotal) {
        state.credentialOffset += state.credentialLimit;
        loadCredentials(false);
      }
    });

    var impDef = $("btn-import-default");
    if (impDef) impDef.addEventListener("click", importDefaultGrok);

    var deviceLogin = $("btn-device-login");
    if (deviceLogin) deviceLogin.addEventListener("click", startDeviceLogin);

    var impRaw = $("btn-import-raw");
    if (impRaw) impRaw.addEventListener("click", openImportRawModal);

    var impFile = $("btn-import-file");
    var impFileInput = $("import-file-input");
    if (impFile && impFileInput) {
      impFile.addEventListener("click", function () {
        impFileInput.click();
      });
      impFileInput.addEventListener("change", function () {
        importGrokFile(impFileInput.files && impFileInput.files[0]);
      });
    }

    var clientRefresh = $("btn-client-refresh");
    if (clientRefresh) clientRefresh.addEventListener("click", loadClients);

    var clientCreate = $("btn-client-create");
    if (clientCreate) clientCreate.addEventListener("click", openCreateClientModal);

    var sysRefresh = $("btn-system-refresh");
    if (sysRefresh) sysRefresh.addEventListener("click", loadSystem);

    var copyInt = $("btn-copy-integration");
    if (copyInt) copyInt.addEventListener("click", copyIntegration);

    var modalClose = $("modal-close");
    if (modalClose) modalClose.addEventListener("click", closeModal);

    var modal = $("modal");
    if (modal) {
      modal.addEventListener("click", function (e) {
        if (e.target && e.target.getAttribute("data-close") === "1") closeModal();
      });
    }

    window.addEventListener("hashchange", render);
  }

  function boot() {
    bind();
    state.key = loadKey();
    if (state.key) {
      api("GET", "/admin/system")
        .then(function (sys) {
          state.system = sys;
          setText($("shell-version"), (sys && sys.version) || "管理后台");
          if (!location.hash || location.hash === "#" || location.hash === "#/") {
            navigate("credentials");
          }
          render();
        })
        .catch(function () {
          if (!state.key) {
            navigate("login");
          }
          render();
        });
    } else {
      if (!location.hash || location.hash === "#" || location.hash === "#/credentials") {
        navigate("login");
      }
      render();
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
