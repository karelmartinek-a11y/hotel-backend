(() => {
  const root = document.querySelector('[data-webapp]');
  if (!root) return;

  const role = root.dataset.role || 'housekeeping';
  const rooms = JSON.parse(root.dataset.rooms || '[]');
  const deviceClass = root.dataset.deviceClass || 'DESKTOP';

  const ui = {
    statusPill: root.querySelector('[data-status-pill]'),
    statusText: root.querySelector('[data-status-text]'),
    deviceId: root.querySelector('[data-device-id]'),
    activationNote: root.querySelector('[data-activation-note]'),
    actionArea: root.querySelector('[data-action-area]'),
    errorBox: root.querySelector('[data-error-box]'),
    successBox: root.querySelector('[data-success-box]'),
    reportList: root.querySelector('[data-report-list]'),
    refreshBtn: root.querySelector('[data-refresh-reports]'),
    breakfastList: root.querySelector('[data-breakfast-list]'),
    breakfastPrev: root.querySelector('[data-breakfast-prev]'),
    breakfastNext: root.querySelector('[data-breakfast-next]'),
    breakfastDate: root.querySelector('[data-breakfast-date]'),
    breakfastStatusText: root.querySelector('[data-breakfast-status-text]'),
    breakfastTotal: root.querySelector('[data-breakfast-total]'),
    roomGrid: root.querySelector('[data-room-grid]'),
    form: root.querySelector('[data-housekeeping-form]'),
    description: root.querySelector('[data-description]'),
    descCount: root.querySelector('[data-desc-count]'),
    typeInputs: root.querySelectorAll('[data-report-type]'),
    photoPreview: root.querySelector('[data-photo-preview]'),
    photoCount: root.querySelector('[data-photo-count]'),
    inputCamera: root.querySelector('[data-photo-camera-input]'),
    inputGallery: root.querySelector('[data-photo-gallery-input]'),
    inputDesktop: root.querySelector('[data-photo-desktop-input]'),
    cameraBtn: root.querySelector('[data-photo-camera-btn]'),
    galleryBtn: root.querySelector('[data-photo-gallery-btn]'),
    desktopBtn: root.querySelector('[data-photo-desktop-btn]')
  };

  const state = {
    deviceId: null,
    deviceFp: null,
    displayName: '',
    status: 'UNKNOWN',
    breakfastDate: null,
    selectedRoom: null,
    files: [],
    urls: new Map()
  };
  let refreshTimer = null;
  let overlay = null;
  let overlayText = null;

  const STORAGE_KEY = 'hotel_device_v2';
  const LEGACY_KEY = 'hotelWebDeviceId';

  const setMode = () => {
    const width = window.innerWidth;
    let mode = 'mode-mobile';
    if (width >= 640 && width < 1024) mode = 'mode-tablet';
    if (width >= 1024) mode = 'mode-desktop';
    root.classList.remove('mode-mobile', 'mode-tablet', 'mode-desktop');
    root.classList.add(mode);
    root.dataset.deviceClass = deviceClass;
  };

  const uuid = () => {
    if (window.crypto && window.crypto.randomUUID) {
      return window.crypto.randomUUID();
    }
    const buf = new Uint8Array(16);
    window.crypto.getRandomValues(buf);
    buf[6] = (buf[6] & 0x0f) | 0x40;
    buf[8] = (buf[8] & 0x3f) | 0x80;
    const b = Array.from(buf).map((n) => n.toString(16).padStart(2, '0'));
    return `${b.slice(0, 4).join('')}-${b.slice(4, 6).join('')}-${b.slice(6, 8).join('')}-${b.slice(8, 10).join('')}-${b.slice(10, 16).join('')}`;
  };

  const safeGetItem = (key) => {
    try {
      return window.localStorage.getItem(key);
    } catch (e) {
      return null;
    }
  };

  const safeSetItem = (key, value) => {
    try {
      window.localStorage.setItem(key, value);
    } catch (e) {
      // ignore storage errors
    }
  };

  const setDeviceCookie = (deviceId) => {
    if (!deviceId) return;
    try {
      const encoded = encodeURIComponent(deviceId);
      document.cookie = `hotel_device_id=${encoded}; Path=/; Max-Age=31536000; SameSite=Lax`;
    } catch (e) {
      console.warn('setting hotel_device_id cookie failed', e);
    }
  };

  const loadState = () => {
    const raw = safeGetItem(STORAGE_KEY);
    if (raw) {
      try {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') return parsed;
      } catch (e) {
        // ignore parse errors
      }
    }
    const legacy = safeGetItem(LEGACY_KEY);
    if (legacy) return { device_id: legacy };
    return {};
  };

  const saveState = (next) => {
    safeSetItem(STORAGE_KEY, JSON.stringify(next));
  };

  const ensureDeviceState = () => {
    const current = loadState();
    if (!current.device_id) current.device_id = uuid();
    if (!current.fp) current.fp = uuid();
    if (typeof current.display_name !== 'string') current.display_name = '';
    saveState(current);
    state.deviceId = current.device_id;
    state.deviceFp = current.fp;
    state.displayName = current.display_name || '';
    if (ui.deviceId) ui.deviceId.textContent = state.deviceId;
    setDeviceCookie(state.deviceId);
    return current;
  };

  const showError = (message) => {
    if (!ui.errorBox) return;
    ui.errorBox.textContent = message;
    ui.errorBox.classList.remove('webapp-hidden');
  };

  const showSuccess = (message, persistent = false) => {
    if (!ui.successBox) return;
    ui.successBox.textContent = message;
    ui.successBox.classList.remove('webapp-hidden');
    if (!persistent) {
      setTimeout(() => ui.successBox.classList.add('webapp-hidden'), 4000);
    }
  };

  const clearAlerts = () => {
    if (ui.errorBox) ui.errorBox.classList.add('webapp-hidden');
    if (ui.successBox) ui.successBox.classList.add('webapp-hidden');
  };

  const setStatus = (status, detail) => {
    state.status = status;
    if (ui.statusPill) ui.statusPill.dataset.status = status;
    if (ui.statusPill) ui.statusPill.textContent = status === 'ACTIVE'
      ? 'Aktivní'
      : status === 'REVOKED'
        ? 'Zablokováno'
        : status === 'PENDING'
          ? 'Čeká na aktivaci'
          : 'Neznámý stav';
    if (ui.statusText) ui.statusText.textContent = detail || '';
    if (ui.activationNote) {
      ui.activationNote.classList.toggle('webapp-hidden', status === 'ACTIVE');
      if (status === 'REVOKED') {
        ui.activationNote.textContent = 'Zařízení bylo zablokováno. Kontaktujte administrátora.';
      } else {
        ui.activationNote.textContent = 'Zařízení čeká na aktivaci. Požádejte administrátora o povolení zařízení v administraci Hotelu.';
      }
    }
    if (ui.actionArea) {
      ui.actionArea.classList.toggle('webapp-hidden', status !== 'ACTIVE');
    }
  };

  const fetchJson = async (url, options = {}) => {
    const resp = await fetch(url, options);
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(text || `Chyba ${resp.status}`);
    }
    if (resp.status === 204) return null;
    return resp.json();
  };

  const createOverlay = () => {
    overlay = document.createElement('div');
    overlay.className = 'webapp-overlay webapp-hidden';
    const card = document.createElement('div');
    card.className = 'webapp-overlay-card';
    const img = document.createElement('img');
    img.src = '/static/brand/hotel-icon.svg';
    img.alt = 'ASC Hotel Chodov';
    const title = document.createElement('p');
    title.className = 'webapp-overlay-title';
    title.textContent = 'Odesílám požadavek';
    overlayText = document.createElement('p');
    overlayText.className = 'webapp-overlay-text';
    overlayText.textContent = 'Vyčkejte prosím, hlášení se odesílá.';
    card.appendChild(img);
    card.appendChild(title);
    card.appendChild(overlayText);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
  };

  const showOverlay = (text) => {
    if (!overlay || !overlayText) return;
    overlayText.textContent = text;
    overlay.classList.remove('webapp-hidden');
  };

  const hideOverlay = () => {
    if (!overlay) return;
    overlay.classList.add('webapp-hidden');
  };

  const registerDevice = async () => {
    const stored = ensureDeviceState();
    const displayName = (stored.display_name || '').trim();
    const payload = {
      device_id: stored.device_id,
      display_name: displayName || undefined,
      device_info: {
        ua: navigator.userAgent,
        platform: navigator.platform || '',
        fp: stored.fp
      }
    };
    await fetchJson('/api/device/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await fetchJson(`/api/device/status?device_id=${encodeURIComponent(stored.device_id)}`, {
      headers: { 'X-Device-Id': stored.device_id }
    });
    const status = data.status || 'UNKNOWN';
    if (data.display_name) {
      const nextState = { ...stored, display_name: data.display_name };
      saveState(nextState);
      state.displayName = data.display_name;
    }
    const detail = status === 'ACTIVE'
      ? 'Zařízení je aktivní.'
      : status === 'REVOKED'
        ? 'Zařízení bylo zablokováno správcem.'
        : 'Zařízení čeká na aktivaci.';
    setStatus(status, detail);
    setDeviceCookie(state.deviceId);
  };

  const renderRooms = () => {
    if (!ui.roomGrid) return;
    ui.roomGrid.querySelectorAll('[data-room]').forEach((btn) => {
      btn.addEventListener('click', () => {
        ui.roomGrid.querySelectorAll('[data-room]').forEach((el) => el.classList.remove('is-active'));
        btn.classList.add('is-active');
        state.selectedRoom = Number(btn.dataset.room);
      });
    });
  };

  const updateDescCount = () => {
    if (!ui.description || !ui.descCount) return;
    const len = ui.description.value.trim().length;
    ui.descCount.textContent = `${len}/50`;
  };

  const clearPhotos = () => {
    state.files = [];
    state.urls.forEach((url) => URL.revokeObjectURL(url));
    state.urls.clear();
    renderPhotos();
  };

  const addFiles = (fileList) => {
    const incoming = Array.from(fileList || []);
    incoming.forEach((file) => {
      if (state.files.length >= 5) return;
      if (!file.type.startsWith('image/')) return;
      state.files.push(file);
    });
    renderPhotos();
  };

  const renderPhotos = () => {
    if (!ui.photoPreview || !ui.photoCount) return;
    state.urls.forEach((url) => URL.revokeObjectURL(url));
    state.urls.clear();
    ui.photoPreview.innerHTML = '';
    ui.photoCount.textContent = `${state.files.length}/5`;
    state.files.forEach((file, idx) => {
      const thumb = document.createElement('div');
      thumb.className = 'photo-thumb';
      const img = document.createElement('img');
      const url = URL.createObjectURL(file);
      state.urls.set(file, url);
      img.src = url;
      img.alt = `Foto ${idx + 1}`;
      const removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.textContent = '×';
      removeBtn.addEventListener('click', () => {
        state.files.splice(idx, 1);
        renderPhotos();
      });
      thumb.appendChild(img);
      thumb.appendChild(removeBtn);
      ui.photoPreview.appendChild(thumb);
    });
  };

  const bindPhotoInputs = () => {
    if (ui.inputCamera) {
      ui.inputCamera.addEventListener('change', (event) => addFiles(event.target.files));
    }
    if (ui.inputGallery) {
      ui.inputGallery.addEventListener('change', (event) => addFiles(event.target.files));
    }
    if (ui.inputDesktop) {
      ui.inputDesktop.addEventListener('change', (event) => addFiles(event.target.files));
    }
    if (ui.cameraBtn && ui.inputCamera) {
      ui.cameraBtn.addEventListener('click', () => ui.inputCamera.click());
    }
    if (ui.galleryBtn && ui.inputGallery) {
      ui.galleryBtn.addEventListener('click', () => ui.inputGallery.click());
    }
    if (ui.desktopBtn && ui.inputDesktop) {
      ui.desktopBtn.addEventListener('click', () => ui.inputDesktop.click());
    }
  };

  const submitReport = async (event) => {
    event.preventDefault();
    clearAlerts();
    if (state.status !== 'ACTIVE') {
      showError('Zařízení není aktivní. Požádejte administrátora o aktivaci.');
      return;
    }
    if (!state.selectedRoom) {
      showError('Vyberte pokoj.');
      return;
    }
    const desc = ui.description ? ui.description.value.trim() : '';
    if (desc.length > 50) {
      showError('Popis je příliš dlouhý.');
      return;
    }
    let reportType = 'FIND';
    ui.typeInputs.forEach((input) => {
      if (input.checked) reportType = input.value;
    });
    const formData = new FormData();
    formData.append('type', reportType);
    formData.append('room', String(state.selectedRoom));
    if (desc) formData.append('description', desc);
    formData.append('createdAtEpochMs', String(Date.now()));
    state.files.forEach((file) => formData.append('photos', file, file.name));
    showOverlay('Vyčkejte prosím, hlášení se odesílá.');
    try {
      await fetchJson('/api/reports', {
        method: 'POST',
        headers: { 'X-Device-Id': state.deviceId },
        body: formData
      });
      if (ui.description) ui.description.value = '';
      updateDescCount();
      clearPhotos();
      showSuccess('Vaše hlášení bylo odesláno.', true);
      overlayText.textContent = 'Vaše hlášení bylo odesláno.';
      window.scrollTo({ top: 0, behavior: 'smooth' });
      setTimeout(() => {
        hideOverlay();
      }, 3000);
    } catch (err) {
      hideOverlay();
      showError('Odeslání se nezdařilo. Zkuste to prosím znovu.');
    }
  };

  const formatDate = (iso) => {
    if (!iso) return '';
    const dt = new Date(iso);
    if (Number.isNaN(dt.getTime())) return iso;
    return dt.toLocaleString('cs-CZ', { dateStyle: 'short', timeStyle: 'short' });
  };

  const formatDateOnly = (isoDate) => {
    if (!isoDate) return '';
    const parts = isoDate.split('-').map((x) => Number(x));
    if (parts.length !== 3 || parts.some((n) => Number.isNaN(n))) return isoDate;
    const dt = new Date(parts[0], parts[1] - 1, parts[2]);
    return dt.toLocaleDateString('cs-CZ', { dateStyle: 'medium' });
  };

  const todayIso = () => {
    const now = new Date();
    const y = now.getFullYear();
    const m = String(now.getMonth() + 1).padStart(2, '0');
    const d = String(now.getDate()).padStart(2, '0');
    return `${y}-${m}-${d}`;
  };

  const addDaysIso = (isoDate, delta) => {
    const [y, m, d] = isoDate.split('-').map((x) => Number(x));
    const dt = new Date(y, m - 1, d);
    dt.setDate(dt.getDate() + delta);
    const yy = dt.getFullYear();
    const mm = String(dt.getMonth() + 1).padStart(2, '0');
    const dd = String(dt.getDate()).padStart(2, '0');
    return `${yy}-${mm}-${dd}`;
  };

  const renderReports = (items) => {
    if (!ui.reportList) return;
    ui.reportList.innerHTML = '';
    if (!items.length) {
      const empty = document.createElement('div');
      empty.className = 'report-empty';
      empty.textContent = 'Žádné otevřené položky.';
      ui.reportList.appendChild(empty);
      return;
    }
    items.forEach((report) => {
      const card = document.createElement('div');
      card.className = 'report-card';
      const title = document.createElement('div');
      title.className = 'report-title';
      title.textContent = `Pokoj ${report.room}`;
      const meta = document.createElement('div');
      meta.className = 'report-meta';
      const created = document.createElement('span');
      created.textContent = formatDate(report.createdAt);
      const type = document.createElement('span');
      type.textContent = report.type === 'ISSUE' ? 'Závada' : 'Nález';
      meta.appendChild(created);
      meta.appendChild(type);
      if (report.description) {
        const desc = document.createElement('div');
        desc.textContent = report.description;
        card.appendChild(title);
        card.appendChild(desc);
      } else {
        card.appendChild(title);
      }
      card.appendChild(meta);
      const actions = document.createElement('div');
      actions.className = 'webapp-actions';
      const doneBtn = document.createElement('button');
      doneBtn.type = 'button';
      doneBtn.className = 'webapp-button primary';
      doneBtn.textContent = role === 'frontdesk' ? 'Ztráta zpracována' : 'PRÁVĚ JSEM OPRAVIL';
      doneBtn.addEventListener('click', async () => {
        clearAlerts();
        await fetchJson(`/api/reports/mark-done?id=${encodeURIComponent(report.id)}`, {
          method: 'POST',
          headers: { 'X-Device-Id': state.deviceId }
        });
        showSuccess('Označeno jako vyřízené.');
        await loadReports();
      });
      actions.appendChild(doneBtn);
      if (Array.isArray(report.thumbnailUrls) && report.thumbnailUrls.length) {
        const photos = document.createElement('div');
        photos.className = 'photo-strip';
        photos.style.marginTop = '12px';
        report.thumbnailUrls.forEach((url) => {
          const thumb = document.createElement('div');
          thumb.className = 'photo-thumb';
          const img = document.createElement('img');
          const sep = url.includes('?') ? '&' : '?';
          img.src = `${url}${sep}device_id=${encodeURIComponent(state.deviceId)}`;
          img.alt = 'Foto závady';
          img.loading = 'lazy';
          thumb.appendChild(img);
          photos.appendChild(thumb);
        });
        card.appendChild(photos);
      } else {
        const noPhoto = document.createElement('div');
        noPhoto.className = 'webapp-muted';
        noPhoto.style.marginTop = '8px';
        noPhoto.textContent = 'Požadavek odeslán bez fotografií.';
        card.appendChild(noPhoto);
      }
      card.appendChild(actions);
      ui.reportList.appendChild(card);
    });
  };

  const loadReports = async () => {
    if (state.status !== 'ACTIVE') return;
    const category = role === 'maintenance' ? 'ISSUE' : 'FIND';
    const data = await fetchJson(`/api/reports/open?category=${category}`, {
      headers: { 'X-Device-Id': state.deviceId }
    });
    renderReports(data.items || []);
  };

  const setBreakfastTotal = (count) => {
    if (!ui.breakfastTotal) return;
    if (typeof count === 'number' && !Number.isNaN(count)) {
      const label = count === 1 ? 'snídaně' : count >= 2 && count <= 4 ? 'snídaně' : 'snídaní';
      ui.breakfastTotal.textContent = `${count} ${label}`;
    } else {
      ui.breakfastTotal.textContent = '—';
    }
  };

  const setBreakfastHeader = (isoDate, statusText, totalCount = null) => {
    if (ui.breakfastDate) ui.breakfastDate.textContent = formatDateOnly(isoDate);
    if (ui.breakfastStatusText) ui.breakfastStatusText.textContent = statusText || '';
    setBreakfastTotal(totalCount);
  };

  const renderBreakfast = (items, status) => {
    if (!ui.breakfastList) return;
    ui.breakfastList.innerHTML = '';

    if (status === 'MISSING') {
      const empty = document.createElement('div');
      empty.className = 'breakfast-empty';
      empty.textContent = 'Nenalezeno / čeká se na stažení přehledu.';
      ui.breakfastList.appendChild(empty);
      return;
    }

    if (!items || !items.length) {
      const empty = document.createElement('div');
      empty.className = 'breakfast-empty';
      empty.textContent = 'Žádné pokoje se snídaní.';
      ui.breakfastList.appendChild(empty);
      return;
    }

    items.forEach((it) => {
      const row = document.createElement('div');
      row.className = 'breakfast-row';
      const left = document.createElement('div');
      left.className = 'breakfast-left';
      const room = document.createElement('div');
      room.className = 'breakfast-room';
      room.textContent = `Pokoj ${it.room}`;
      left.appendChild(room);
      if (it.name) {
        const name = document.createElement('div');
        name.className = 'breakfast-name';
        name.textContent = it.name;
        left.appendChild(name);
      }
      const meta = document.createElement('div');
      meta.className = 'breakfast-meta';
      meta.textContent = `${it.count} ${
        it.count === 1 ? 'osoba' : it.count >= 2 && it.count <= 4 ? 'osoby' : 'osob'
      }`;
      left.appendChild(meta);
      row.appendChild(left);

      const actions = document.createElement('div');
      actions.className = 'webapp-actions';

      const checked = Boolean(it.checkedAt || it.checkedBy);
      if (checked) {
        row.classList.add('is-checked');
        const done = document.createElement('div');
        done.className = 'webapp-pill';
        done.textContent = 'Označeno';
        actions.appendChild(done);
      } else {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'webapp-button primary';
        btn.textContent = 'Byl na snídani';
        btn.addEventListener('click', async () => {
          clearAlerts();
          try {
            await fetchJson('/api/v1/breakfast/check', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-Device-Id': state.deviceId
              },
              body: JSON.stringify({ date: state.breakfastDate, room: it.room })
            });
            await loadBreakfast(state.breakfastDate);
          } catch (e) {
            showError('Označení se nezdařilo.');
          }
        });
        actions.appendChild(btn);
      }

      row.appendChild(actions);
      ui.breakfastList.appendChild(row);
    });
  };

  const normalizeBreakfastItems = (list) => {
    return (list || []).map((it) => ({
      ...it,
      name: it.name || it.guestName || it.guest_name || null
    }));
  };

  const loadBreakfast = async (isoDate) => {
    if (state.status !== 'ACTIVE') return;
    const target = isoDate || todayIso();
    state.breakfastDate = target;
    setBreakfastHeader(target, 'Načítám...', null);
    try {
      const data = await fetchJson(`/api/v1/breakfast/day?date=${encodeURIComponent(target)}`, {
        headers: { 'X-Device-Id': state.deviceId }
      });
      const items = normalizeBreakfastItems(data.items).slice().sort((a, b) => Number(a.room) - Number(b.room));
      const status = data.status || (items.length ? 'FOUND' : 'MISSING');
      const total = items.reduce((sum, it) => sum + (Number(it.count) || 0), 0);
      setBreakfastHeader(target, status === 'MISSING' ? 'Nenalezeno / čeká se' : '', total);
      renderBreakfast(items, status);
    } catch (e) {
      setBreakfastHeader(target, 'Nepodařilo se načíst.', null);
      if (ui.breakfastList) {
        ui.breakfastList.innerHTML = '';
        const empty = document.createElement('div');
        empty.className = 'breakfast-empty';
        empty.textContent = 'Nepodařilo se načíst přehled.';
        ui.breakfastList.appendChild(empty);
      }
    }
  };

  const bindBreakfastNav = () => {
    if (!ui.breakfastPrev || !ui.breakfastNext) return;
    ui.breakfastPrev.addEventListener('click', () => {
      const next = addDaysIso(state.breakfastDate || todayIso(), -1);
      loadBreakfast(next).catch(() => {});
    });
    ui.breakfastNext.addEventListener('click', () => {
      const next = addDaysIso(state.breakfastDate || todayIso(), 1);
      loadBreakfast(next).catch(() => {});
    });
  };

  const init = async () => {
    setMode();
    window.addEventListener('resize', setMode);
    renderRooms();
    bindPhotoInputs();
    createOverlay();
    if (ui.description) {
      ui.description.addEventListener('input', updateDescCount);
      updateDescCount();
    }
    if (ui.form) ui.form.addEventListener('submit', submitReport);
    if (ui.refreshBtn) ui.refreshBtn.addEventListener('click', loadReports);
    if (role === 'breakfast') {
      bindBreakfastNav();
      state.breakfastDate = todayIso();
      if (ui.breakfastDate) ui.breakfastDate.textContent = formatDateOnly(state.breakfastDate);
    }
    try {
      await registerDevice();
      if (role === 'breakfast') {
        await loadBreakfast(state.breakfastDate || todayIso());
        refreshTimer = window.setInterval(() => {
          if (document.visibilityState === 'visible' && state.status === 'ACTIVE') {
            loadBreakfast(state.breakfastDate || todayIso()).catch(() => {});
          }
        }, 30000);
      } else if (role !== 'housekeeping') {
        await loadReports();
        refreshTimer = window.setInterval(() => {
          if (document.visibilityState === 'visible' && state.status === 'ACTIVE') {
            loadReports().catch(() => {});
          }
        }, 30000);
      }
    } catch (err) {
      setStatus('UNKNOWN', 'Nepodařilo se načíst stav zařízení.');
      showError('Nelze se připojit k serveru.');
    }
  };

  init();
})();
