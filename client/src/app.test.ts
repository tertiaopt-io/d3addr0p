import { describe, it, expect } from 'vitest';
import {
  renderTransmit,
  renderShell,
  isNativeShell,
  renderUnlock,
  renderChannels,
  renderKeyExchange,
  renderIdentity,
  renderAway,
  renderGetInfo,
  renderBuddies,
  renderBuddySetup,
  renderAddPerson,
  renderProvisioning,
  renderNewDeviceWizard,
  renderSettings,
  renderBuddyScan,
  renderBuddyQr,
  renderAppearance,
  sanitizeAppearance,
  sanitizeMessageLook,
  wrapMessageLook,
  isValidTokenValue,
  parseContactLink,
  formatMessageText,
  escapeHtml,
  DemoController,
  DEFAULT_IDENTITY,
  DEFAULT_APPEARANCE,
  THEME_CLASS,
  LOCKED_MODEL,
  type TransmitModel,
  type IdentityProfile,
  type PeerIdentity,
  type BuddyVerifyInfo,
  type Buddy,
  type GroupSummary,
  type BlockedContact,
  type Appearance,
} from './app.js';

describe('transmit renderer (M5 skin)', () => {
  it('renders the locked initial state with no peer sub-line', () => {
    const html = renderTransmit(LOCKED_MODEL);
    expect(html).toContain('class="dd-bar"');
    expect(html).toContain('OFFLINE');
    expect(html).not.toContain('dd-sub'); // no peer yet
    expect(html).toContain('channel locked');
    expect(html).toContain('class="dd-cursor"');
  });

  it('renders a secure conversation with peer fingerprint and a burn countdown', () => {
    const model: TransmitModel = {
      secure: true,
      peer: 'RAVEN',
      fingerprint: '5F·A2·91·C4',
      log: [
        { kind: 'message', sender: 'RAVEN', text: 'package received', lifetime: { kind: 'duration', seconds: 90 }, remainingSeconds: 84 },
        { kind: 'destroyed' },
      ],
      compose: 'en route',
      conversationId: 'raven',
    };
    const html = renderTransmit(model);
    expect(html).toContain('<span class="dd-tx"></span>SECURE');
    expect(html).toContain('class="dd-sub"');
    expect(html).toContain('5F·A2·91·C4');
    expect(html).toContain('burns 1:24'); // 84s formatted mm:ss
    expect(html).toContain('▢ message destroyed');
    // AIM23: the two-icon column (peer slot on top, self slot below) is present for a peer conversation.
    expect(html).toContain('class="dd-chat-icons" data-dd-chaticons="raven"');
    expect(html).toContain('data-icon-slot="peer"');
    expect(html).toContain('data-icon-slot="self"');
    // AIM23: an inbound peer message renders inline as "RAVEN:" in the peer color.
    expect(html).toContain('dd-name dd-name-peer');
    expect(html).toContain('RAVEN:');
  });

  it('shows only the self icon (no peer slot) in the Note-to-Self column', () => {
    const html = renderTransmit({
      secure: true,
      peer: 'you',
      fingerprint: null,
      log: [],
      compose: '',
      conversationId: 'self',
      selfNote: true,
    });
    expect(html).toContain('dd-chat-icons-solo');
    expect(html).toContain('data-icon-slot="self"');
    expect(html).not.toContain('data-icon-slot="peer"');
  });

  it('omits the icon column entirely when no conversation is open', () => {
    expect(renderTransmit(LOCKED_MODEL)).not.toContain('dd-chat-icons');
  });

  it('renders the AIM-style IM toolbar: Profile, Add Buddy (only for a known non-buddy), Attach File, Call, Video, Block', () => {
    const base: TransmitModel = {
      secure: true,
      peer: 'RAVEN',
      fingerprint: 'AA',
      peerHandle: 'raven',
      peerIsBuddy: false,
      log: [],
      compose: '',
      conversationId: 'c1',
    };
    const html = renderTransmit(base);
    expect(html).toContain('dd-imbar');
    expect(html).toContain('>Profile</span>');
    expect(html).toContain('data-action="add-buddy"');
    expect(html).toContain('>Add Buddy</span>');
    expect(html).toContain('>Attach File</span>');
    expect(html).toContain('>Call</span>');
    expect(html).toContain('>Video</span>');
    expect(html).toContain('>Block</span>');
    // The old sub-line text links are gone; the sub keeps only the name + key line.
    expect(html).not.toContain('data-action="add-person"');
    expect(html).not.toContain('>Get Info<');
    // Already a buddy: Add Buddy disappears; everything else stays.
    const buddy = renderTransmit({ ...base, peerIsBuddy: true });
    expect(buddy).not.toContain('data-action="add-buddy"');
    expect(buddy).toContain('>Profile</span>');
    // No known handle (an inbound stranger): Add Buddy is absent too (nothing to add by name).
    const stranger = renderTransmit({ ...base, peerHandle: null });
    expect(stranger).not.toContain('data-action="add-buddy"');
    // Offline: the live-session actions dim, the stored-data actions stay active.
    const offline = renderTransmit({ ...base, secure: false });
    expect(offline).toContain('data-action="send-file" disabled');
    expect(offline).toContain('data-action="call-audio" disabled');
    expect(offline).toContain('data-action="call-video" disabled');
    expect(offline).not.toContain('data-action="get-info" disabled');
  });

  it('renders Note to Self without any peer controls (no Add, so no peer can enter the self-group)', () => {
    const model: TransmitModel = {
      secure: true,
      peer: 'Note to Self',
      fingerprint: null,
      selfNote: true,
      log: [{ kind: 'message', sender: 'YOU', text: 'remember the drop', lifetime: { kind: 'until-revoked' }, remainingSeconds: null }],
      compose: '',
      conversationId: 'c-self',
    };
    const html = renderTransmit(model);
    expect(html).toContain('Note to Self');
    expect(html).toContain('only your devices see this');
    // The self-group split diagnostic rides this subtitle: the group id alone could not say WHICH
    // device minted, so roster size and the Welcome counters go on screen next to it (the phone has
    // no console, and device-local MLS state is invisible to the keyless gateway).
    const diagnosed = renderTransmit({ ...model, selfDiag: '2 devices · W1/0 · NoMatchingKeyPackage' });
    expect(diagnosed).toContain('group self');
    expect(diagnosed).toContain('2 devices');
    expect(diagnosed).toContain('W1/0');
    expect(diagnosed).toContain('NoMatchingKeyPackage');
    expect(html).not.toContain('W1/0'); // absent when there is nothing to report
    // The peer-only controls must be absent: Add would inject a peer into the own-devices self-group.
    expect(html).not.toContain('data-action="add-person"');
    expect(html).not.toContain('data-action="get-info"');
    expect(html).not.toContain('data-action="block-peer"');
    expect(html).not.toContain('data-action="call-audio"');
    // The bottom toolbar keeps Attach File: files ride to your own devices over the self-group.
    expect(html).toContain('dd-imbar');
    expect(html).toContain('data-action="send-file"');
    // The compose form is still present so you can jot notes.
    expect(html).toContain('id="dd-compose-form"');
  });

  it('leads the compose toolbar with the ⏳ lifetime picker and offers a never-expires option', () => {
    const html = renderTransmit({ secure: true, peer: 'RAVEN', fingerprint: 'AA', log: [], compose: '', conversationId: 'c1' });
    // The picker is the FIRST control on the bar (it governs the whole message, so it reads first).
    expect(html.indexOf('data-rt-pop="timer"')).toBeLessThan(html.indexOf('data-rt-pop="color"'));
    expect(html).toContain('Never (revocable)'); // the until-revoked kind, labeled by what it does
  });

  it('labels burn and until-revoked messages, and offers revoke only on our own revocable message', () => {
    const model: TransmitModel = {
      secure: true,
      peer: 'RAVEN',
      fingerprint: 'AA',
      log: [
        { kind: 'message', sender: 'RAVEN', text: 'one look', lifetime: { kind: 'burn-on-read' }, remainingSeconds: null },
        { kind: 'message', sender: 'YOU', text: 'recallable', lifetime: { kind: 'until-revoked' }, remainingSeconds: null, messageId: 'm1', canRevoke: true },
        { kind: 'message', sender: 'RAVEN', text: 'their keeper', lifetime: { kind: 'until-revoked' }, remainingSeconds: null },
      ],
      compose: '',
      conversationId: 'raven',
    };
    const html = renderTransmit(model);
    expect(html).toContain('burns after this viewing');
    expect(html).toContain('kept until revoked');
    // Exactly ONE revoke control: on our own until-revoked message, never on a peer's.
    expect(html).toContain('data-action="revoke-msg" data-mid="m1"');
    expect((html.match(/data-action="revoke-msg"/g) ?? []).length).toBe(1);
  });

  it('marks a near-expiry message with the warn/throb classes', () => {
    const model: TransmitModel = {
      secure: true,
      peer: 'RAVEN',
      fingerprint: 'AA',
      log: [{ kind: 'message', sender: 'YOU', text: 'moving now', lifetime: { kind: 'duration', seconds: 30 }, remainingSeconds: 6 }],
      compose: '',
      conversationId: 'raven',
    };
    const html = renderTransmit(model);
    expect(html).toContain('dd-line dd-warn');
    expect(html).toContain('dd-meta dd-warn dd-near');
    expect(html).toContain('burns 0:06');
    // AIM-style inline line: 'YOU' is labelled as the self-colored name.
    expect(html).toContain('dd-name dd-name-self');
    expect(html).toContain('YOU:');
  });

  it('stamps the absolute expiry on an armed-duration burn so the countdown can tick live (AIM25)', () => {
    const at = 1_700_000_000_000;
    const withExpiry = renderTransmit({
      secure: true,
      peer: 'RAVEN',
      fingerprint: 'AA',
      log: [{ kind: 'message', sender: 'YOU', text: 'go', lifetime: { kind: 'duration', seconds: 90 }, remainingSeconds: 84, expiresAtMs: at }],
      compose: '',
      conversationId: 'r',
    });
    expect(withExpiry).toContain(`data-expires-at="${at}"`);
    // A message with no absolute expiry (unarmed / until-revoked) carries NO stamp, so the ticker skips it.
    const noExpiry = renderTransmit({
      secure: true,
      peer: 'RAVEN',
      fingerprint: 'AA',
      log: [{ kind: 'message', sender: 'YOU', text: 'kept', lifetime: { kind: 'until-revoked' }, remainingSeconds: null }],
      compose: '',
      conversationId: 'r',
    });
    expect(noExpiry).not.toContain('data-expires-at');
  });

  it('HTML-escapes attacker-influenced message text, sender, peer, and compose', () => {
    const xss = '<img src=x onerror=alert(1)>';
    const model: TransmitModel = {
      secure: true,
      peer: xss,
      fingerprint: '"><script>',
      log: [{ kind: 'message', sender: xss, text: xss, lifetime: { kind: 'burn-on-read' }, remainingSeconds: null }],
      compose: xss,
      conversationId: 'x',
    };
    const html = renderTransmit(model);
    expect(html).not.toContain('<img src=x'); // raw tag never present
    expect(html).not.toContain('<script>');
    expect((html.match(/&lt;img src=x/g) ?? []).length).toBeGreaterThanOrEqual(3); // text, sender, peer, compose
  });

  it('escapeHtml handles all the dangerous characters', () => {
    expect(escapeHtml(`&<>"'`)).toBe('&amp;&lt;&gt;&quot;&#39;');
  });
});

describe('chrome shell + screens (M5)', () => {
  it('renders the desktop chrome around a conversation with the embedded terminal', () => {
    const html = renderShell({ kind: 'conversation', transmit: { ...LOCKED_MODEL, peer: 'RAVEN' } });
    expect(html).toContain('class="dd-menubar"');
    expect(html).toContain('Channels');
    expect(html).toContain('class="dd-window"');
    expect(html).toContain('class="dd-titlebar"');
    expect(html).toContain('class="dd-content-well"');
    expect(html).toContain('class="dd-scrollbar"');
    expect(html).not.toContain('dd-growbox'); // non-functional decorations removed
    // Every signed-in window has functional minimize / close controls (minimize goes to the menu bar).
    expect(html).toContain('data-action="win-minimize"');
    expect(html).toContain('data-action="win-close"');
    expect(html).toContain('<div class="dd">'); // the terminal lives inside the window
    expect(html).toContain('>TRANSMIT · RAVEN</span>');
    expect(html).not.toContain('dd-menu-clock'); // the clock is gone (it overflowed the bar on mobile)
    expect(html).not.toContain('id="dd-clock"');
  });

  it('shows the menu bar only once signed in, not on the unlock or device-join screens', () => {
    expect(renderShell({ kind: 'unlock' })).not.toContain('dd-menubar');
    expect(renderShell({ kind: 'newdevice-wizard', state: { step: 'choose', connected: false } })).not.toContain('dd-menubar');
    expect(renderShell({ kind: 'recovery', secret: 'ab'.repeat(16) })).not.toContain('dd-menubar');
    // Signed-in screens keep it.
    expect(renderShell({ kind: 'channels', channels: [] })).toContain('dd-menubar');
    expect(renderShell({ kind: 'identity', profile: DEFAULT_IDENTITY })).toContain('dd-menubar');
  });

  it('exposes window controls on the unlock screen ONLY inside the native shell (dd-native)', () => {
    // Web: no window controls on the unlock/guided flows (no OS window, no escape hatch into the app).
    expect(isNativeShell()).toBe(false);
    expect(renderShell({ kind: 'unlock' })).not.toContain('data-action="win-close"');
    const g = globalThis as unknown as { __ddShell?: unknown };
    try {
      g.__ddShell = { native: true, minimize() {}, close() {} };
      expect(isNativeShell()).toBe(true);
      // Native: the OS window needs minimize/close on every screen, the unlock screen included.
      const html = renderShell({ kind: 'unlock' });
      expect(html).toContain('data-action="win-minimize"');
      expect(html).toContain('data-action="win-close"');
    } finally {
      delete g.__ddShell;
    }
    expect(isNativeShell()).toBe(false);
  });

  it('dispatches the window content per view', () => {
    expect(renderShell({ kind: 'unlock' })).toContain('id="dd-unlock-form"');
    expect(renderShell({ kind: 'unlock' })).toContain('>DEAD DROP</div>'); // unlock title
    expect(renderShell({ kind: 'channels', channels: [] })).toContain('no channels yet');
    expect(renderShell({ kind: 'channels', channels: [] })).toContain('>CHANNELS</span>');
    expect(renderShell({ kind: 'away', profile: DEFAULT_IDENTITY })).toContain('>AWAY MESSAGE</span>');
  });

  it('anchors the DEAD DROP menu at the titlebar top-left and brands the menu bar with the logo', () => {
    const html = renderShell({ kind: 'buddies', buddies: [], groups: [], statuses: {}, collapsed: [], blocked: [], selected: [], profile: DEFAULT_IDENTITY, ownName: 'me', icons: {}, awayText: {} });
    // The app-menu trigger lives INSIDE the buddy-list titlebar (before the title), top-left as window
    // decoration.
    const bar = html.slice(html.indexOf('dd-titlebar'), html.indexOf('dd-window-body'));
    expect(bar).toContain('data-action="app-menu"');
    expect(bar.indexOf('data-action="app-menu"')).toBeLessThan(bar.indexOf('dd-title"'));
    expect(bar).toContain('dd-winmenu');
    // The menu bar ALSO carries a working DEAD DROP menu (logo + name), reachable from every screen.
    const menubar = html.slice(html.indexOf('dd-menubar'), html.indexOf('dd-stage'));
    expect(menubar).toContain('dd-logo-ic');
    expect(menubar).toContain('DEAD DROP');
    expect(menubar).toContain('data-action="app-menu"'); // the brand is a real dropdown trigger now
    expect(menubar).toContain('dd-appmenu-pop');
    expect(menubar).not.toContain('◆');
    // The two-pane Channels window carries the titlebar menu too (for Pop out / Device keys), but a
    // TRANSIENT window (e.g. Get Info) does NOT — only buddies, conversation, and channels do.
    const gi = renderShell({ kind: 'getinfo', conversationId: '', peer: 'X', peers: [] });
    expect(gi.slice(gi.indexOf('dd-titlebar'), gi.indexOf('dd-window-body'))).not.toContain('data-action="app-menu"');
    // The guided/sensitive flows still get no menu at all (no escape hatch).
    expect(renderShell({ kind: 'unlock' })).not.toContain('data-action="app-menu"');
  });

  it('shows the logo hero (mark + wordmark) at the top of the unlock screen', () => {
    for (const mode of ['login', 'register'] as const) {
      const html = renderUnlock(undefined, mode);
      expect(html).toContain('dd-logo-hero');
      expect(html).toContain('dd-logo-mark');
      expect(html).toContain('dd-logo-word');
      // The hero leads the form (before the inputs), and the mark is a CSP-safe inline SVG.
      expect(html.indexOf('dd-logo-hero')).toBeLessThan(html.indexOf('dd-input'));
      expect(html).toContain('fill-rule="evenodd"');
      expect(html).not.toContain('style=');
    }
  });

  it('keeps only Device keys and Self Destruct in the DEAD DROP dropdown (everything social lives on the buddy list)', () => {
    const html = renderShell({ kind: 'channels', channels: [] });
    expect(html).toContain('data-action="app-menu"'); // the DEAD DROP trigger toggles the dropdown
    expect(html).toContain('dd-appmenu-pop'); // the dropdown panel the trigger toggles
    expect(html).toContain('data-action="device-keys"');
    expect(html.indexOf('data-action="device-keys"')).toBeLessThan(html.indexOf('data-action="self-destruct"'));
    // Away message, Profile, Buddy List Setup, and Note to Self all moved to the buddy-list surfaces.
    expect(html).not.toContain('data-action="away-message"');
    expect(html).not.toContain('data-action="identity-menu"');
    expect(html).not.toContain('data-action="buddy-setup"');
    expect(html).not.toContain('data-action="note-to-self"');
    // Top order is Buddies before Channels.
    expect(html.indexOf('>Buddies</span>')).toBeLessThan(html.indexOf('>Channels</span>'));
  });

  it('HTML-escapes the peer in a conversation title', () => {
    const html = renderShell({ kind: 'conversation', transmit: { ...LOCKED_MODEL, peer: '<b>X</b>' } });
    expect(html).toContain('TRANSMIT · &lt;b&gt;X&lt;/b&gt;');
    expect(html).not.toContain('<b>X</b>');
  });
});

describe('unlock screen', () => {
  it('renders a username field, a passphrase field, unlock button, and the credential note', () => {
    const html = renderUnlock();
    expect(html).toContain('id="dd-user"');
    expect(html).toContain('id="dd-pass"');
    expect(html).toContain('type="password"');
    expect(html).toContain('>Unlock</button>');
    expect(html).toContain('Account recovery is impossible');
    expect(html).toContain('keep them somewhere only you can reach');
  });

  it('shows an error message, escaped', () => {
    expect(renderUnlock('<x>bad')).toContain('&lt;x&gt;bad');
  });

  it('credits the project with a link back, on both the login and the create-account screen', () => {
    for (const mode of ['login', 'register'] as const) {
      const html = renderUnlock(undefined, mode);
      expect(html).toContain('href="https://tertiaopt.io"');
      expect(html).toContain('tertiaopt.io</a> project');
      expect(html).toContain('rel="noopener noreferrer"'); // the opened page cannot reach back into ours
    }
  });

  it('shows the pitch, the protocol comparison, and the desktop downloads on the WEB login screen', () => {
    const html = renderUnlock();
    // The pitch: presence you declare, and the deliberate absence of a mobile client.
    expect(html).toContain('A messenger that lets you be gone.');
    expect(html).toContain('ships no mobile client on purpose');
    // The comparison is about protocol design, so the protocol row must be there by name.
    expect(html).toContain('How the two are built');
    expect(html).toContain('MLS (RFC 9420)');
    expect(html).toContain('Double Ratchet');
    // The rows that keep it honest about what this project does not have.
    expect(html).toContain('Independent audit');
    expect(html).toContain('None. This is a young project.');
    expect(html).toContain('for almost everyone it is the right');
    expect(html).toContain('github.com/tertiaopt-io/d3addr0p/releases');
    expect(html).toContain('DEAD-DROP-win-x64.zip');
  });

  it('hides the comparison and the downloads inside the native shell, keeping the credit', () => {
    const g = globalThis as { __ddShell?: { native: boolean } };
    g.__ddShell = { native: true }; // the desktop app: it IS the thing those panels advertise
    try {
      const html = renderUnlock();
      expect(html).not.toContain('How the two are built');
      expect(html).not.toContain('lets you be gone');
      expect(html).not.toContain('releases/latest/download');
      expect(html).toContain('tertiaopt.io'); // attribution is not marketing: it stays
    } finally {
      delete g.__ddShell;
    }
  });
});

describe('channels list', () => {
  const channels = [
    { id: 'raven', peer: 'RAVEN', fingerprint: '5F', status: 'secure' as const, preview: 'hi', unread: 2 },
    { id: 'wren', peer: '<b>WREN</b>', fingerprint: 'C2', status: 'blocked' as const, preview: '<img>', unread: 0 },
  ];

  it('renders a row per channel with status, fingerprint, and an unread badge', () => {
    const html = renderChannels(channels);
    expect(html).toContain('data-channel="raven"');
    expect(html).toContain('dd-status-secure');
    expect(html).toContain('dd-status-blocked');
    expect(html).toContain('class="dd-badge">2<');
    expect(html).toContain('key 5F');
  });

  it('HTML-escapes attacker-influenced peer and preview', () => {
    const html = renderChannels(channels);
    expect(html).not.toContain('<b>WREN</b>');
    expect(html).not.toContain('<img>');
    expect(html).toContain('&lt;b&gt;WREN&lt;/b&gt;');
  });

  it('shows an empty state when there are no channels', () => {
    expect(renderChannels([])).toContain('no channels yet');
  });
});

describe('appearance / theming (AIM18 + AIM19 prefs window)', () => {
  it('validates token values: hex/rgb colors, allowlisted fonts + sizes pass; anything else is rejected', () => {
    expect(isValidTokenValue('--dd-ink', '#2be000')).toBe(true);
    expect(isValidTokenValue('--dd-ink', '#fff')).toBe(true);
    expect(isValidTokenValue('--dd-secure', 'rgba(0, 255, 65, 0.5)')).toBe(true);
    expect(isValidTokenValue('--dd-buddy-ink', '#e0504a')).toBe(true);
    // fonts: the editor bench (RT_FONTS faces) and the legacy AIM18 stacks both pass
    expect(isValidTokenValue('--dd-font-msg', 'Verdana, Geneva, sans-serif')).toBe(true);
    expect(isValidTokenValue('--dd-buddy-font', '"Comic Sans MS", "Comic Sans", cursive')).toBe(true);
    expect(isValidTokenValue('--dd-font-msg', 'Georgia, "Times New Roman", Times, serif')).toBe(true); // legacy stack
    // sizes: the fixed step list only
    expect(isValidTokenValue('--dd-buddy-size', '12px')).toBe(true);
    expect(isValidTokenValue('--dd-msg-user-size', '18px')).toBe(true);
    expect(isValidTokenValue('--dd-buddy-size', '99px')).toBe(false);
    expect(isValidTokenValue('--dd-msg-user-size', '12')).toBe(false);
    expect(isValidTokenValue('--dd-msg-user-size', 'calc(1px + 1vh)')).toBe(false);
    // rejected: CSS-injection vectors, a non-allowlisted font, and a token outside the allowlist
    expect(isValidTokenValue('--dd-field', 'url(https://evil/x.png)')).toBe(false);
    expect(isValidTokenValue('--dd-ink', 'red; background: url(x)')).toBe(false);
    expect(isValidTokenValue('--dd-ink', 'expression(alert(1))')).toBe(false);
    expect(isValidTokenValue('--dd-font-msg', 'Comic Sans')).toBe(false);
    expect(isValidTokenValue('--dd-desk', '#000000')).toBe(false); // not a user-editable token
  });

  it('sanitizes an untrusted theme pack: unknown theme → default, only valid allowlisted tokens survive', () => {
    const out = sanitizeAppearance({
      theme: 'winamp',
      tokens: {
        '--dd-ink': '#2be000', // kept
        '--dd-buddy-size': '14px', // kept
        '--dd-field': 'url(x)', // dropped (not a color)
        '--dd-desk': '#000000', // dropped (not user-editable)
        '--dd-secure': '#4bff6a', // kept
      },
    });
    expect(out.theme).toBe('winamp');
    expect(out.tokens['--dd-ink']).toBe('#2be000');
    expect(out.tokens['--dd-buddy-size']).toBe('14px');
    expect(out.tokens['--dd-secure']).toBe('#4bff6a');
    expect(out.tokens['--dd-field']).toBeUndefined();
    expect(out.tokens['--dd-desk']).toBeUndefined();
  });

  it('sanitizes garbage to the safe default', () => {
    expect(sanitizeAppearance(null)).toEqual(DEFAULT_APPEARANCE);
    expect(sanitizeAppearance('nope')).toEqual(DEFAULT_APPEARANCE);
    expect(sanitizeAppearance({ theme: 'bogus', tokens: 42 })).toEqual(DEFAULT_APPEARANCE);
  });

  it('maps each built-in theme to a root class (default = no class)', () => {
    expect(THEME_CLASS.default).toBe('');
    expect(THEME_CLASS.winamp).toBe('dd-theme-winamp');
    expect(THEME_CLASS.win98).toBe('dd-theme-win98');
    expect(THEME_CLASS.h4x0r).toBe('dd-theme-h4x0r');
    expect(THEME_CLASS.aim).toBe('dd-theme-aim'); // AIM23 replica theme
  });

  it('accepts the AIM theme in a pack and lists it as a selectable card', () => {
    expect(sanitizeAppearance({ theme: 'aim', tokens: {} }).theme).toBe('aim');
    const html = renderAppearance(DEFAULT_APPEARANCE, 'themes');
    expect(html).toContain('data-appear-theme="aim"');
    expect(html).toContain('>AIM<');
  });

  describe('My Message Look (AIM24)', () => {
    it('wraps composed markers in the look markers, outer→inner, and nests inline formatting inside', () => {
      // font 'r' (Round/Comic), color 'rd' (red), size large, highlight 'yl'
      const look = { font: 'r', color: 'rd', size: 'l' as const, hl: 'yl' };
      const wrapped = wrapMessageLook(look, 'hello *world*');
      expect(wrapped).toBe('[f:r][c:rd][h:yl][z:l]hello *world*[/z][/h][/c][/f]');
      // and it renders CSP-safe (classes + <font>, never an inline style)
      const html = formatMessageText(wrapped);
      expect(html).toContain('dd-ft-r'); // font class
      expect(html).toContain('dd-c-rd'); // color class
      expect(html).toContain('dd-hl-yl'); // highlight class
      expect(html).toContain('<font size='); // size
      expect(html).toContain('<strong>world</strong>'); // the inline bold nested inside
      expect(html).not.toContain('style=');
    });

    it('leaves text unchanged when there is no look, or the look is empty', () => {
      expect(wrapMessageLook(undefined, 'plain')).toBe('plain');
      expect(wrapMessageLook({}, 'plain')).toBe('plain');
    });

    it('sanitizes a MessageLook, dropping non-palette values and empty looks', () => {
      expect(sanitizeMessageLook({ font: 'r', color: 'rd', size: 'l', hl: 'gd' })).toEqual({ font: 'r', color: 'rd', size: 'l', hl: 'gd' });
      // bad values are dropped; nothing valid left → undefined
      expect(sanitizeMessageLook({ font: 'url(x)', color: '#nope', size: 'huge', hl: 42 })).toBeUndefined();
      expect(sanitizeMessageLook(null)).toBeUndefined();
      expect(sanitizeMessageLook('nope')).toBeUndefined();
      // a partially-valid look keeps only the valid field
      expect(sanitizeMessageLook({ font: 'r', color: 'bogus' })).toEqual({ font: 'r' });
    });

    it('carries a valid messageLook through sanitizeAppearance and drops an invalid one', () => {
      expect(sanitizeAppearance({ theme: 'default', tokens: {}, messageLook: { color: 'rd' } }).messageLook).toEqual({ color: 'rd' });
      expect(sanitizeAppearance({ theme: 'default', tokens: {}, messageLook: { color: 'zzz' } }).messageLook).toBeUndefined();
      expect(sanitizeAppearance({ theme: 'default', tokens: {} }).messageLook).toBeUndefined();
    });

    it('lists the My Message Look category and its style controls with a preview', () => {
      const html = renderAppearance({ theme: 'default', tokens: {}, messageLook: { color: 'rd', font: 'r' } }, 'mymessage');
      expect(html).toContain('data-appear-cat="mymessage"');
      expect(html).toContain('My Message Look');
      expect(html).toContain('data-look-set="font"');
      expect(html).toContain('data-look-set="color"');
      expect(html).toContain('data-look-set="size"');
      expect(html).toContain('data-look-set="hl"');
      // the preview renders a sample message wrapped in the current look
      expect(html).toContain('dd-c-rd');
      expect(html).toContain('dd-ft-r');
    });
  });

  it('lists the AIM-prefs categories: Buddy List Appearance, Message Appearance, Themes', () => {
    const html = renderAppearance(DEFAULT_APPEARANCE, 'buddylist');
    expect(html).toContain('Buddy List Appearance');
    expect(html).toContain('Message Appearance');
    expect(html).toContain('Themes');
    expect(html).toContain('data-appear-cat="buddylist"');
    expect(html).toContain('data-appear-cat="message"');
    expect(html).toContain('data-appear-cat="themes"');
  });

  it('Buddy List category: font/size/color pickers + the Entering/Online/Departing preview', () => {
    const html = renderAppearance(DEFAULT_APPEARANCE, 'buddylist');
    expect(html).toContain('data-appear-set="--dd-buddy-font"');
    expect(html).toContain('data-appear-set="--dd-buddy-size"');
    expect(html).toContain('data-appear-set="--dd-buddy-ink"');
    expect(html).toContain('Entering Buddy');
    expect(html).toContain('Online Buddy');
    expect(html).toContain('Departing Buddy');
    // the preview box rides inside its isolation wall + theme carrier (so the SAVED look cannot bleed in)
    expect(html).toContain('dd-appear-isolate');
    expect(html).toContain('dd-appear-themebox');
    expect(html).toContain('dd-appear-preview');
    // deliberately NOT a .dd-tree: root-scoped theme rules (.dd-theme-x .dd-tree) must not reach it
    expect(html).not.toContain('dd-appear-preview dd-tree');
    expect(html).not.toMatch(/\sstyle=/); // strict CSP: no inline style attributes
  });

  it('the themebox wears the DRAFT theme class; packText survives an error re-render, escaped', () => {
    const winamp = renderAppearance({ theme: 'winamp', tokens: {} }, 'buddylist');
    expect(winamp).toContain('dd-appear-themebox dd-theme-winamp');
    const def = renderAppearance(DEFAULT_APPEARANCE, 'buddylist');
    expect(def).not.toContain('dd-theme-winamp');
    const withText = renderAppearance(DEFAULT_APPEARANCE, 'themes', 'that is not valid JSON', '{"broken<tag>');
    expect(withText).toContain('{&quot;broken&lt;tag&gt;'); // preserved AND escaped
    expect(withText).toContain('that is not valid JSON');
  });

  it('Message category: font/size/text/background/accent pickers + a sample chat preview', () => {
    const html = renderAppearance(DEFAULT_APPEARANCE, 'message');
    expect(html).toContain('data-appear-set="--dd-font-msg"');
    expect(html).toContain('data-appear-set="--dd-msg-user-size"');
    expect(html).toContain('data-appear-set="--dd-ink"');
    expect(html).toContain('data-appear-set="--dd-field"');
    expect(html).toContain('data-appear-set="--dd-secure"');
    expect(html).toContain('forward secrecy active'); // the sample system line
    expect(html).toContain('dd-appear-prevmsg');
    expect(html).not.toMatch(/\sstyle=/);
  });

  it('Themes category: every theme card (active marked), packs, and a preview', () => {
    const html = renderAppearance({ theme: 'h4x0r', tokens: {} }, 'themes');
    expect(html).toContain('data-appear-theme="default"');
    expect(html).toContain('data-appear-theme="winamp"');
    expect(html).toContain('data-appear-theme="win98"');
    expect(html).toContain('data-appear-theme="h4x0r"');
    expect(html).toContain('dd-appear-theme-active" data-appear-theme="h4x0r"');
    expect(html).toContain('data-action="appear-import"');
    expect(html).toContain('data-action="appear-export"');
    expect(html).toContain('dd-appear-prevmsg');
    expect(html).not.toMatch(/\sstyle=/);
  });

  it('every category carries Save / Cancel / Reset (draft semantics: nothing applies until Save)', () => {
    for (const cat of ['buddylist', 'message', 'themes']) {
      const html = renderAppearance(DEFAULT_APPEARANCE, cat);
      expect(html).toContain('data-action="appear-save"');
      expect(html).toContain('data-action="appear-cancel"');
      expect(html).toContain('data-action="appear-reset"');
    }
  });

  it('the pickers reflect the draft: current font label, size, and swatch marked', () => {
    const draft: Appearance = {
      theme: 'default',
      tokens: { '--dd-buddy-font': 'Verdana, Geneva, sans-serif', '--dd-buddy-size': '14px', '--dd-buddy-ink': '#e0504a' },
    };
    const html = renderAppearance(draft, 'buddylist');
    expect(html).toContain('Verdana'); // the trigger shows the current pick
    expect(html).toContain('>14<'); // and the current size
    expect(html).toContain('dd-appear-sw-on'); // and the chosen swatch is marked
  });

  it('titles the window APPEARANCE and DemoController round-trips the stored look', async () => {
    const shell = renderShell({ kind: 'appearance', draft: DEFAULT_APPEARANCE, category: 'buddylist' });
    expect(shell).toContain('APPEARANCE');
    const c = new DemoController();
    const next: Appearance = { theme: 'win98', tokens: { '--dd-ink': '#000000' } };
    await c.setAppearance(next);
    expect(await c.getAppearance()).toEqual(next);
  });
});

describe('DemoController', () => {
  const c = new DemoController();

  it('unlocks with a username and non-empty passphrase and rejects empties', async () => {
    expect(await c.unlock('alice', 'hunter2')).toEqual({ ok: true });
    expect((await c.unlock('alice', '')).ok).toBe(false);
    expect((await c.unlock('', 'hunter2')).ok).toBe(false);
  });

  it('lists demo channels and opens one into a transmit model', async () => {
    expect((await c.listChannels()).length).toBeGreaterThan(0);
    const t = await c.openChannel('raven');
    expect(t.peer).toBe('RAVEN');
    expect(t.secure).toBe(true);
    expect(t.log.length).toBeGreaterThan(0);
  });

  it('starts a key exchange and accepts an incoming one into a secure conversation', async () => {
    expect((await c.startKeyExchange()).mode).toBe('start');
    const incoming = await c.channelKeyExchange('falcon');
    expect(incoming.mode).toBe('incoming');
    expect(incoming.peer).toBe('FALCON');
    const t = await c.acceptKeyExchange('falcon');
    expect(t.secure).toBe(true);
  });

  it('round-trips the identity card in memory', async () => {
    const fresh = new DemoController();
    expect(await fresh.getIdentity()).toEqual(DEFAULT_IDENTITY);
    const profile: IdentityProfile = { icon: { kind: 'emoji', value: 'X', bg: '#111' }, bio: 'hi', away: { enabled: true, message: 'brb', serverSide: false } };
    await fresh.setIdentity(profile);
    expect(await fresh.getIdentity()).toEqual(profile);
  });

  it('manages the buddy list (normalized, deduped)', async () => {
    const fresh = new DemoController();
    const before = (await fresh.listBuddies()).length;
    const added = await fresh.addBuddy('Wren');
    expect(added.some((b) => b.username === 'wren')).toBe(true); // normalized to lowercase
    expect((await fresh.addBuddy('wren')).length).toBe(added.length); // deduped
    expect((await fresh.removeBuddy('wren')).length).toBe(before);
  });

  it('blocks and unblocks in the demo', async () => {
    const fresh = new DemoController();
    expect(await fresh.listBlocked()).toEqual([]);
    await fresh.blockConversation('c1');
    const blocked = await fresh.listBlocked();
    expect(blocked.length).toBe(1);
    expect((await fresh.unblock(blocked[0]!.key)).length).toBe(0);
  });

  it('toggles the demo presence opt-in (off by default)', async () => {
    const fresh = new DemoController();
    expect(await fresh.getPresenceEnabled()).toBe(false);
    await fresh.setPresenceEnabled(true);
    expect(await fresh.getPresenceEnabled()).toBe(true);
  });

  it('toggles demo notifications (on by default)', async () => {
    const fresh = new DemoController();
    expect(await fresh.getNotifyEnabled()).toBe(true);
    await fresh.setNotifyEnabled(false);
    expect(await fresh.getNotifyEnabled()).toBe(false);
  });
});

describe('identity screen', () => {
  it('renders the icon and profile sections (away now lives in the DEAD DROP menu)', () => {
    const html = renderIdentity({ profile: DEFAULT_IDENTITY });
    expect(html).not.toContain('dd-form-title'); // no in-body heading: the titlebar names the screen
    expect(html).toContain('buddy icon');
    expect(html).toContain('profile');
    expect(html).not.toContain('away message'); // moved out to its own editor
    expect(html).toContain('data-action="id-save"');
    expect(html).toContain('dd-id-emoji');
    // Save/Cancel sit in a centered action row; initials authoring is gone.
    expect(html).toContain('dd-field dd-form-actions');
    expect(html).toContain('data-action="id-cancel"');
    expect(html).not.toContain('data-action="id-initials"');
  });

  it('renders an emoji/initials icon background as a CSP-safe class, never an inline style', () => {
    // The emoji/initials branch used to emit style="background:..", which the strict CSP strips; it
    // must now carry a palette class. Guarded here with a NON-null icon (DEFAULT_IDENTITY's is null).
    const withIcon = renderIdentity({ profile: { ...DEFAULT_IDENTITY, icon: { kind: 'emoji', value: '🦊', bg: '#1f9d6b' } } });
    expect(withIcon).not.toContain('style='); // no inline style anywhere on the screen
    expect(withIcon).toContain('dd-ic-1'); // #1f9d6b is ICON_COLORS[1]
    // An unknown/peer-supplied colour falls back to the first palette class, still no inline style.
    const foreign = renderIdentity({ profile: { ...DEFAULT_IDENTITY, icon: { kind: 'initials', value: 'AB', bg: 'red; }' } } });
    expect(foreign).not.toContain('style=');
    expect(foreign).toContain('dd-ic-0');
  });

  it('shows a shareable contact QR only when a contact link is provided (CSP-safe, with a copy button)', () => {
    // No link (e.g. before sign-in): no QR block.
    const bare = renderIdentity({ profile: DEFAULT_IDENTITY });
    expect(bare).not.toContain('your contact QR');
    expect(bare).not.toContain('dd-qr-svg');
    // With a link: an inline-SVG QR, the link text, and a Copy button; and no inline style (CSP).
    const link = 'https://d3addr0p.com/#dd=alice88&k=5F·A2·91·C4';
    const html = renderIdentity({ profile: DEFAULT_IDENTITY }, link);
    expect(html).toContain('your contact QR');
    expect(html).toContain('dd-qr-svg');
    expect(html).toContain('data-action="copy-contact-link"');
    expect(html).toContain('alice88'); // the link is shown for copy/share
    const qrPart = html.slice(html.indexOf('dd-qr-svg'));
    expect(qrPart.slice(0, qrPart.indexOf('</svg>'))).not.toContain('style=');
  });

  it('discloses the image size signal and the accepted formats in the icon note, with no em-dash', () => {
    const html = renderIdentity({ profile: DEFAULT_IDENTITY });
    expect(html).toContain('PNG, JPG, GIF, or WebP');
    expect(html).toContain('the server can tell when you publish a buddy icon');
    expect(html).toContain('It still cannot read it');
    expect(html).not.toContain('—'); // brief 0.7: no em-dash in app-facing copy
  });

  it('escapes a hostile profile/icon value', () => {
    const profile: IdentityProfile = { icon: { kind: 'initials', value: '<b', bg: '#000' }, bio: '<script>x</script>', away: DEFAULT_IDENTITY.away };
    const html = renderIdentity({ profile });
    expect(html).toContain('&lt;script&gt;');
    expect(html).not.toContain('<script>x');
  });

  it('gives the profile and away editors the WYSIWYG rich-text toolbar (color/highlight/size/B-I-U/font/emoji)', () => {
    const idHtml = renderIdentity({ profile: DEFAULT_IDENTITY });
    expect(idHtml).toContain('class="dd-rt-bar"');
    expect(idHtml).toContain('data-rt-color='); // text color picker
    expect(idHtml).toContain('data-rt-hl='); // highlight picker
    expect(idHtml).toContain('data-rt-size="s"'); // smaller / default / larger
    expect(idHtml).toContain('data-rt-size="l"');
    expect(idHtml).toContain('data-rt-cmd="bold"');
    expect(idHtml).toContain('data-rt-cmd="italic"');
    expect(idHtml).toContain('data-rt-cmd="underline"');
    expect(idHtml).toContain('data-rt-pop="font"'); // F = font
    // No app emoji picker: the device-native emoji input covers the full set (the grid limited it).
    expect(idHtml).not.toContain('data-rt-pop="emoji"');
    // The message-lifetime picker is compose-only: never on the profile/away editors.
    expect(idHtml).not.toContain('data-rt-pop="timer"');
    // The profile editor is a contenteditable seeded from the saved text (WYSIWYG), never an inline style.
    expect(idHtml).toContain('id="dd-id-bio" contenteditable="true"');
    expect(idHtml).not.toContain('style=');
    const awayHtml = renderAway({ profile: { ...DEFAULT_IDENTITY, away: { enabled: true, message: '', serverSide: false } } });
    expect(awayHtml).toContain('id="dd-away-msg" contenteditable="true"');
    expect(awayHtml).toContain('class="dd-rt-bar"');
  });
});

describe('away message screen', () => {
  it('always shows the away editor with the server-side opt-in defaulting OFF', () => {
    expect(DEFAULT_IDENTITY.away.serverSide).toBe(false);
    // The editor and its server-side reply option are always available (so you can write a message even
    // before turning the auto-reply on); the server-side opt-in defaults OFF (unchecked).
    const html = renderAway({ profile: DEFAULT_IDENTITY });
    expect(html).toContain('AWAY MESSAGE');
    expect(html).toContain('id="dd-away-msg" contenteditable="true"');
    expect(html).toContain('id="dd-away-server"');
    expect(html).not.toContain('id="dd-away-server" checked'); // defaults OFF
    expect(html).toContain('Let the server reply');
  });

  it('discloses the 7-day loss with no em-dash and offers save/cancel', () => {
    const html = renderAway({ profile: { ...DEFAULT_IDENTITY, away: { enabled: true, message: '', serverSide: false } } });
    expect(html).toContain('the reply is lost and the sender gets nothing');
    expect(html).toContain('data-action="away-save"');
    expect(html).toContain('data-action="away-cancel"');
    expect(html).not.toContain('—');
  });

  it('offers the saved away messages as a dropdown with a New option and Delete', () => {
    const html = renderAway({ profile: { ...DEFAULT_IDENTITY, away: { enabled: false, message: '', serverSide: false, saved: ['at lunch', '[c:rd]on a call[/c]'] } } });
    expect(html).toContain('saved away messages');
    expect(html).toContain('id="dd-away-pick"'); // the dropdown listing every saved message
    expect(html).toContain('New away message'); // the create-a-new-one option
    expect(html).toContain('at lunch');
    expect(html).toContain('on a call'); // the format markers are stripped for the preview
    expect(html).toContain('data-action="away-del-sel"'); // delete the selected saved message
    // The dropdown (and its hint) is shown even with an empty library, so there is always a way to see,
    // choose, delete, and create away messages.
    const empty = renderAway({ profile: DEFAULT_IDENTITY });
    expect(empty).toContain('id="dd-away-pick"');
    expect(empty).toContain('No saved away messages yet');
  });
});

describe('peer Get-Info panel', () => {
  it('renders a peer card with the fingerprint and the trust warning', () => {
    const peers: PeerIdentity[] = [{ key: 'aabb', fingerprint: '5F·A2·91·C4', icon: { kind: 'emoji', value: 'X', bg: '#111' }, bio: 'meet at the drop', away: '' }];
    const html = renderGetInfo('RAVEN', peers);
    expect(html).not.toContain('dd-form-title'); // no in-body "GET INFO" heading; the titlebar names the screen
    expect(html).toContain('RAVEN'); // the peer name still leads the body
    expect(html).toContain('5F·A2·91·C4');
    expect(html).toContain('meet at the drop');
    expect(html).toContain('does not prove who they are'); // the trust anchor warning stays adjacent
    expect(html).toContain('data-action="getinfo-back"');
  });

  it('shows an empty state and escapes a hostile bio', () => {
    expect(renderGetInfo('X', [])).toContain('No buddy info yet');
    const html = renderGetInfo('X', [{ key: 'a', fingerprint: 'AA', icon: null, bio: '<script>x</script>', away: '' }]);
    expect(html).toContain('&lt;script&gt;');
    expect(html).not.toContain('<script>x');
  });

  const vi = (state: BuddyVerifyInfo['state']) => ({
    peerKey: state === 'stale' ? '' : 'ab'.repeat(32),
    peerFingerprint: state === 'stale' ? '' : 'AB·AB·AB·AB',
    ourFingerprint: 'CD·CD·CD·CD',
    ourWords: 'tavo ken rilm bax sodu quen zim lorn',
    theirWords: 'polm ved sest kuun dax rel mub tass',
    verifiedKey: state === 'verified' || state === 'changed' || state === 'stale' ? 'ee'.repeat(32) : '',
    state,
  });

  it('offers Mark as Verified with BOTH phrases when the buddy is comparable and unverified', () => {
    const html = renderGetInfo('RAVEN', [], undefined, undefined, undefined, vi('none'));
    expect(html).toContain('Verify buddy');
    // Both halves must be present and labelled: a single shared phrase is the broken design.
    expect(html).toContain('tavo ken rilm bax sodu quen zim lorn');
    expect(html).toContain('polm ved sest kuun dax rel mub tass');
    expect(html).toContain('your words');
    expect(html).toContain('their words');
    expect(html).toContain('compare BOTH sets');
    expect(html).toContain('data-action="verify-mark"');
    expect(html).not.toContain('Identity changed');
  });

  it('never claims a pin is being watched when the current key is unreadable', () => {
    const html = renderGetInfo('RAVEN', [], undefined, undefined, undefined, vi('stale'));
    expect(html).toContain('not checkable right now');
    expect(html).toContain('treat this channel as unconfirmed');
    // The reassuring language and the phrase boxes must BOTH be absent: there is nothing to compare.
    expect(html).not.toContain('Verified buddy');
    expect(html).not.toContain('dd-verify-words');
    expect(html).not.toContain('data-action="verify-mark"');
  });

  it('shows the pinned state with a forget option once verified', () => {
    const html = renderGetInfo('RAVEN', [], undefined, undefined, undefined, vi('verified'));
    expect(html).toContain('Verified buddy');
    expect(html).toContain('While this device can');
    expect(html).toContain('data-action="verify-clear"');
    expect(html).not.toContain('Mark as Verified');
  });

  it('screams on a changed key and gates re-trust behind the danger button', () => {
    const html = renderGetInfo('RAVEN', [], undefined, undefined, undefined, vi('changed'));
    expect(html).toContain('Identity changed');
    expect(html).toContain('NOT the one you verified');
    expect(html).toContain('dd-btn-danger');
    expect(html).toContain('Verify the new key');
    // The armed second tap renames the button so the user knows the next tap commits.
    const armed = renderGetInfo('RAVEN', [], undefined, undefined, undefined, vi('changed'), true);
    expect(armed).toContain('Tap again to trust the new key');
  });

  it('explains itself when there is nothing to compare, and never shows on your own card', () => {
    const html = renderGetInfo('RAVEN', [], undefined, undefined, undefined, vi('unavailable'));
    expect(html).toContain('Nothing to compare yet');
    expect(html).not.toContain('verify-mark');
    const own = renderGetInfo('me', [], undefined, undefined, true, vi('none'));
    expect(own).not.toContain('Verify buddy');
  });
});

// A profile with the away responder on, for the toolbar-check and header-bubble tests.
const AWAY_ON_PROFILE: IdentityProfile = {
  ...DEFAULT_IDENTITY,
  away: { enabled: true, message: 'gone to the beach', serverSide: false },
};

describe('buddy list (read-only tree)', () => {
  it('shows OUR icon, handle, and away message in an AIM-style header at the top', () => {
    const profile: IdentityProfile = {
      ...AWAY_ON_PROFILE,
      icon: { kind: 'emoji', value: '\u{1F985}', bg: '#1f9d6b' },
    };
    const html = renderBuddies([], [], {}, [], [], [], profile, 'DevinJacks', {});
    expect(html).toContain('class="dd-blhead"');
    expect(html).toContain('DevinJacks');
    expect(html).toContain('gone to the beach'); // the away bubble
    expect(html).toContain('dd-ic-1'); // the icon bg rides a palette class, never an inline style
    expect(html).not.toContain('style=');
    // The little ◆ status control: a dropdown with Online / New Away Message; away tints it
    // dd-st-away and the check sits on the active choice.
    expect(html).toContain('data-action="status-menu"');
    expect(html).toContain('dd-st-away');
    expect(html).toContain('data-action="status-online">Online');
    expect(html).toContain('data-action="status-edit-away">New Away Message');
    // While ONLINE the tint flips and the check moves to Online.
    const online = renderBuddies([], [], {}, [], [], [], DEFAULT_IDENTITY, 'me', {});
    expect(online).toContain('dd-st-online');
    expect(online).toContain('data-action="status-online">✓ Online');
  });

  it('puts the connection status in the header (far right), not the titlebar (AIM26)', () => {
    const html = renderBuddies([], [], {}, [], [], [], DEFAULT_IDENTITY, 'me', {});
    // the conn control lives inside the header now, wrapped in .dd-blhead-conn
    expect(html).toContain('dd-blhead-conn');
    expect(html).toContain('id="dd-conn"');
    expect(html).toContain('id="dd-conn-pop"');
    // it comes AFTER the header text column, so it renders at the far right of the header row
    expect(html.indexOf('dd-blhead-conn')).toBeGreaterThan(html.indexOf('dd-blhead-txt'));
    // and it is no longer emitted from the titlebar wrapper
    expect(html).not.toContain('dd-title-connwrap');
  });

  it('renders the connection popover AFTER the away bubble so it paints over it (AIM26)', () => {
    // Bug: clicking the SECURE LINK with an away message set showed the popover buried
    // under the away bubble. With the conn control co-located in the header (not the
    // titlebar), the popover markup comes after the away bubble in DOM order, so with its
    // positive z-index it out-paints the away bubble (which is z-index:auto).
    const away: IdentityProfile = {
      ...DEFAULT_IDENTITY,
      away: { enabled: true, message: 'gone fishing', serverSide: false },
    };
    const html = renderBuddies([], [], {}, [], [], [], away, 'me', {});
    const awayBubble = html.indexOf('dd-blhead-status');
    const pop = html.indexOf('id="dd-conn-pop"');
    expect(awayBubble).toBeGreaterThanOrEqual(0);
    expect(pop).toBeGreaterThanOrEqual(0);
    expect(pop).toBeGreaterThan(awayBubble);
  });

  it('has a Channels button in the bottom toolbar between Group Chat and Buddy Info (AIM25)', () => {
    const html = renderBuddies([], [], {}, [], [], [], DEFAULT_IDENTITY, 'me', {});
    expect(html).toContain('data-action="tbar-channels"');
    expect(html).toContain('>Channels</span>');
    // ordering: Group Chat, then Channels, then Buddy Info
    const gc = html.indexOf('tbar-group-chat');
    const ch = html.indexOf('tbar-channels');
    const info = html.indexOf('tbar-info');
    expect(gc).toBeGreaterThanOrEqual(0);
    expect(ch).toBeGreaterThan(gc);
    expect(info).toBeGreaterThan(ch);
  });

  it('lists the saved away-message LIBRARY in the ◆ dropdown beneath New Away Message', () => {
    const profile: IdentityProfile = {
      ...DEFAULT_IDENTITY,
      away: { enabled: true, message: 'gone fishing', serverSide: false, saved: ['gone fishing', '[c:rd]beach day[/c] with a very long tail that gets cut'] },
    };
    const html = renderBuddies([], [], {}, [], [], [], profile, 'me', {});
    expect(html).toContain('data-action="status-saved"');
    expect(html).toContain('✓ “gone fishing”'); // the ACTIVE saved message carries the check
    expect(html).toContain('“beach day with a very lon…”'); // markers stripped + truncated in the preview
    expect(html).not.toContain('data-action="status-away"'); // the old bare toggle is gone for good
    // Dropdown order: Online, then New Away Message, then the saved list beneath it.
    expect(html.indexOf('data-action="status-online"')).toBeLessThan(html.indexOf('data-action="status-edit-away"'));
    expect(html.indexOf('data-action="status-edit-away"')).toBeLessThan(html.indexOf('data-action="status-saved"'));
    // The ◆ is GREEN while online.
    const onlineHtml = renderBuddies([], [], {}, [], [], [], DEFAULT_IDENTITY, 'me', {});
    expect(onlineHtml).toContain('dd-blhead-stbtn dd-st-online');
    // An empty library: still just Online + New Away Message (writing one is how you go away).
    expect(onlineHtml).not.toContain('data-action="status-away"');
    expect(onlineHtml).toContain('data-action="status-edit-away">New Away Message');
    expect(onlineHtml).not.toContain('data-action="status-saved"');
  });

  it('shows the away message in the header bubble only while away, and stays blank when online', () => {
    // Online (away off): the bubble is blank even with a profile bio (the bio is not echoed here).
    const online = renderBuddies([], [], {}, [], [], [], { ...DEFAULT_IDENTITY, bio: 'field ops' }, 'me', {});
    expect(online).not.toContain('field ops');
    expect(online).not.toContain('dd-blhead-status');
    // Away with a message: the bubble carries the away message.
    const away = renderBuddies([], [], {}, [], [], [], { ...DEFAULT_IDENTITY, away: { enabled: true, message: 'gone fishing', serverSide: false } }, 'me', {});
    expect(away).toContain('dd-blhead-status');
    expect(away).toContain('gone fishing');
  });

  it('escapes an attacker-influenced handle and away text in the header', () => {
    const xss = '<img src=x onerror=1>';
    const profile: IdentityProfile = { ...DEFAULT_IDENTITY, away: { enabled: true, message: xss, serverSide: false } };
    const html = renderBuddies([], [], {}, [], [], [], profile, xss, {});
    expect(html).not.toContain('<img src=x');
  });

  it('shows a cached E2E icon beside a buddy and a deterministic initials placeholder otherwise', () => {
    const buddies: Buddy[] = [{ username: 'raven', addedAt: 0, group: 'Buddies' }, { username: 'falcon', addedAt: 0, group: 'Buddies' }];
    const html = renderBuddies(buddies, [], {}, [], [], [], DEFAULT_IDENTITY, 'me', {
      raven: { kind: 'emoji', value: '\u{1F426}', bg: '#2a52d6' },
    });
    expect(html).toContain('\u{1F426}'); // raven's shared icon
    expect(html).toContain('>\u{1F47B}</span>'); // falcon never shared one: the ghost placeholder
    // The placeholder color is deterministic: the same username always renders the same palette class.
    const again = renderBuddies(buddies, [], {}, [], [], [], DEFAULT_IDENTITY, 'me', {});
    const cls = (h: string): string | undefined => /dd-bic (dd-ic-\d)/.exec(h)?.[1];
    expect(cls(again)).toBeDefined();
    expect(cls(again)).toBe(cls(renderBuddies(buddies, [], {}, [], [], [], DEFAULT_IDENTITY, 'me', {})));
  });

  it('moves a BLOCKED buddy out of its group into the Blocked drop, shown by name', () => {
    const buddies: Buddy[] = [
      { username: 'raven', addedAt: 0, group: 'Buddies' },
      { username: 'falcon', addedAt: 0, group: 'Buddies' },
    ];
    const blocked: BlockedContact[] = [
      { key: 'k1', fingerprint: '5F·A2·91·C4', username: 'raven' }, // a blocked buddy: named
      { key: 'k2', fingerprint: '9B·11·00·EE' }, // a key-only block (no conversation handle): fingerprint
    ];
    const html = renderBuddies(buddies, [], {}, [], blocked, [], DEFAULT_IDENTITY, 'me', {});
    // raven left the Buddies group (no selectable row) and shows under Blocked by name.
    expect(html).not.toContain('data-buddy-select="raven"');
    expect(html).toContain('data-buddy-select="falcon"');
    expect(html).toContain('>Blocked</span>');
    expect(html).toContain('raven'); // named in the Blocked drop
    expect(html).toContain('key 9B·11·00·EE'); // the key-only block keeps its fingerprint label
    // A blocked buddy in the selection cannot drive the toolbar (Send IM stays disabled).
    const withSel = renderBuddies(buddies, [], {}, [], blocked, ['raven'], DEFAULT_IDENTITY, 'me', {});
    expect(withSel).toContain('data-action="tbar-send-im" disabled');
  });

  it('labels a blocked buddy by name in Buddy List Setup so it can be recognized and unblocked', () => {
    const blocked: BlockedContact[] = [{ key: 'k1', fingerprint: '5F·A2·91·C4', username: 'raven' }];
    const html = renderBuddySetup([], [], {}, blocked, false, false, null);
    expect(html).toContain('data-setup-sel="blocked:k1"'); // selectable, so Delete unblocks it
    expect(html).toContain('raven');
    expect(html).toContain('key 5F·A2·91·C4'); // the key stays visible as the trust anchor
  });

  it('escapes a peer-authored image icon value and keeps unknown palette colors on a safe class', () => {
    const buddies: Buddy[] = [{ username: 'raven', addedAt: 0, group: 'Buddies' }];
    const html = renderBuddies(buddies, [], {}, [], [], [], DEFAULT_IDENTITY, 'me', {
      raven: { kind: 'image', value: '"><script>alert(1)</script>', bg: 'javascript:evil' },
    });
    expect(html).not.toContain('<script>');
    const unknownBg = renderBuddies(buddies, [], {}, [], [], [], DEFAULT_IDENTITY, 'me', {
      raven: { kind: 'initials', value: 'RV', bg: 'red; background:url(x)' },
    });
    expect(unknownBg).toContain('dd-bic dd-ic-0'); // unknown peer bg falls back to the first palette class
    expect(unknownBg).not.toContain('style=');
  });

  it('always shows the Blocked drop, even empty, so blocked buddies have a visible place to land', () => {
    const empty = renderBuddies([], [], {}, [], [], [], DEFAULT_IDENTITY, 'me', {});
    expect(empty).toContain('Blocked');
    expect(empty).toContain('(0)');
  });

  it('shows minimize/close on signed-in windows only (never on unlock or guided/sensitive flows)', () => {
    expect(renderShell({ kind: 'buddies', buddies: [], groups: [], statuses: {}, collapsed: [], blocked: [], selected: [], profile: DEFAULT_IDENTITY, ownName: 'me', icons: {}, awayText: {} })).toContain('data-action="win-minimize"');
    expect(renderShell({ kind: 'identity', profile: DEFAULT_IDENTITY })).toContain('data-action="win-close"');
    expect(renderShell({ kind: 'unlock' })).not.toContain('data-action="win-minimize"');
    // ADD A DEVICE must be left ONLY through its own Cancel (which closes the pairing window), and the
    // controls must not offer an unauthorized wizard-driven device an escape into the app.
    expect(renderShell({ kind: 'provisioning', state: { role: 'seedholder', step: 'opening' } })).not.toContain('data-action="win-minimize"');
  });

  it('renders buddies as plain selectable NAME rows (not chunky buttons), with an empty state', () => {
    expect(renderBuddies([], [], {}, [], [], [], DEFAULT_IDENTITY, 'me', {})).toContain('no buddies yet');
    const buddies: Buddy[] = [{ username: 'raven', addedAt: 0, group: 'Buddies' }, { username: 'falcon', addedAt: 0, group: 'Buddies' }];
    const html = renderBuddies(buddies, [], {}, [], [], [], DEFAULT_IDENTITY, 'me', {});
    expect(html).not.toContain('dd-form-title'); // the window titlebar names the screen; no in-body heading
    // A name row carries data-buddy-select (click selects) and is a tree row, not a dd-buddy-open button.
    expect(html).toContain('data-buddy-select="raven"');
    expect(html).toContain('class="dd-tree-buddy'); // plain name row (prefix; may carry -off/-sel)
    expect(html).not.toContain('dd-buddy-open'); // the old chunky button class is gone
    // The read-only list has no add form, no remove buttons, and no toggles (those moved to Setup).
    expect(html).not.toContain('data-action="buddy-add"');
    expect(html).not.toContain('data-buddy-remove');
    expect(html).not.toContain('id="dd-presence-toggle"');
  });

  it('flashes a sign-on / sign-off animation on the rows that just changed presence', () => {
    const buddies: Buddy[] = [
      { username: 'raven', addedAt: 0, group: 'Buddies' },
      { username: 'falcon', addedAt: 0, group: 'Buddies' },
      { username: 'stan', addedAt: 0, group: 'Buddies' },
    ];
    const statuses = { raven: 'online', falcon: 'offline', stan: 'online' };
    const html = renderBuddies(buddies, [], statuses, [], [], [], DEFAULT_IDENTITY, 'me', {}, {}, undefined, { raven: 'on', falcon: 'off' });
    // The signaled rows carry the one-shot flash class; the unsignaled row does not.
    expect(html).toMatch(/data-buddy-select="raven"[^>]*dd-tree-signon|dd-tree-signon[^>]*data-buddy-select="raven"/);
    expect(html).toContain('dd-tree-signoff');
    const stanRow = html.slice(html.indexOf('data-buddy-select="stan"') - 80, html.indexOf('data-buddy-select="stan"') + 20);
    expect(stanRow).not.toContain('dd-tree-sign');
    // No signals passed = no flash classes at all (the default).
    expect(renderBuddies(buddies, [], statuses, [], [], [], DEFAULT_IDENTITY, 'me', {})).not.toContain('dd-tree-sign');
  });

  it('shows a dim away-message subtitle under an away buddy, a plain "Away" when no message, and none when online', () => {
    const buddies: Buddy[] = [
      { username: 'raven', addedAt: 0, group: 'Buddies' }, // away WITH a cached message
      { username: 'falcon', addedAt: 0, group: 'Buddies' }, // away with NO cached message
      { username: 'stan', addedAt: 0, group: 'Buddies' }, // online
    ];
    const statuses = { raven: 'away', falcon: 'away', stan: 'online' };
    const awayText = { raven: 'gone *fishing* [c:rd]back at 5[/c]', stan: 'this should not show (online)' };
    const html = renderBuddies(buddies, [], statuses, [], [], [], DEFAULT_IDENTITY, 'me', {}, awayText);
    const row = (u: string): string => {
      const i = html.indexOf(`data-buddy-select="${u}"`);
      return html.slice(html.lastIndexOf('<button', i), html.indexOf('</button>', i) + 9);
    };
    // raven: the away text renders as a PLAIN, marker-stripped subtitle (no bold/color HTML in the preview).
    expect(row('raven')).toContain('dd-tree-sub');
    expect(row('raven')).toContain('gone fishing back at 5');
    expect(row('raven')).not.toContain('<strong>');
    expect(row('raven')).not.toContain('dd-c-rd');
    // falcon: away but no message -> a plain "Away" subtitle.
    expect(row('falcon')).toContain('dd-tree-sub');
    expect(row('falcon')).toContain('Away');
    // stan: online -> NO subtitle even though awayText has a (stale) entry (the presence flag gates it).
    expect(row('stan')).not.toContain('dd-tree-sub');
    expect(row('stan')).not.toContain('this should not show');
  });

  it('files buddies into collapsible group folders with an online/total count, online-first', () => {
    const buddies: Buddy[] = [
      { username: 'stan', addedAt: 0, group: 'Family' },
      { username: 'tim', addedAt: 0, group: 'Family' },
      { username: 'raven', addedAt: 0, group: 'Buddies' },
    ];
    const html = renderBuddies(buddies, [], { stan: 'online' }, [], [], [], DEFAULT_IDENTITY, 'me', {});
    expect(html).toContain('data-buddy-toggle="Family"');
    expect(html).toContain('data-buddy-toggle="Buddies"');
    expect(html).toContain('(1/2)'); // Family: 1 of 2 online
    expect(html).toContain('(0/1)'); // Buddies: 0 of 1
    // The default group is listed first, then the rest alphabetically.
    expect(html.indexOf('data-buddy-toggle="Buddies"')).toBeLessThan(html.indexOf('data-buddy-toggle="Family"'));
    // The online buddy sorts above the offline one within Family.
    expect(html.indexOf('data-buddy-select="stan"')).toBeLessThan(html.indexOf('data-buddy-select="tim"'));
    // A collapsed folder shows its header but not its members.
    const collapsed = renderBuddies(buddies, [], { stan: 'online' }, ['Family'], [], [], DEFAULT_IDENTITY, 'me', {});
    expect(collapsed).toContain('data-buddy-toggle="Family"');
    expect(collapsed).not.toContain('data-buddy-select="stan"');
    expect(collapsed).toContain('data-buddy-select="raven"'); // Buddies is still expanded
  });

  it('highlights the selected buddies', () => {
    const buddies: Buddy[] = [{ username: 'raven', addedAt: 0, group: 'Buddies' }, { username: 'falcon', addedAt: 0, group: 'Buddies' }];
    const html = renderBuddies(buddies, [], {}, [], [], ['raven'], DEFAULT_IDENTITY, 'me', {});
    // The selected row carries dd-tree-sel and aria-pressed; the unselected one does not.
    expect(html).toMatch(/data-buddy-select="raven"[^>]*aria-pressed="true"/);
    expect(html).toContain('dd-tree-sel');
    expect(html).toMatch(/data-buddy-select="falcon"[^>]*aria-pressed="false"/);
  });

  it('shows a synced EMPTY group folder even with no members', () => {
    const groups: GroupSummary[] = [{ name: 'Co-Workers' }];
    const html = renderBuddies([], groups, {}, [], [], [], DEFAULT_IDENTITY, 'me', {});
    expect(html).toContain('data-buddy-toggle="Co-Workers"');
    expect(html).toContain('(0/0)'); // empty folder still renders with a zero count
  });

  it('lists blocked contacts as their own "Blocked" drop at the bottom (read-only, no unblock here)', () => {
    const blocked: BlockedContact[] = [{ key: 'a'.repeat(64), fingerprint: 'DE·AD·BE·EF' }];
    const html = renderBuddies([{ username: 'raven', addedAt: 0, group: 'Buddies' }], [], {}, [], blocked, [], DEFAULT_IDENTITY, 'me', {});
    expect(html).toContain('Blocked'); // the drop's label
    expect(html).toContain('DE·AD·BE·EF'); // shown by fingerprint
    expect(html).not.toContain('data-unblock'); // unblock is a Setup action, not here
    // The Blocked drop is the LAST node in the tree.
    expect(html.indexOf('data-buddy-toggle="Buddies"')).toBeLessThan(html.lastIndexOf('Blocked'));
  });

  it('shows presence dots from a buddy status', () => {
    const online = renderBuddies([{ username: 'raven', addedAt: 0, group: 'Buddies' }], [], { raven: 'online' }, [], [], [], DEFAULT_IDENTITY, 'me', {});
    expect(online).toContain('dd-status-secure'); // online dot
    const idle = renderBuddies([{ username: 'raven', addedAt: 0, group: 'Buddies' }], [], { raven: 'idle' }, [], [], [], DEFAULT_IDENTITY, 'me', {});
    expect(idle).toContain('dd-status-pending'); // idle dot
  });

  it('escapes a hostile buddy handle', () => {
    const html = renderBuddies([{ username: '<img src=x onerror=1>', addedAt: 0, group: 'Buddies' }], [], {}, [], [], [], DEFAULT_IDENTITY, 'me', {});
    expect(html).toContain('&lt;img');
    expect(html).not.toContain('<img src=x');
  });

  it('renders the bottom toolbar: actions gated by the selection, with Profile and Setup in row 2', () => {
    const buddies: Buddy[] = [{ username: 'raven', addedAt: 0, group: 'Buddies' }, { username: 'falcon', addedAt: 0, group: 'Buddies' }];
    // Nothing selected: Send IM, Group Chat, and Buddy Info are all disabled; Profile/Setup always available.
    const none = renderBuddies(buddies, [], {}, [], [], [], DEFAULT_IDENTITY, 'me', {});
    expect(none).toContain('data-action="tbar-send-im" disabled');
    expect(none).toContain('data-action="tbar-group-chat" disabled');
    expect(none).toContain('data-action="tbar-info" disabled');
    expect(none).toContain('data-action="tbar-profile"');
    expect(none).toContain('data-action="tbar-setup"');
    // The away toolbar button is gone: the ◆ status control in the header owns the away message now.
    expect(none).not.toContain('data-action="tbar-away"');
    // Exactly one selected: Send IM and Buddy Info enable, Group Chat enables too.
    const one = renderBuddies(buddies, [], {}, [], [], ['raven'], AWAY_ON_PROFILE, 'me', {});
    expect(one).not.toContain('data-action="tbar-send-im" disabled');
    expect(one).not.toContain('data-action="tbar-info" disabled');
    expect(one).not.toContain('data-action="tbar-group-chat" disabled');
    // Two selected: Group Chat stays enabled but Send IM and Buddy Info (single-target) disable.
    const two = renderBuddies(buddies, [], {}, [], [], ['raven', 'falcon'], DEFAULT_IDENTITY, 'me', {});
    expect(two).not.toContain('data-action="tbar-group-chat" disabled');
    expect(two).toContain('data-action="tbar-send-im" disabled');
    expect(two).toContain('data-action="tbar-info" disabled');
  });
});

describe('buddy list setup', () => {
  const buddies: Buddy[] = [
    { username: 'stan', addedAt: 0, group: 'Family' },
    { username: 'raven', addedAt: 0, group: 'Buddies' },
  ];
  const groups: GroupSummary[] = [{ name: 'Family' }, { name: 'Co-Workers' }];

  it('renders the Add Buddy / Add Group / Delete toolbar, the toggles, and a selectable tree', () => {
    const html = renderBuddySetup(buddies, groups, {}, [], false, true, null);
    expect(html).toContain('BUDDY LIST SETUP');
    expect(html).toContain('data-action="setup-add-buddy"');
    expect(html).toContain('data-action="setup-add-group"');
    expect(html).toContain('data-action="setup-delete"');
    expect(html).toContain('id="dd-presence-toggle"'); // toggles live here now
    expect(html).toContain('id="dd-notify-toggle"');
    // Selectable rows for groups and buddies, plus the per-buddy group move select.
    expect(html).toContain('data-setup-sel="group:Family"');
    expect(html).toContain('data-setup-sel="buddy:stan"');
    expect(html).toContain('data-buddy-group="stan"');
    // Even an empty synced group is present so you can file buddies into it or delete it.
    expect(html).toContain('data-setup-sel="group:Co-Workers"');
  });

  it('highlights the selected row and only enables Delete for a deletable selection', () => {
    // A selected buddy is highlighted and Delete is enabled.
    const sel = renderBuddySetup(buddies, groups, {}, [], false, true, { type: 'buddy', id: 'stan' });
    expect(sel).toMatch(/data-setup-sel="buddy:stan"[^>]*dd-tree-sel|dd-tree-sel[^>]*data-setup-sel="buddy:stan"/);
    expect(sel).not.toContain('data-action="setup-delete" disabled');
    // The default group cannot be deleted: selecting it disables Delete.
    const def = renderBuddySetup(buddies, groups, {}, [], false, true, { type: 'group', id: 'Buddies' });
    expect(def).toContain('data-action="setup-delete" disabled');
    // Neither can the Blocked drop (a built-in).
    const gb = renderBuddySetup(buddies, groups, {}, [], false, true, { type: 'gblocked', id: '' });
    expect(gb).toContain('data-action="setup-delete" disabled');
    // Nothing selected also disables Delete.
    expect(renderBuddySetup(buddies, groups, {}, [], false, true, null)).toContain('data-action="setup-delete" disabled');
  });

  it('always shows the Blocked drop (auto-populated, selectable) and a Rename control for groups', () => {
    // Blocked is present and selectable even with NOBODY blocked, so every user has it from the start.
    const html = renderBuddySetup(buddies, groups, {}, [], false, true, null);
    expect(html).toContain('data-setup-sel="gblocked:"');
    expect(html).toContain('Blocked');
    expect(html).toContain('(0)');
    // Rename exists and is disabled until a group (or the Blocked drop) is selected.
    expect(html).toContain('data-action="setup-rename" disabled');
    const g = renderBuddySetup(buddies, groups, {}, [], false, true, { type: 'group', id: 'Family' });
    expect(g).not.toContain('data-action="setup-rename" disabled');
    const gb = renderBuddySetup(buddies, groups, {}, [], false, true, { type: 'gblocked', id: '' });
    expect(gb).not.toContain('data-action="setup-rename" disabled');
    // A selected BUDDY is not renamable here (renames are for groups).
    const b = renderBuddySetup(buddies, groups, {}, [], false, true, { type: 'buddy', id: 'stan' });
    expect(b).toContain('data-action="setup-rename" disabled');
  });

  it('renders the built-ins under their renamed labels while selection keys stay internal', () => {
    const renamed: GroupSummary[] = [
      { name: 'Pals', role: 'default' },
      { name: 'Family' },
      { name: 'Enemies', role: 'blocked' },
    ];
    const html = renderBuddySetup(buddies, renamed, {}, [], false, true, null);
    // The default group SHOWS its new name yet still selects (and files buddies) by its internal key.
    expect(html).toContain('Pals');
    expect(html).toContain('data-setup-sel="group:Buddies"');
    expect(html).not.toContain('>Buddies<'); // the old label is not shown anywhere
    // The Blocked drop shows its new name too.
    expect(html).toContain('Enemies');
    // The per-buddy group select offers the display label with the INTERNAL value.
    expect(html).toContain('<option value="Buddies"');
    expect(html).toContain('>Pals</option>');
  });

  it('lists blocked contacts as selectable rows so Delete can unblock them', () => {
    const blocked: BlockedContact[] = [{ key: 'b'.repeat(64), fingerprint: 'FE·ED·FA·CE' }];
    const html = renderBuddySetup(buddies, groups, {}, blocked, false, true, null);
    expect(html).toContain('FE·ED·FA·CE');
    expect(html).toContain(`data-setup-sel="blocked:${'b'.repeat(64)}"`);
  });
});

describe('message formatting (emoticons + bold/italic)', () => {
  it('substitutes emoticons and applies bold/italic', () => {
    expect(formatMessageText('hello :) world')).toContain('🙂');
    expect(formatMessageText('that is *important*')).toContain('<strong>important</strong>');
    expect(formatMessageText('a _word_ here')).toContain('<em>word</em>');
    expect(formatMessageText('love <3')).toContain('❤️');
  });

  it('escapes HTML first so formatting cannot be used to inject', () => {
    const html = formatMessageText('<script>alert(1)</script> *x*');
    expect(html).toContain('&lt;script&gt;');
    expect(html).not.toContain('<script>');
    expect(html).toContain('<strong>x</strong>'); // only our own tags appear
  });

  it('applies a color marker as a CSP-safe class (palette key) and keeps legacy hex as <font color>', () => {
    // New palette color: a CSS class, never an inline style, so it survives the strict CSP.
    expect(formatMessageText('[c:rd]red[/c]')).toContain('<span class="dd-c-rd">red</span>');
    expect(formatMessageText('[c:bl]*bold*[/c]')).toContain('<span class="dd-c-bl"><strong>bold</strong></span>');
    expect(formatMessageText('[c:rd]red[/c]')).not.toContain('style=');
    // Legacy raw-hex markers from older saved text still render (as a CSP-safe <font color> attribute).
    expect(formatMessageText('[#ff0000]red[/]')).toContain('<font color="#ff0000">red</font>');
    expect(formatMessageText('[#ff0000]red[/]')).not.toContain('style=');
  });

  it('ignores a color marker whose key/hex is invalid (no arbitrary CSS)', () => {
    expect(formatMessageText('[#zz]x[/] [#12]y[/]')).not.toContain('<font');
    expect(formatMessageText('[#zz]x[/]')).toContain('[#zz]x[/]'); // left as literal text
    expect(formatMessageText('[c:zz]x[/c]')).not.toContain('<span class'); // unknown palette key
  });

  it('applies underline, highlight, size, and font markers as CSP-safe tags (no inline style)', () => {
    expect(formatMessageText('[u]under[/u]')).toContain('<u>under</u>');
    expect(formatMessageText('[h:y]hi[/h]')).toContain('<span class="dd-hl-y">hi</span>');
    expect(formatMessageText('[z:l]big[/z]')).toContain('<font size="5">big</font>'); // legacy large
    expect(formatMessageText('[z:s]small[/z]')).toContain('<font size="2">small</font>'); // legacy small
    expect(formatMessageText('[f:m]code[/f]')).toContain('<span class="dd-ft-m">code</span>');
    // An unknown highlight/font key is left literal (only the fixed palette renders).
    expect(formatMessageText('[h:Z]x[/h]')).not.toContain('<span class');
    expect(formatMessageText('[h:y]hi[/h]')).not.toContain('style=');
  });

  it('parses every explicit size level 1-7 to its <font size> tag (three smaller, three larger)', () => {
    // The CSS maps each level to a distinct em; the DOM round-trip is covered in richtext.test.ts (jsdom).
    for (const n of [1, 2, 3, 4, 5, 6, 7]) {
      expect(formatMessageText(`[z:${n}]x[/z]`)).toContain(`<font size="${n}">x</font>`);
    }
  });

  it('treats a backslash-escaped marker character as a literal (round-trips editor text)', () => {
    expect(formatMessageText('a \\* b')).toContain('a * b');
    expect(formatMessageText('a \\* b')).not.toContain('<strong>');
    expect(formatMessageText('\\[c:rd]x')).toContain('[c:rd]x'); // escaped open bracket stays literal
  });

  it('composes and rebalances nested formatting into well-formed HTML', () => {
    // Properly nested: color > size > bold.
    expect(formatMessageText('[c#5a9be0][z:l]*x*[/z][/c]')).toBe('<font color="#5a9be0"><font size="5"><strong>x</strong></font></font>');
    // Improperly nested (bold opened, color opened, bold closed first): rebalanced, still well-formed.
    const html = formatMessageText('*a[c#ff0000]b*c[/c]');
    expect(html).toContain('</strong>'); // bold is closed
    expect((html.match(/<font/g) ?? []).length).toBe((html.match(/<\/font>/g) ?? []).length); // balanced fonts
    expect((html.match(/<strong>/g) ?? []).length).toBe((html.match(/<\/strong>/g) ?? []).length); // balanced bold
  });
});

describe('add-person (multi-person group chat)', () => {
  it('renders the add-person form with the group disclosure', () => {
    const html = renderAddPerson();
    expect(html).toContain('ADD PERSON');
    expect(html).toContain('id="dd-addperson-input"');
    expect(html).toContain('data-action="addperson-submit"');
    expect(html).toContain('can read messages sent from now on'); // earlier messages are not shared
    expect(html).not.toContain('—');
  });

  it('surfaces an error and escapes it', () => {
    expect(renderAddPerson('<b>x</b>')).toContain('&lt;b&gt;x&lt;/b&gt;');
  });
});

describe('key-exchange screen', () => {
  it('shows the peer fingerprint and accept/reject for an incoming offer', () => {
    const html = renderKeyExchange({
      mode: 'incoming',
      conversationId: 'c1',
      selfFingerprint: '9A·3C',
      peer: 'RAVEN',
      peerFingerprint: '5F·A2·91·C4',
    });
    expect(html).toContain('>RAVEN</div>');
    expect(html).toContain('5F·A2·91·C4');
    expect(html).toContain('data-action="accept-key"');
    expect(html).toContain('data-conv="c1"');
    expect(html).toContain('Confirm this key with your contact');
  });

  it('shows our own fingerprint when starting a new channel', () => {
    const html = renderKeyExchange({ mode: 'start', conversationId: 'new', selfFingerprint: '9A·3C·71·EE' });
    expect(html).toContain('NEW CHANNEL');
    expect(html).toContain('9A·3C·71·EE');
  });

  it('HTML-escapes an attacker-influenced peer name and fingerprint', () => {
    const html = renderKeyExchange({
      mode: 'incoming',
      conversationId: 'c1',
      selfFingerprint: 'x',
      peer: '<b>X</b>',
      peerFingerprint: '"><script>',
    });
    expect(html).not.toContain('<b>X</b>');
    expect(html).not.toContain('"><script>');
  });

  it('escapes a pre-filled peer username (from a scanned contact link) in the start-screen input value', () => {
    const html = renderKeyExchange({
      mode: 'start',
      conversationId: 'new',
      selfFingerprint: 'x',
      byUsername: true,
      selfUsername: 'me',
      peerUsername: '"><script>alert(1)</script>',
    });
    expect(html).toContain('id="dd-peer-username"');
    expect(html).not.toContain('"><script>'); // attribute-injection safe
    expect(html).toContain('&lt;script&gt;'); // shown escaped inside the value
  });
});

describe('add-a-device QR screens (QR5)', () => {
  const device = {
    deviceId: 'this',
    deviceKey: 'aa'.repeat(32),
    addedAt: 1,
    lastSeenAt: 2,
    revoked: false,
    current: true,
    authorized: true,
  };

  it('Device keys offers both the QR path and the six-word fallback', () => {
    const html = renderSettings([device], 'aa'.repeat(32));
    expect(html).toContain('data-action="scan-device"'); // authorized device scans the new one
    expect(html).toContain('data-action="show-device-qr"'); // new device shows its code
    expect(html).toContain('data-action="add-device"'); // six-word fallback stays
    expect(html).toContain('data-action="connect-this-device"');
  });

  it('hides revoked devices from the Device keys list (row kept only server-side as a burned tombstone)', () => {
    const revoked = { deviceId: 'oldphone', deviceKey: 'bb'.repeat(32), addedAt: 1, lastSeenAt: 2, revoked: true, current: false, authorized: false };
    const html = renderSettings([device, revoked], 'aa'.repeat(32));
    expect(html).toContain('AA·AA·AA·AA'); // the active device's key still renders
    expect(html).not.toContain('BB·BB·BB·BB'); // the revoked device's key is not rendered
    expect(html).not.toContain('oldphone'); // and neither is its id
  });

  it('the last-device guard counts only AUTHORIZED devices (an orphan cannot unblock self-revoke)', () => {
    const other = { deviceId: 'laptop', deviceKey: 'cc'.repeat(32), addedAt: 1, lastSeenAt: 2, revoked: false, current: false, authorized: true };
    const orphan = { deviceId: 'orphan', deviceKey: 'dd'.repeat(32), addedAt: 1, lastSeenAt: 2, revoked: false, current: false, authorized: false };
    // Two authorized devices: the current device is revocable (no "only device" lock).
    expect(renderSettings([device, other], 'aa'.repeat(32))).not.toContain('your only device');
    // The current device alone: the guard blocks self-revoke and points to Self Destruct.
    expect(renderSettings([device], 'aa'.repeat(32))).toContain('your only device');
    // The current device plus an unauthorized ORPHAN sibling: the orphan does not count, guard still holds.
    expect(renderSettings([device, orphan], 'aa'.repeat(32))).toContain('your only device');
  });

  it('Device keys has a centered Back button in both the populated and empty states', () => {
    const populated = renderSettings([device], 'aa'.repeat(32));
    expect(populated).toContain('data-action="settings-back"');
    expect(populated).toContain('dd-field dd-form-actions');
    const empty = renderSettings([], 'aa'.repeat(32));
    expect(empty).toContain('data-action="settings-back"'); // reachable even when devices fail to load
  });

  it('the new device shows a scannable QR (no six words) and no inline style', () => {
    const payload = 'ddpair:' + 'A'.repeat(80);
    const html = renderProvisioning({ role: 'newdevice', step: 'showqr', qr: payload });
    expect(html).toContain('SHOW THIS CODE');
    expect(html).toContain('<svg'); // an inline QR was rendered
    expect(html).not.toContain('style='); // CSP-safe: no inline styles
    expect(html).toContain('data-action="prov-cancel"');
  });

  it('a QR that cannot be built falls back to the six-word guidance', () => {
    const html = renderProvisioning({ role: 'newdevice', step: 'showqr', qr: '' });
    expect(html).toContain('Connect this device'); // pointed at the fallback
    expect(html).not.toContain('<svg');
  });

  it('the qrexpired step offers a fresh code and a way back (Fix 3)', () => {
    const html = renderProvisioning({ role: 'newdevice', step: 'qrexpired' });
    expect(html).toContain('The code expired before your other device scanned it.');
    expect(html).toContain('data-action="show-device-qr"'); // Show a new code
    expect(html).toContain('data-action="prov-cancel"'); // Back
    expect(html).not.toContain('style=');
  });

  it('the new-device wizard points at Device keys (not the old Settings) and offers a scannable QR', () => {
    const html = renderNewDeviceWizard({ step: 'choose', connected: true });
    // "Settings" was renamed to "Device keys" long ago; the wizard copy must not still send users there.
    expect(html).not.toContain('Settings');
    expect(html).toContain('Device keys');
    // Both add-a-device paths are offered: the six-word compare AND a QR the other device scans.
    expect(html).toContain('data-action="wizard-provision"'); // six words
    expect(html).toContain('data-action="show-device-qr"'); // show a scannable code
  });

  it('the provisioning wait screens point at Device keys, never the old Settings', () => {
    expect(renderProvisioning({ role: 'newdevice', step: 'waiting' })).not.toContain('Settings');
    expect(renderProvisioning({ role: 'newdevice', step: 'waiting' })).toContain('Device keys');
    expect(renderProvisioning({ role: 'seedholder', step: 'waiting' })).not.toContain('Settings');
  });

  it('the scanning screen wires a camera preview element', () => {
    const html = renderProvisioning({ role: 'seedholder', step: 'scanning' });
    expect(html).toContain('SCAN A DEVICE');
    expect(html).toContain('id="dd-scan-video"');
    expect(html).toContain('id="dd-scan-canvas"');
    expect(html).toContain('data-action="prov-cancel"');
  });
});

describe('add-a-buddy by QR (contact exchange)', () => {
  it('Buddy List Setup offers Scan a buddy / Scan me under Delete', () => {
    const html = renderBuddySetup([], [], {}, [], false, true, null);
    const delAt = html.indexOf('data-action="setup-delete"');
    const scanAt = html.indexOf('data-action="buddy-scan"');
    const meAt = html.indexOf('data-action="buddy-showme"');
    expect(delAt).toBeGreaterThan(-1);
    expect(scanAt).toBeGreaterThan(delAt); // the scan buttons sit below Delete
    expect(meAt).toBeGreaterThan(delAt);
    expect(html).toContain('>Scan a buddy</button>');
    expect(html).toContain('>Scan me</button>');
  });

  it('the Scan a buddy screen wires a camera preview (no six words)', () => {
    const html = renderBuddyScan();
    expect(html).toContain('SCAN A BUDDY');
    expect(html).toContain('id="dd-scan-video"');
    expect(html).toContain('id="dd-scan-canvas"');
    expect(html).toContain('data-action="buddy-scan-cancel"');
  });

  it('the Scan me screen renders a contact QR with no inline style', () => {
    const html = renderBuddyQr('https://d3addr0p.com/#dd=alice&k=abc123');
    expect(html).toContain('SCAN ME');
    expect(html).toContain('<svg'); // the contact QR
    expect(html).not.toContain('style='); // CSP-safe
    expect(html).toContain('data-action="buddy-qr-back"');
  });

  it('the Scan me screen degrades gracefully with no link', () => {
    const html = renderBuddyQr('');
    expect(html).not.toContain('<svg');
    expect(html).toContain('Profile'); // pointed at the Profile share fallback
  });

  it('parseContactLink extracts the username and fingerprint, and rejects non-contacts', () => {
    const ok = parseContactLink('https://d3addr0p.com/#dd=bob&k=deadbeef');
    expect(ok).toEqual({ username: 'bob', fingerprint: 'deadbeef' });
    expect(parseContactLink('ddpair:AAAA')).toBeNull(); // a device-pairing code, not a contact
    expect(parseContactLink('https://example.com/no-fragment')).toBeNull();
    expect(parseContactLink('https://d3addr0p.com/#other=1')).toBeNull(); // fragment without dd=
    expect(parseContactLink('#dd=carol')?.username).toBe('carol'); // bare fragment, no fingerprint
    expect(parseContactLink('#dd=carol')?.fingerprint).toBe('');
  });
});


describe('buddy verification badge', () => {
  const buddy = { username: 'raven', addedAt: 1, group: 'Buddies' };
  it('marks a verified buddy with a quiet check and a changed one loudly', () => {
    const ok = renderBuddies([buddy], [], { raven: 'online' }, [], [], [], DEFAULT_IDENTITY, 'me', {}, {}, undefined, {}, { raven: 'verified' });
    expect(ok).toContain('dd-tree-verify');
    expect(ok).toContain('\u2713');
    const bad = renderBuddies([buddy], [], { raven: 'online' }, [], [], [], DEFAULT_IDENTITY, 'me', {}, {}, undefined, {}, { raven: 'changed' });
    expect(bad).toContain('dd-tree-verify-bad');
    expect(bad).toContain('identity changed');
  });
  it('renders a pinned-but-uncheckable buddy distinctly, never as a confident check', () => {
    const stale = renderBuddies([buddy], [], { raven: 'online' }, [], [], [], DEFAULT_IDENTITY, 'me', {}, {}, undefined, {}, { raven: 'stale' });
    expect(stale).toContain('dd-tree-verify-stale');
    expect(stale).toContain('cannot check right now');
    // The confident check belongs to 'verified' alone (matched by its exact title attribute, since
    // other chrome on this screen legitimately uses a check glyph).
    expect(stale).not.toContain('title="verified"');
  });
  it('leaves an unverified buddy unadorned (no alarm fatigue)', () => {
    const html = renderBuddies([buddy], [], { raven: 'online' }, [], [], [], DEFAULT_IDENTITY, 'me', {});
    expect(html).not.toContain('dd-tree-verify');
  });
});
