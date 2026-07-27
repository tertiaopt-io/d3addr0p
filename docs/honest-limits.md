# Honest Limits (product copy)

> This is the §A.3 bright-line copy. It must appear to users, plainly. The strings in the
> "In-product copy" blocks are app-facing: no em-dashes, no "not X but Y" constructions
> (brief §0.7). Engineers: do not soften these and do not let any feature description
> contradict them. False confidence is the failure mode that gets people hurt.

## What this app does not protect against

These limits are real and permanent. State them, do not bury them.

1. **A compromised or unlocked-under-coercion device.** If your phone is infected with
   spyware, or it is taken while unlocked and you are forced to open the app, no messaging
   system can protect the contents of your conversations. This app reduces and bounds that
   damage. It does not remove it.

2. **The destination is visible on the network.** The name of the server you connect to
   travels in the clear on every connection. The set of people who connect to it can be
   counted. This app relies on that name looking ordinary, on a convincing decoy site, and
   on changing the name over time. It does not hide which server you reach. If you need to
   hide that, turn on Tor in settings and accept that your traffic will look unusual.

3. **The look is cover, not a lock.** The retro appearance helps this app blend in as a
   novelty rather than a security tool. Appearance protects no one on its own. The duress
   passphrase, decoy mode, panic wipe, and key destruction are the defenses that matter if
   your device is examined.

4. **Disappearing messages are cooperative once read.** A timer reduces exposure. It does
   not delete a message that someone has already screenshotted, photographed off the screen,
   or captured with spyware. Once a message is on a screen, it can leave the system.

5. **Detection is made harder, not impossible.** Traffic shaping raises the cost of spotting
   this app on a hostile network. It does not make it invisible.

6. **This is a web app, and the server it loads from is its origin.** Install it to your home
   screen so it pins a signed copy and stops downloading fresh code each time. Even installed,
   the first load is a moment of trust, and your browser and operating system are part of what
   you are trusting. Verify the published build hash through a channel you trust before you
   rely on it. A native packaged app would be stronger here. This build does not ship one.

7. **Your messages can be tied to you cryptographically.** Each message you send is signed by
   your key. Someone who captures a message and your key can show that your key signed it. This
   app does not give you the ability to deny later that you sent a given message. Plan around
   that. The duress passphrase, decoy mode, and panic wipe protect what is on your device, and
   they are what you rely on if you are forced to open the app.

8. **You are trusting the keys the service handed you.** When you start a conversation, the two
   keys are exchanged through the service. This build does not yet let you confirm a contact's
   key through a separate trusted channel, so a server that has been seized or compelled could
   hand each side the wrong key and read everything between you. The app warns you if a key you
   already accepted later changes, and that warning only helps after the first exchange. Until
   key confirmation through a separate channel is added, treat the identity of a new contact as
   unconfirmed.

9. **Your passphrase is the lock on everything stored.** What this app keeps on your device is
   encrypted, and your passphrase is what unlocks it. If your device is taken while powered off,
   someone with it can try to guess your passphrase offline for as long as they like. A strong,
   unique passphrase is the only thing protecting your stored messages and contacts in that case.
   The panic wipe destroys the key, and on flash storage that is the real protection, stronger
   than trying to overwrite the data. Choose a passphrase you would trust with your life.

10. **A message you already read can, in a narrow case, be recovered.** This build cannot fully
    erase the key history for messages you have already received if someone takes an image of
    your powered-off device AND has also recorded your network traffic. Messages you have not yet
    read, and the readable copies the app stores, are still protected by their own keys. This is a
    known gap in the underlying library that will close in a later version. If this case is part
    of your threat, turn off message history or use the ephemeral session mode.

11. **A proxy in front of the service can see who connects and when.** This deployment is reached
    through Cloudflare, which unscrambles the connection at its edge before passing it on. Cloudflare
    can see your address, the times you connect, the size of your messages, and the routing labels
    they carry. It cannot read the messages themselves, which stay encrypted end to end and whose
    keys it never holds. It is still a company that sees this pattern of activity and can be compelled
    to hand it over. The service behind it keeps no logs and never even sees your real address, so
    this exposure is to Cloudflare, not to the server. If a company being able to see when and from
    where you connect is part of your risk, reach the service directly or over Tor instead.

12. **The service keeps a list of accounts so usernames stay unique.** To let you sign in with a
    username and to let people reach you by that name, the server stores a scrambled form of your
    username, a check value it can test your passphrase against without learning it, and the public
    key of each device on your account. It never sees your username in plain form, your passphrase, a
    device name, or any message in your conversations. The only personal text it can read is an away
    message, and only if you choose to store one on it by turning on server-side away replies (item 15).
    Two risks come with this. A seized server could block or refuse
    accounts. And because people find each other by looking a username up on the server, a server that
    has been seized or compelled could hand back the wrong key for a name and sit in the middle, which
    is why you still confirm a contact's key fingerprint through a channel you already trust before you
    rely on it. Two smaller things a caller can learn from the server. Whether a scrambled username is
    registered, since a sign-in or reach attempt answers differently for a name that exists (the plain
    handle is never revealed, only that its scrambled form is in use). And to add you to a group, any
    signed-in account can claim your devices' one-time keys from the server; the server limits how fast
    one account can claim yours, but a determined caller could slowly use them up, which only forces a
    later add onto a reusable fallback key and never exposes a message. Nobody can reset your login: a
    lost username or passphrase loses the account for good.
    There is one recovery path, the recovery secret you saved when you created the account; it never
    reaches the server, and if you lose it and every signed-in device, the account is gone for good.

13. **Your account can have more than one device, and that comes with limits.** Every device on your
    account receives each message, and you can reply from any of them. A device added later receives
    messages from when it joins onward and cannot read the ones sent before it joined (forward secrecy),
    and your devices heal this themselves as they reconnect, so a device that was offline when another was
    added pulls it into your open conversations once it comes back online. A new device joins in one of three
    ways: another signed-in device scans a one-time QR code that the new device shows, or another signed-in
    device adds it and you compare the same six words on both screens before it is trusted, or you enter your
    recovery secret on the new device. The QR code carries only a fresh one-time pairing key and the new
    device's public key, and it is read by the camera alone, so it never travels through the server; the
    authorization is then sealed to that one-time key, which means a server that relays your traffic can
    neither read it nor redirect it to a device you did not scan. Scanning opens your camera on this site
    only, and the video stays on your device and is never sent anywhere. If your browser cannot open the
    camera, use the six-word method instead. The scan itself is the trust, so it adds whichever device
    shows the code: only scan a code shown by your own new device under Device keys, Show this device, and
    only show your code to your own device's camera. Scanning a code from anywhere else, or showing yours
    to someone else, links that device instead, the same way it works when you link a phone by QR
    elsewhere. Four things to know. First, your
    recovery secret can add a device by itself, so guard it like the account: anyone who has it can join
    a device to your name. Your passphrase alone enrolls a device record on the server too, so open
    Settings and check the device list if you suspect either was learned. Second, revoking a device burns
    its key on the server so it can never sign in or be reached again, and it rotates your group keys so
    that device cannot read messages sent after the revoke; it does not reach into a device that already
    holds your messages, does not erase those messages, and does not wipe the device. Third, the lock
    that stops a removed device from being slipped back in strengthens as your other devices reconnect
    and re-key; a seized or compelled server can delay that catch-up, which only keeps the removed device
    out more slowly, and it cannot roll back a device that has already caught up. Fourth, the first time
    you see a new contact's set of devices is trust on first use, the same as their key, so confirm it
    through a channel you already trust. The app tells you when your account has more than one device.
    Note to Self is a private chat with only your own devices: a note is end-to-end encrypted to that
    group, stored under your passphrase, and syncs to every device you are signed in on. It rides the
    same channel as your buddy-list sync and is never sent to anyone else. The same forward-secrecy limit
    applies, so a device you link later shows only the notes written after it joined, not your older ones,
    and on a single device a note is simply kept locally until you add a second one.

14. **Your buddy icon and profile travel inside your conversations and the server never stores them.**
    When you set a buddy icon or a short profile, it goes to the people you already have a conversation
    with as encrypted content, the same way a message does, so the server cannot read it. Two things
    follow from there being no server directory for it. A new contact sees a blank icon and no profile
    until the first time the two of you connect. And the server can tell WHEN you publish a buddy icon or
    profile, because an uploaded image is larger than a text message, though it still cannot read what the
    image is; an emoji or initials icon is small enough that even the timing is hidden. A profile is
    written by the person it belongs to and does not prove who they are, so confirm a contact's key
    fingerprint through a channel you already trust before you rely on what their profile says. Your buddy
    list is handled differently, because it is your contact graph. It syncs across your own devices over a
    hidden group that holds only your own devices, so it never rides a conversation with another person and
    a contact never learns who else is on your list. The most recent change to each buddy wins on every
    device, so an add and a removal both travel. Two things the server can still see: that your account
    keeps one hidden own-devices group, and roughly when your list changes from the timing of an update. It
    cannot read who is on the list.

15. **Away messages have two modes, and the server-backed one is a deliberate tradeoff.** Your away
    message is stored on your device, and there are two ways it gets sent. While you are signed in but
    idle, your device sends it back as an encrypted reply to whoever messages you, rate-limited so it
    does not spam them, and a message that arrived while every device was offline gets that reply the
    next time a device comes online. Two limits on this device-only mode: sending any auto-reply at all
    tells a network observer that one of your devices was online to handle the incoming message, which it
    could not otherwise tell for an unread message, so turn auto-reply off if hiding that matters to you;
    and the reply is best-effort, because the server holds an undelivered message in memory for up to
    seven days, so if you stay offline past that or the server restarts, the reply is lost and the sender
    gets nothing. Your away setting (the message, the on/off state, and the server-side choice) syncs
    across your own devices so the most recent change from any device wins everywhere; it rides your
    conversations like your buddy icon, so only your own devices adopt it (a peer cannot push you a fake
    one), but a peer's device does receive the encrypted bytes, which is acceptable because your away
    message is text meant for that peer anyway. Separately, and off by default, you can turn on server-side away replies, which relaxes
    the guarantees above: the server then stores your away message in readable form, your device sends a
    small heartbeat while you are online so the server can tell when all your devices go offline, and the
    server hands your away message to anyone who looks you up while you are offline. Three costs come with
    that mode: the server can read your away message, the heartbeat lets the server learn when you are
    online for every session you are signed in and not only when you are away, and the server learns that
    a given person reached you while you were offline. Leave server-side away replies off unless you
    accept those costs.

16. **Sharing your status tells the server, and your buddies, when you are around.** Presence is off by
    default. When you turn it on, your device sends a small heartbeat to the server with your status
    (online, away, or idle), and buddies who look you up see it. The server can read this status, and
    because the heartbeat runs the whole time you are signed in with presence on, the server learns your
    pattern of when you are online, not only your status right now. Idle is detected from your own
    activity and set for you. Turn presence off to keep all of this to yourself; your buddies then see
    you as offline.

17. **Blocking is best-effort and bounded.** When you block a contact, their key goes on a list, you
    leave that conversation, and a fresh invitation from a fully-blocked group is dropped before you ever
    see it. Three limits come with that. Block stops new messages and new conversations; it cannot reach
    a message a device of yours already received and stored. It blocks a key, so a determined person can
    reach you again from a new device key, which shows up as a new unverified contact. And the block
    lives only on your devices; the person you blocked is not told, and nothing stops them from trying.

18. **Sending a file connects you straight to the other person, which reveals your network address.** A
    file you send goes directly device to device over an encrypted connection, and the bytes never pass
    through the server. There is no size limit, because the file is streamed in small pieces rather than
    loaded whole, so a large file moves without filling memory. On a browser that can save straight to
    disk, a received file is written there as it arrives; otherwise it is held in memory until it
    finishes, which a very large file can strain on a small device. You are asked to accept an incoming
    file before it begins, because accepting is what opens the direct connection. The cost of going
    direct is that the two devices learn each other's real network address, the one piece of information
    the rest of this app works to hide. A helper server is used only to discover how to reach each other,
    never to carry the file. Because there is no relay, a strict network in between can stop the direct
    connection from forming, and the transfer then fails rather than falling back through a server. Send
    or accept a file only when revealing your address to that contact is acceptable, and treat a file you
    receive with the same care as any attachment, because it is something the sender chose to hand you.

19. **Audio and video calls connect you straight to the other person, which reveals your network
    address.** A call's sound and picture travel directly device to device and never pass through the
    server. The media is encrypted by the call itself, and the keys that protect it are carried inside
    your end-to-end channel, so the server can neither listen in nor stand in the middle. Two costs come
    with going direct, the same as for files. The two devices learn each other's real network address,
    the thing the rest of this app works to hide, so place or accept a call only when that is acceptable
    to you. And because there is no relay, a strict network in between can stop the call from connecting,
    and it then fails rather than routing through a server. Calls are one to one. Starting a call tells
    the other side you are reaching out right then, and the fact that a call happened and how long it
    lasted is something an observer of either side's network can notice, even though what is said stays
    private.

### In-product copy: first-run notice

```
Read this before you trust your safety to this app.

This app keeps your messages unreadable to the server and to the network. It cannot
protect you if your phone is infected with spyware, or if it is taken while unlocked and
you are forced to open it. It cannot hide which server you connect to. The retro look is
cover, not protection. Disappearing messages reduce exposure, they do not erase a message
someone already saw. Detection is made harder, never impossible.

If your safety depends on this, learn the duress passphrase and the panic wipe before you
send anything.
```

### In-product copy: disappearing-message tooltip

```
This message becomes unreadable when the timer ends, and its key is destroyed so it cannot
be recovered from this device later. For a message you receive, the timer starts when you
open the conversation, so it will not disappear before you have seen it. This does not erase
a copy someone already saw, screenshotted, or photographed.
```

### In-product copy: identity and away

```
Your buddy icon and profile are sent inside your encrypted conversations. The server never
stores them. People see them after you and they have connected once. A new contact sees a
blank icon until then.

Your away message is stored on this device. It is sent from your device as an encrypted
reply when one of your devices is online. If every device is offline, it is sent the next
time a device comes online. If you stay offline past seven days, or the server restarts, the
reply is lost and the sender gets nothing.

With server away replies on, the server stores your away message and can tell when all your
devices are offline. Anyone who messages you while you are offline gets that reply, and the
server can see they reached you. Turn this off to keep your offline status off the server.
```

### In-product copy: network / Tor setting

```
Standard mode keeps you reachable and makes your traffic look ordinary to a casual
observer. The server name you connect to is still visible on the network. Tor mode hides
which server you reach, and your traffic will look unusual. Choose Tor only if hiding the
destination is worth standing out.
```

### In-product copy: files and calls

```
A file you send goes straight to the other person and never reaches the server. There is no
size limit. Going direct means you and they learn each other's network address. A strict
network in between can stop the transfer, and there is no fallback through a server. You
choose whether to accept an incoming file before it starts.

A call connects you directly to the other person. The sound and picture are encrypted and
never reach the server. Going direct means you and they learn each other's network address.
A strict network in between can stop a call from connecting, with no fallback. Calls are one
to one.
```

## What "forensic unrecoverability" covers, exactly

Holds for:
- Traffic captured in transit, against a classical attacker (stays opaque without endpoint keys).
  **It is NOT yet post-quantum safe**: the post-quantum ciphersuite is not running in this build
  (ADR-007), so an adversary who stores your traffic today may be able to decrypt it with a future
  quantum computer. Treat harvest-now-decrypt-later as a real risk until that lands.
- Data on the server (in memory only, deleted once every device of the conversation has
  confirmed durable receipt, or after at most 24 hours). Each device registers an opaque
  per-mailbox delivery cursor so a device that crashes mid-receive is re-sent the ciphertext
  it missed instead of silently losing it. The cursor is a per-mailbox SECRET-KEYED tag (not
  the device's bootstrap key), so two mailboxes of the same device carry unrelated tags: a
  snapshot of the in-memory registry cannot be read as a device-to-conversation map. Honest
  cost: a LIVE observer still correlates a device's mailboxes from the simultaneous
  subscriptions on its one connection; the registry only makes that (already visible)
  association persist for up to 2 hours after the device goes offline, then it is dropped.
  The server tracks at most 128 device cursors per mailbox; a conversation whose member
  devices exceed that can, in a crash-during-delivery corner, still lose the redelivery
  guarantee for its least recently seen devices. The crash-redelivery poison-drop (which lets
  the server discard a permanently unprocessable frame so a member cannot pin a mailbox with
  junk) covers malformed frames and authorization-gate rejections only; a stale-epoch, replay,
  or decrypt-failed frame is not dropped early and redelivers until its TTL, bounded like any
  publish-flood by the 1024-blob-per-mailbox cap and the transport TTL.
  The delivery cursor is kept only while a mailbox is active (a held blob or a live subscriber);
  once a mailbox fully drains it is pruned at once rather than kept for the 2-hour window, so the
  crash-redelivery guarantee holds strictly for a blob still held for you, but a device offline
  across a window where its mailbox empties out gets no redelivery of a message published in that
  gap. This narrows, but does not remove, the residual crash-fork corner: if your own group commit
  goes unseen until its transport TTL expires while every peer is offline, and a peer then returns
  and commits a rival before you reconnect, your device can still confirm its stale commit onto a
  private epoch (the same outcome the underlying at-most-once bus produced before this feature, now
  reachable in a narrower window). Closing it fully needs a durable, acknowledged message log,
  which the single-node in-memory bus is not.
- Data at rest on a device seized powered-off or locked, after its lifetime expires
  (destroyed by crypto-erase, not byte overwrite).

Does **not** hold for:
- A message on an implanted endpoint.
- A device seized while unlocked under coercion.
- A screenshot or a photograph of the screen.
- A server seized while powered on, for the specific ciphertexts in its brief in-flight
  window (those stay opaque without endpoint keys).
