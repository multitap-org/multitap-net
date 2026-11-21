// net_webrtc.js: the browser half of net_rtc_emscripten.cpp (Emscripten
// --js-library; frontend_net adds it to the link by itself, and exports its
// path as MULTITAP_NET_WEBRTC_JS).
//
// Everything here runs on the page's main thread, the only place browsers
// give RTCPeerConnection, RTCDataChannel and WebSocket. C++ writes commands
// into one ring and wakes us with net_webrtc_kick (proxied here, async);
// what the browser reports goes back as events into the ring of the NetRtc
// or socket it belongs to, which the network thread polls. The ring layout
// and the command / event numbers are described in net_rtc_emscripten.cpp:
// keep both files in step.
//
// The bytes: data channels and WebSocket refuse views of shared memory, so
// what we send is copied out of the heap first (slice), and what arrives is
// copied into the ring. Those copies are the browser's own allocations;
// nothing on the C++ side allocates per message.
//
// Signaling blobs (net_rtc.h): 'd' type 0 sdp, or 'c' mid 0 candidate.

var LibraryNetWebRtc = {
  $NetWebRtc: {
    instances: [],   // NetRtc id -> {ring, buffered, queued, stun, peers: [], pending: []}
    sockets: [],     // socket id -> {ring, ws, pending: [], closed}
    timer: 0,
    encoder: null,
    decoder: null,

    LABELS: ['control', 'input', 'stream', 'files'],
    CHANNELS: 4,
    MAX_PEERS: 8,

    // Ring offsets (bytes) and record header.
    HEAD: 0, TAIL: 4, SIZE: 8, DROPPED: 12, RELEASED: 16, DATA: 32,
    WRAP: 0xFFFFFFFF,

    // Commands (C++ -> JS).
    CMD_INSTANCE_OPEN: 1, CMD_INSTANCE_CLOSE: 2, CMD_PEER_OPEN: 3, CMD_PEER_SIGNAL: 4,
    CMD_PEER_SEND: 5, CMD_PEER_CLOSE: 6, CMD_SOCKET_OPEN: 7, CMD_SOCKET_SEND: 8, CMD_SOCKET_CLOSE: 9,
    // Events (JS -> C++).
    EV_CONNECTED: 1, EV_DISCONNECTED: 2, EV_RECEIVED: 3, EV_SIGNAL: 4,
    EV_SOCKET_OPEN: 6, EV_SOCKET_MESSAGE: 7, EV_SOCKET_CLOSED: 8,

    log: function(text) {
      console.warn('net_webrtc: ' + text);
    },

    text: function(bytes) {
      if (!NetWebRtc.decoder) NetWebRtc.decoder = new TextDecoder();
      return NetWebRtc.decoder.decode(bytes);
    },

    // One record into a ring C++ reads. False when it doesn't fit.
    write: function(ring, kind, channel, owner, index, bytes) {
      var size = bytes ? bytes.length : 0;
      var need = 12 + ((size + 3) & ~3);
      var base = ring >>> 2;
      var ringSize = HEAPU32[base + 2];
      if (need > ringSize) return false;
      var head = Atomics.load(HEAPU32, base);
      var tail = Atomics.load(HEAPU32, base + 1);
      var position = head & (ringSize - 1);
      var contiguous = ringSize - position;
      var total = need > contiguous ? contiguous + need : need;
      if (((head - tail) >>> 0) + total > ringSize) {
        Atomics.add(HEAPU32, base + 3, 1);
        return false;
      }
      var data = ring + NetWebRtc.DATA;
      if (need > contiguous) {
        HEAPU32[(data + position) >>> 2] = NetWebRtc.WRAP;
        head = (head + contiguous) >>> 0;
        position = 0;
      }
      var at = data + position;
      HEAPU32[at >>> 2] = need;
      HEAPU8[at + 4] = kind;
      HEAPU8[at + 5] = channel;
      HEAPU8[at + 6] = owner;
      HEAPU8[at + 7] = index;
      HEAPU32[(at + 8) >>> 2] = size;
      if (size > 0) HEAPU8.set(bytes, at + 12);
      Atomics.store(HEAPU32, base, (head + need) >>> 0);
      return true;
    },

    // An event for C++. Data on an unreliable channel that doesn't fit is
    // dropped (as the network would); anything else waits in `pending`, in
    // order, and the timer retries it.
    emit: function(owner, holder, kind, channel, index, bytes, droppable) {
      if (holder.pending.length === 0 && NetWebRtc.write(holder.ring, kind, channel, owner, index, bytes)) return true;
      if (droppable) return false;
      if (bytes && bytes.buffer === HEAPU8.buffer) bytes = bytes.slice();
      holder.pending.push([kind, channel, index, bytes]);
      NetWebRtc.startTimer();
      return true;
    },

    flush: function(owner, holder) {
      while (holder.pending.length > 0) {
        var event = holder.pending[0];
        if (!NetWebRtc.write(holder.ring, event[0], event[1], owner, event[2], event[3])) return;
        holder.pending.shift();
      }
    },

    // Every 20 ms while anything is open: what waited for room in a ring,
    // and the channels' bufferedAmount (it falls without telling us).
    startTimer: function() {
      if (NetWebRtc.timer) return;
      NetWebRtc.timer = setInterval(function() {
        var busy = false;
        NetWebRtc.instances.forEach(function(instance, id) {
          if (!instance) return;
          busy = true;
          NetWebRtc.flush(id, instance);
          instance.peers.forEach(function(peer, index) {
            if (peer) NetWebRtc.updateBuffered(instance, index, peer);
          });
        });
        NetWebRtc.sockets.forEach(function(socket, id) {
          if (!socket) return;
          busy = true;
          NetWebRtc.flush(id, socket);
        });
        if (!busy) {
          clearInterval(NetWebRtc.timer);
          NetWebRtc.timer = 0;
        }
      }, 20);
    },

    updateBuffered: function(instance, index, peer) {
      var base = (instance.buffered >>> 2) + index * NetWebRtc.CHANNELS;
      for (var c = 0; c < NetWebRtc.CHANNELS; c++) {
        var amount = peer && peer.channels[c] ? peer.channels[c].bufferedAmount : 0;
        Atomics.store(HEAPU32, base + c, amount >>> 0);
      }
    },

    blob: function(tag, shortText, longText) {
      if (!NetWebRtc.encoder) NetWebRtc.encoder = new TextEncoder();
      var a = NetWebRtc.encoder.encode(shortText);
      var b = NetWebRtc.encoder.encode(longText);
      var out = new Uint8Array(2 + a.length + b.length);
      out[0] = tag.charCodeAt(0);
      out.set(a, 1);
      out[1 + a.length] = 0;
      out.set(b, 2 + a.length);
      return out;
    },

    // Forgets a peer: no handler of it runs again. `report`: tell C++ (its
    // index is free once C++ reads this).
    closePeer: function(id, instance, index, report) {
      var peer = instance.peers[index];
      if (!peer) return;
      instance.peers[index] = null;
      peer.closed = true;
      peer.pc.onicecandidate = null;
      peer.pc.onconnectionstatechange = null;
      peer.channels.forEach(function(channel) {
        if (!channel) return;
        channel.onopen = null;
        channel.onclose = null;
        channel.onmessage = null;
        channel.onbufferedamountlow = null;
        try { channel.close(); } catch (e) {}
      });
      try { peer.pc.close(); } catch (e) {}
      NetWebRtc.updateBuffered(instance, index, null);
      if (report) NetWebRtc.emit(id, instance, NetWebRtc.EV_DISCONNECTED, 0, index, null, false);
    },

    openPeer: function(id, instance, index, offers) {
      if (instance.peers[index]) NetWebRtc.closePeer(id, instance, index, false);
      var pc;
      try {
        pc = new RTCPeerConnection({iceServers: instance.stun ? [{urls: instance.stun}] : []});
      } catch (e) {
        NetWebRtc.log('no RTCPeerConnection: ' + e);
        NetWebRtc.emit(id, instance, NetWebRtc.EV_DISCONNECTED, 0, index, null, false);
        return;
      }
      var peer = {pc: pc, channels: [], open: 0, connected: false, closed: false, offers: offers,
                  chain: Promise.resolve()};
      instance.peers[index] = peer;
      var fail = function(error) {
        if (peer.closed) return;
        NetWebRtc.log('connection ' + index + ': ' + error);
        NetWebRtc.closePeer(id, instance, index, true);
      };
      // The four channels, negotiated out of band with fixed ids (the same on
      // both sides, libdatachannel's too). control, files: reliable, ordered.
      // input, stream: unordered, never sent again.
      for (var c = 0; c < NetWebRtc.CHANNELS; c++) {
        var reliable = c === 0 || c === 3;
        var options = {negotiated: true, id: c, ordered: reliable};
        if (!reliable) options.maxRetransmits = 0;
        var channel = pc.createDataChannel(NetWebRtc.LABELS[c], options);
        channel.binaryType = 'arraybuffer';
        channel.bufferedAmountLowThreshold = 64 * 1024;
        peer.channels.push(channel);
        (function(number, droppable) {
          channel.onopen = function() {
            if (peer.closed) return;
            peer.open++;
            if (peer.open === NetWebRtc.CHANNELS && !peer.connected) {
              peer.connected = true;
              NetWebRtc.emit(id, instance, NetWebRtc.EV_CONNECTED, 0, index, null, false);
            }
          };
          channel.onclose = function() {
            fail('channel ' + NetWebRtc.LABELS[number] + ' closed');
          };
          channel.onmessage = function(event) {
            if (peer.closed || !(event.data instanceof ArrayBuffer)) return;   // text: never ours
            var bytes = new Uint8Array(event.data);
            if (!NetWebRtc.emit(id, instance, NetWebRtc.EV_RECEIVED, number, index, bytes, droppable) && !droppable) {
              fail('no room for a reliable message');
            }
          };
          channel.onbufferedamountlow = function() {
            if (!peer.closed) NetWebRtc.updateBuffered(instance, index, peer);
          };
        })(c, !reliable);
      }
      pc.onicecandidate = function(event) {
        if (peer.closed || !event.candidate || !event.candidate.candidate) return;
        NetWebRtc.emit(id, instance, NetWebRtc.EV_SIGNAL, 0, index,
                       NetWebRtc.blob('c', event.candidate.sdpMid || '', event.candidate.candidate), false);
      };
      pc.onconnectionstatechange = function() {
        if (pc.connectionState === 'failed' || pc.connectionState === 'closed') fail(pc.connectionState);
      };
      if (offers) {
        peer.chain = peer.chain.then(function() {
          return pc.createOffer();
        }).then(function(offer) {
          return pc.setLocalDescription(offer);
        }).then(function() {
          if (peer.closed) return;
          NetWebRtc.emit(id, instance, NetWebRtc.EV_SIGNAL, 0, index,
                         NetWebRtc.blob('d', 'offer', pc.localDescription.sdp), false);
        }).catch(fail);
      }
    },

    // A blob from the other side. Steps run one after another per peer (the
    // chain), so a candidate is only added after the description before it.
    signalPeer: function(id, instance, index, bytes) {
      var peer = instance.peers[index];
      if (!peer || bytes.length < 3) return;
      var zero = bytes.indexOf(0, 1);
      if (zero < 0) return;
      var shortText = NetWebRtc.text(bytes.subarray(1, zero));
      var longText = NetWebRtc.text(bytes.subarray(zero + 1));
      var pc = peer.pc;
      var fail = function(error) {
        if (peer.closed) return;
        NetWebRtc.log('connection ' + index + ': ' + error);
        NetWebRtc.closePeer(id, instance, index, true);
      };
      if (bytes[0] === 100) {   // 'd'
        var offer = shortText === 'offer';
        var answer = shortText === 'answer';
        if ((offer && peer.offers) || (answer && !peer.offers) || (!offer && !answer)) return;
        peer.chain = peer.chain.then(function() {
          return pc.setRemoteDescription({type: shortText, sdp: longText});
        }).then(function() {
          if (!offer || peer.closed) return;
          return pc.createAnswer().then(function(description) {
            return pc.setLocalDescription(description);
          }).then(function() {
            if (peer.closed) return;
            NetWebRtc.emit(id, instance, NetWebRtc.EV_SIGNAL, 0, index,
                           NetWebRtc.blob('d', 'answer', pc.localDescription.sdp), false);
          });
        }).catch(fail);
      } else if (bytes[0] === 99) {   // 'c'
        var candidate = {candidate: longText, sdpMid: shortText !== '' ? shortText : null};
        if (shortText === '') candidate.sdpMLineIndex = 0;
        peer.chain = peer.chain.then(function() {
          if (!peer.closed) return pc.addIceCandidate(candidate);
        }).catch(function(error) {
          NetWebRtc.log('a candidate was not taken: ' + error);   // others may still work
        });
      }
    },

    sendPeer: function(instance, index, channel, at, size) {
      var slot = index * NetWebRtc.CHANNELS + channel;
      Atomics.sub(HEAPU32, (instance.queued >>> 2) + slot, size);
      var peer = instance.peers[index];
      if (!peer || !peer.connected || channel >= NetWebRtc.CHANNELS) return;
      var dc = peer.channels[channel];
      if (dc.readyState !== 'open') return;
      try {
        dc.send(HEAPU8.slice(at, at + size));
      } catch (e) {
        return;   // a full buffer on an unreliable channel: a lost packet
      }
      Atomics.store(HEAPU32, (instance.buffered >>> 2) + slot, dc.bufferedAmount >>> 0);
    },

    openSocket: function(id, ring, url) {
      var socket = {ring: ring, ws: null, pending: [], closed: false, reported: false};
      NetWebRtc.sockets[id] = socket;
      var closed = function() {
        if (socket.closed || socket.reported) return;
        socket.reported = true;
        NetWebRtc.emit(id, socket, NetWebRtc.EV_SOCKET_CLOSED, 0, 0, null, false);
      };
      try {
        socket.ws = new WebSocket(url, 'multitap-beacon.1');
      } catch (e) {
        NetWebRtc.log('signaling socket ' + url + ': ' + e);
        closed();
        return;
      }
      socket.ws.binaryType = 'arraybuffer';
      socket.ws.onopen = function() {
        if (!socket.closed) NetWebRtc.emit(id, socket, NetWebRtc.EV_SOCKET_OPEN, 0, 0, null, false);
      };
      socket.ws.onmessage = function(event) {
        if (socket.closed || !(event.data instanceof ArrayBuffer)) return;
        NetWebRtc.emit(id, socket, NetWebRtc.EV_SOCKET_MESSAGE, 0, 0, new Uint8Array(event.data), false);
      };
      socket.ws.onclose = closed;
      socket.ws.onerror = closed;
      NetWebRtc.startTimer();
    },

    closeSocket: function(id) {
      var socket = NetWebRtc.sockets[id];
      if (!socket) return;
      NetWebRtc.sockets[id] = null;
      socket.closed = true;
      if (socket.ws) {
        socket.ws.onopen = null;
        socket.ws.onmessage = null;
        socket.ws.onclose = null;
        socket.ws.onerror = null;
        try { socket.ws.close(); } catch (e) {}
      }
      Atomics.store(HEAPU32, (socket.ring >>> 2) + 4, 1);   // released: C++ may reuse it
    },

    command: function(kind, channel, owner, index, at, size) {
      var instance = NetWebRtc.instances[owner];
      switch (kind) {
      case NetWebRtc.CMD_INSTANCE_OPEN:
        NetWebRtc.instances[owner] = {
          ring: HEAPU32[at >>> 2],
          buffered: HEAPU32[(at + 4) >>> 2],
          queued: HEAPU32[(at + 8) >>> 2],
          stun: NetWebRtc.text(HEAPU8.slice(at + 12, at + size)),
          peers: [],
          pending: [],
        };
        NetWebRtc.startTimer();
        break;
      case NetWebRtc.CMD_INSTANCE_CLOSE:
        if (!instance) break;
        for (var i = 0; i < instance.peers.length; i++) NetWebRtc.closePeer(owner, instance, i, false);
        NetWebRtc.instances[owner] = null;
        Atomics.store(HEAPU32, (instance.ring >>> 2) + 4, 1);   // released
        break;
      case NetWebRtc.CMD_PEER_OPEN:
        if (instance) NetWebRtc.openPeer(owner, instance, index, channel === 1);
        break;
      case NetWebRtc.CMD_PEER_SIGNAL:
        if (instance) NetWebRtc.signalPeer(owner, instance, index, HEAPU8.slice(at, at + size));
        break;
      case NetWebRtc.CMD_PEER_SEND:
        if (instance) NetWebRtc.sendPeer(instance, index, channel, at, size);
        break;
      case NetWebRtc.CMD_PEER_CLOSE:
        if (!instance) break;
        if (instance.peers[index]) {
          NetWebRtc.closePeer(owner, instance, index, true);
        } else {
          // Already gone (it failed on its own and C++ hasn't read that yet):
          // that `disconnected` is on its way, nothing more to say.
        }
        break;
      case NetWebRtc.CMD_SOCKET_OPEN:
        NetWebRtc.openSocket(owner, HEAPU32[at >>> 2], NetWebRtc.text(HEAPU8.slice(at + 4, at + size)));
        break;
      case NetWebRtc.CMD_SOCKET_SEND:
        var socket = NetWebRtc.sockets[owner];
        if (socket && socket.ws && socket.ws.readyState === 1) socket.ws.send(HEAPU8.slice(at, at + size));
        break;
      case NetWebRtc.CMD_SOCKET_CLOSE:
        NetWebRtc.closeSocket(owner);
        break;
      }
    },
  },

  // Woken by C++ after it wrote commands (on the main thread: proxied, async).
  net_webrtc_kick__deps: ['$NetWebRtc'],
  net_webrtc_kick__proxy: 'async',
  net_webrtc_kick__sig: 'vpp',
  net_webrtc_kick: function(ring, kickPending) {
    // Cleared before reading: a command written after this is followed by
    // another kick.
    Atomics.store(HEAPU32, kickPending >>> 2, 0);
    var base = ring >>> 2;
    var size = HEAPU32[base + 2];
    var data = ring + NetWebRtc.DATA;
    for (;;) {
      var tail = Atomics.load(HEAPU32, base + 1);
      var head = Atomics.load(HEAPU32, base);
      if (head === tail) break;
      var position = tail & (size - 1);
      var at = data + position;
      var length = HEAPU32[at >>> 2];
      if (length === NetWebRtc.WRAP) {
        Atomics.store(HEAPU32, base + 1, (tail + size - position) >>> 0);
        continue;
      }
      NetWebRtc.command(HEAPU8[at + 4], HEAPU8[at + 5], HEAPU8[at + 6], HEAPU8[at + 7], at + 12,
                        HEAPU32[(at + 8) >>> 2]);
      Atomics.store(HEAPU32, base + 1, (tail + length) >>> 0);
    }
  },
};

addToLibrary(LibraryNetWebRtc);
