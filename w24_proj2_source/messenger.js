'use strict';

/** ******* Imports ********/

const {
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr,
} = require('./lib');

const { subtle } = require('node:crypto').webcrypto;

/**
 * Chuyển đổi một CryptoKey (public key) thành chuỗi JSON.
 */
async function egPubKeyToJSONString(key) {
  const jwk = await cryptoKeyToJSON(key);
  return JSON.stringify(jwk);
}

/**
 * Chuyển đổi một chuỗi JSON (JWK) thành CryptoKey (public key).
 */
async function jwkStringToEGPubKey(jwkString) {
  const jwk = JSON.parse(jwkString);
  return await subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-384' }, true, []);
}

/**
 * So sánh 2 public key (dạng chuỗi JWK)
 */
async function pubKeysEqual(receivedPubKeyStr, currentPubKey) {
  const currentPubKeyStr = await egPubKeyToJSONString(currentPubKey);
  return receivedPubKeyStr === currentPubKeyStr;
}

class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    this.caPublicKey = certAuthorityPublicKey;
    this.govPublicKey = govPublicKey;
    this.conns = {};
    this.certs = {};
    this.EGKeyPair = {};
    this.username = '';
  }

  async generateCertificate(username) {
    this.username = username;
    this.EGKeyPair = await generateEG();
    const egPubKeyJwk = await cryptoKeyToJSON(this.EGKeyPair.pub);
    return { username, pubKey: egPubKeyJwk };
  }

  async receiveCertificate(certificate, signature) {
    const certString = JSON.stringify(certificate);
    const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature);
    if (!isValid) throw new Error('Certificate signature verification failed.');

    const theirEGPubKey = await jwkStringToEGPubKey(JSON.stringify(certificate.pubKey));
    this.certs[certificate.username] = {
      pubKey: theirEGPubKey,
      username: certificate.username,
    };
  }

  async _initDHState(name) {
    const theirCert = this.certs[name];
    if (!theirCert) throw new Error(`Certificate for ${name} not found.`);

    const theirLongTermPubKey = theirCert.pubKey;
    const dhInit = await computeDH(this.EGKeyPair.sec, theirLongTermPubKey);
    const [rk_init] = await HKDF(dhInit, dhInit, 'initial-key-derivation');

    this.conns[name] = {
      rootKey: rk_init,
      sendChainKey: null,
      recvChainKey: null,
      myEphKeyPair: this.EGKeyPair,
      theirEphPubKey: theirLongTermPubKey,
      sendCount: 0,
      recvCount: 0,
      pendingRecvKeys: new Map(), // Map<"PubKeyStr-Count", CryptoKey>
      sendingRatchetNeeded: true,
      prevChainLength: 0, // Số lượng tin nhắn của chuỗi gửi trước đó
    };
  }

  async _performDHRatchet(name, theirPubKeyForDH, myNewKeyPair, isSending) {
    const conn = this.conns[name];

    let dhOut;
    if (isSending) {
      dhOut = await computeDH(myNewKeyPair.sec, conn.theirEphPubKey);
    } else {
      dhOut = await computeDH(conn.myEphKeyPair.sec, theirPubKeyForDH);
    }

    const [newRK, newCK] = await HKDF(dhOut, conn.rootKey, 'ratchet-step');
    conn.rootKey = newRK;

    if (isSending) {
      conn.myEphKeyPair = myNewKeyPair;
      conn.sendChainKey = newCK;
      // Lưu lại độ dài chuỗi cũ để gửi trong header (pn)
      conn.prevChainLength = conn.sendCount;
      conn.sendCount = 0;
    } else {
      conn.theirEphPubKey = theirPubKeyForDH;
      conn.recvChainKey = newCK;
      conn.recvCount = 0;
    }
  }

  async _deriveNextKeys(chainKey) {
    const messageKey = await HMACtoAESKey(chainKey, 'message-key');
    const nextChainKey = await HMACtoHMACKey(chainKey, 'next-chain-key');
    return [messageKey, nextChainKey];
  }

  async sendMessage(name, plaintext) {
    if (!this.conns[name]) await this._initDHState(name);
    const conn = this.conns[name];

    if (conn.sendingRatchetNeeded) {
      const myNewEph = await generateEG();
      await this._performDHRatchet(name, null, myNewEph, true);
      conn.sendingRatchetNeeded = false;
    }

    const senderPubKeyStr = await egPubKeyToJSONString(conn.myEphKeyPair.pub);
    const [msgKey, nextChainKey] = await this._deriveNextKeys(conn.sendChainKey);
    conn.sendChainKey = nextChainKey;
    conn.sendCount++;

    // Gov Encryption
    const vGov = this.EGKeyPair.pub;
    const dhGov = await computeDH(this.EGKeyPair.sec, this.govPublicKey);
    const govKey = await HMACtoAESKey(dhGov, govEncryptionDataStr);
    const ivGov = genRandomSalt(12);
    const msgKeyBuffer = await subtle.exportKey('raw', msgKey);
    const cGov = await encryptWithGCM(govKey, msgKeyBuffer, ivGov);

    const ivPeer = genRandomSalt(12);

    const header = {
      sender: this.username,
      receiver: name,
      count: conn.sendCount,
      prevCount: conn.prevChainLength, // Gửi kèm pn
      pubKey: senderPubKeyStr,
      vGov: vGov,
      ivGov: ivGov,
      cGov: cGov,
      receiverIV: ivPeer,
    };

    const ciphertext = await encryptWithGCM(msgKey, plaintext, ivPeer, JSON.stringify(header));
    return [header, ciphertext];
  }

  async receiveMessage(name, [header, ciphertext]) {
    if (!this.conns[name]) await this._initDHState(name);
    const conn = this.conns[name];

    if (header.receiver !== this.username || header.sender !== name) {
      throw new Error('Message is not intended for this user.');
    }

    // --- BƯỚC 1: Kiểm tra xem khóa có trong pendingRecvKeys không ---
    // Key của map là sự kết hợp của PubKey và Count để đảm bảo duy nhất
    const mapKey = `${header.pubKey}-${header.count}`;
    let msgKey;

    if (conn.pendingRecvKeys.has(mapKey)) {
      msgKey = conn.pendingRecvKeys.get(mapKey);
      conn.pendingRecvKeys.delete(mapKey);
    } else {
      // Nếu không tìm thấy, tiếp tục xử lý Ratchet hoặc Normal chain
      const receivedPubKeyStr = header.pubKey;
      const theirNewPubKey = await jwkStringToEGPubKey(receivedPubKeyStr);
      const DH_STEP_TAKEN = !(await pubKeysEqual(receivedPubKeyStr, conn.theirEphPubKey));

      if (DH_STEP_TAKEN) {
        // --- BƯỚC 2: DH Ratchet Triggered ---
        // Tính toán các khóa còn thiếu của chuỗi CŨ (dựa vào header.prevCount)
        if (conn.recvChainKey) {
          const prevChainMax = header.prevCount || 0;
          const oldPubKeyStr = await egPubKeyToJSONString(conn.theirEphPubKey);

          while (conn.recvCount < prevChainMax) {
            let k, nextCk;
            [k, nextCk] = await this._deriveNextKeys(conn.recvChainKey);
            conn.recvChainKey = nextCk;
            conn.recvCount++;
            // Lưu vào map với PubKey CŨ
            conn.pendingRecvKeys.set(`${oldPubKeyStr}-${conn.recvCount}`, k);
          }
        }

        // Thực hiện Ratchet sang chuỗi mới
        await this._performDHRatchet(name, theirNewPubKey, null, false);
        conn.sendingRatchetNeeded = true;
      }

      // --- BƯỚC 3: Xử lý tin nhắn trong chuỗi HIỆN TẠI (Chuỗi mới hoặc chuỗi cũ tiếp diễn) ---
      // Tính toán các khóa bị nhảy cóc trong chuỗi HIỆN TẠI
      const currentPubKeyStr = header.pubKey;
      while (conn.recvCount + 1 < header.count) {
        let k, nextCk;
        [k, nextCk] = await this._deriveNextKeys(conn.recvChainKey);
        conn.recvChainKey = nextCk;
        conn.recvCount++;
        conn.pendingRecvKeys.set(`${currentPubKeyStr}-${conn.recvCount}`, k);
      }

      // Lấy khóa cho tin nhắn hiện tại
      if (header.count === conn.recvCount + 1) {
        let nextCk;
        [msgKey, nextCk] = await this._deriveNextKeys(conn.recvChainKey);
        conn.recvChainKey = nextCk;
        conn.recvCount++;
      } else {
        // Nếu không tìm thấy key và count không khớp, có thể là replay hoặc lỗi
        throw new Error('Message replay or out of sequence.');
      }
    }

    try {
      const plaintextBuffer = await decryptWithGCM(
        msgKey,
        ciphertext,
        header.receiverIV,
        JSON.stringify(header)
      );
      return bufferToString(plaintextBuffer);
    } catch (e) {
      throw new Error('Decryption failed: possible message tampering or incorrect key.');
    }
  }
}

module.exports = {
  MessengerClient,
};
