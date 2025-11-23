import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API = 'http://localhost:3000';

interface StoredKeyPair {
  publicKey: string;
  privateKey: string;
}

function App() {
  const [view, setView] = useState<'login' | 'register' | 'chat'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [userId, setUserId] = useState<number | null>(null);
  const [userKeyPair, setUserKeyPair] = useState<CryptoKeyPair | null>(null);

  const [recipientId, setRecipientId] = useState('');
  const [message, setMessage] = useState('');
  const [contactUsername, setContactUsername] = useState('');
  const [contactResult, setContactResult] = useState<string>('');

  const safeBase64ToUint8 = (b64: string) =>
    Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const deriveKeyFromPassword = async (password: string) => {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode('chat-seguro-salt'),
        iterations: 100000,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  };

  const encryptPrivateKey = async (privateKeyJwk: JsonWebKey, password: string) => {
    const aesKey = await deriveKeyFromPassword(password);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      new TextEncoder().encode(JSON.stringify(privateKeyJwk))
    );

    return {
      data: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
      iv: btoa(String.fromCharCode(...iv)),
    };
  };

  const decryptPrivateKey = async (encryptedData: string, iv: string, password: string) => {
    const aesKey = await deriveKeyFromPassword(password);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: safeBase64ToUint8(iv) },
      aesKey,
      safeBase64ToUint8(encryptedData)
    );

    return JSON.parse(new TextDecoder().decode(decrypted));
  };


  const loadKeys = async (): Promise<CryptoKeyPair | null> => {
    const saved = localStorage.getItem('userKeyPair');
    if (!saved) {
      return null;
    }
    try {
      const stored: StoredKeyPair = JSON.parse(saved);

      const publicKey = await crypto.subtle.importKey(
        'jwk',
        JSON.parse(stored.publicKey),
        { name: 'RSA-PSS', hash: 'SHA-256' },
        true,
        ['verify']
      );

      const privateKey = await crypto.subtle.importKey(
        'jwk',
        JSON.parse(stored.privateKey),
        { name: 'RSA-PSS', hash: 'SHA-256' },
        true,
        ['sign']
      );

      const kp = { publicKey, privateKey };
      setUserKeyPair(kp);
      return kp;
    } catch (e) {
      console.error('Error cargando claves:', e);
      localStorage.removeItem('userKeyPair');
      return null;
    }
  };

  useEffect(() => {
    const init = async () => {
      const savedToken = localStorage.getItem('token');
      const savedUserId = localStorage.getItem('userId');
      const savedUsername = localStorage.getItem('username');

      if (savedToken && savedUserId && savedUsername) {
        setToken(savedToken);
        setUserId(Number(savedUserId));
        setUsername(savedUsername);
        setView('chat');
        await loadKeys();
      }
    };
    init();
  }, []);

  const createEnvelope = async (payload: any) => {
    const serverRes = await axios.get(`${API}/auth/public-key`).catch(e => {
      console.error('createEnvelope: error obteniendo public-key del servidor', e?.response?.status, e?.response?.data);
      throw new Error('No se pudo obtener la clave pública del servidor');
    });
    const serverPubPem = serverRes?.data?.publicKey;
    if (!serverPubPem) throw new Error('Clave pública del servidor no disponible');

    const aesKey = await crypto.subtle.generateKey(
      { name: 'AES-CBC', length: 256 },
      true,
      ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const data = new TextEncoder().encode(JSON.stringify(payload));
    const encryptedData = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, data);
    const rawKey = await crypto.subtle.exportKey('raw', aesKey);

    const cleanPem = serverPubPem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n/g, '').trim();
    const serverPubKey = await crypto.subtle.importKey(
      'spki',
      safeBase64ToUint8(cleanPem),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );

    const encryptedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, serverPubKey, rawKey);

    return {
      encryptedData: btoa(String.fromCharCode(...new Uint8Array(encryptedData))),
      encryptedKey: btoa(String.fromCharCode(...new Uint8Array(encryptedKey))),
      iv: btoa(String.fromCharCode(...iv)),
    };
  };

  const register = async () => {
    try {
      const keyPair = await crypto.subtle.generateKey(
        { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true,
        ['sign', 'verify']
      );

      const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
      const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
      const stored: StoredKeyPair = {
        publicKey: JSON.stringify(publicKeyJwk),
        privateKey: JSON.stringify(privateKeyJwk),
      };
      localStorage.setItem('userKeyPair', JSON.stringify(stored));
      setUserKeyPair(keyPair);

      const publicKeyExported = await crypto.subtle.exportKey('spki', keyPair.publicKey);
      const publicKeyPem = btoa(String.fromCharCode(...new Uint8Array(publicKeyExported)));
      const encryptedPrivateKey = await encryptPrivateKey(privateKeyJwk, password);

      const payload = {
        username,
        password,
        email: `${username}@example.com`,
        publicKey: publicKeyPem,
        encryptedPrivateKey: JSON.stringify(encryptedPrivateKey),
      };

      const envelope = await createEnvelope(payload);

      const res = await axios.post(`${API}/auth/register`, envelope);
      alert('Registro exitoso. Tu clave privada está cifrada y guardada de forma segura.');
      setView('login');
    } catch (error: any) {
      console.error('Error en registro:', error);
      localStorage.removeItem('userKeyPair');
      setUserKeyPair(null);
      alert('Error en registro: ' + (error.response?.data?.message || error.message));
    }
  };

  const login = async () => {
    try {
      const envelope = await createEnvelope({ username, password });
      const res = await axios.post(`${API}/auth/login`, envelope);

      const newToken = res.data.token;
      const newUserId = res.data.userId;
      const encryptedPrivateKey = res.data.encryptedPrivateKey;

      localStorage.setItem('token', newToken);
      localStorage.setItem('userId', String(newUserId));
      localStorage.setItem('username', username);

      setToken(newToken);
      setUserId(newUserId);
      if (encryptedPrivateKey) {
        try {
          const encrypted = JSON.parse(encryptedPrivateKey);
          const privateKeyJwk = await decryptPrivateKey(encrypted.data, encrypted.iv, password);
          const cleanPublicKey = res.data.publicKey.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n/g, '').trim();
          const publicKeyBuffer = safeBase64ToUint8(cleanPublicKey);
          const publicKeyCrypto = await crypto.subtle.importKey(
            'spki',
            publicKeyBuffer,
            { name: 'RSA-PSS', hash: 'SHA-256' },
            true,
            ['verify']
          );
          const publicKeyJwk = await crypto.subtle.exportKey('jwk', publicKeyCrypto);

          const stored: StoredKeyPair = {
            publicKey: JSON.stringify(publicKeyJwk),
            privateKey: JSON.stringify(privateKeyJwk),
          };
          localStorage.setItem('userKeyPair', JSON.stringify(stored));

          await loadKeys();
        } catch (e) {
          console.error('Error descifrando privateKey:', e);
          alert('Error al recuperar claves. Verifica tu contraseña o intenta registrarte de nuevo.');
        }
      } else {
        alert('Este usuario no tiene claves guardadas. Necesitas registrarte de nuevo.');
      }

      setView('chat');
      alert(`Bienvenido, ${username}`);
    } catch (error: any) {
      console.error('Error en login:', error?.response?.status, error?.response?.data);
      alert('Error en login: ' + (error.response?.data?.message || error.message));
    }
  };

  const createMessageEnvelope = async (message: string, recipientId: number) => {
    const recipientRes = await axios.get(`${API}/users/public-key-by-id/${recipientId}`).catch(e => {
      console.error('createMessageEnvelope: error fetching public key by id', e?.response?.status, e?.response?.data);
      return null;
    });
    const recipientPubPem = recipientRes?.data;
    if (!recipientPubPem) throw new Error('Clave pública del destinatario no disponible');

    const aesKey = await crypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(16));

    const data = new TextEncoder().encode(message);
    const encryptedData = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, data);
    const rawKey = await crypto.subtle.exportKey('raw', aesKey);

    const cleanPem = recipientPubPem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n/g, '').trim();
    const recipientPubKey = await crypto.subtle.importKey(
      'spki',
      safeBase64ToUint8(cleanPem),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );

    const encryptedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, recipientPubKey, rawKey);

    let signature = '';
    if (userKeyPair?.privateKey) {
      const messageBytes = new TextEncoder().encode(message);
      const signatureArray = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, userKeyPair.privateKey, messageBytes);
      signature = btoa(String.fromCharCode(...new Uint8Array(signatureArray)));
    }

    return {
      encryptedData: btoa(String.fromCharCode(...new Uint8Array(encryptedData))),
      encryptedKey: btoa(String.fromCharCode(...new Uint8Array(encryptedKey))),
      iv: btoa(String.fromCharCode(...iv)),
      signature,
    };
  };

  const sendMessage = async () => {
    if (!recipientId || !message) return alert('Completa todos los campos');

    try {
      const envelope = await createMessageEnvelope(message, Number(recipientId));

      await axios.post(
        `${API}/messages/send`,
        {
          recipientId: Number(recipientId),
          encryptedData: envelope.encryptedData,
          encryptedKey: envelope.encryptedKey,
          iv: envelope.iv,
          signature: envelope.signature,
          originalMessage: message,
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      alert('Mensaje enviado');
      setMessage('');
    } catch (error: any) {
      console.error('Error enviando mensaje:', error);
      alert('Error: ' + (error.response?.data?.message || error.message));
    }
  };

  const addContactWithVerification = async () => {
    if (!contactUsername.trim()) return alert('Escribe un username');

    let kp = userKeyPair;
    if (!kp?.privateKey) {
      kp = await loadKeys();
    }
    if (!kp?.privateKey) {
      console.error('userKeyPair after loadKeys:', kp, 'localStorage:', localStorage.getItem('userKeyPair'));
      return alert('No tienes clave privada. Intenta cerrar sesión y volver a entrar.');
    }

    const challenge = `ADD_CONTACT_${contactUsername}_${Date.now()}`;

    try {
      const signatureArray = await crypto.subtle.sign(
        { name: 'RSA-PSS', saltLength: 32 },
        kp.privateKey,
        new TextEncoder().encode(challenge)
      );
      const signature = btoa(String.fromCharCode(...new Uint8Array(signatureArray)));

      const res = await axios.post(
        `${API}/users/add-contact/${contactUsername}`,
        { challenge, signature },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setContactResult(`Contacto agregado: ${contactUsername}`);
      setContactUsername('');
    } catch (err: any) {
      console.error('Error addContact:', err?.response?.status, err?.response?.data);
      const msg = err.response?.data?.message || err.message || 'Error desconocido';
      setContactResult(`Error: ${msg}`);
    }
  };

  const logout = () => {
    localStorage.clear();
    setToken('');
    setUserId(null);
    setUsername('');
    setPassword('');
    setUserKeyPair(null);
    setView('login');
  };

  return (
    <div style={{ padding: 40, fontFamily: 'Arial', maxWidth: 600, margin: '0 auto' }}>
      <h1>Chat Seguro</h1>

      {view === 'register' && (
        <div>
          <h2>Registro</h2>
          <input
            placeholder="Usuario"
            value={username}
            onChange={e => setUsername(e.target.value)}
            style={{ width: '100%', padding: 10, margin: '5px 0', boxSizing: 'border-box' }}
          />
          <input
            type="password"
            placeholder="Contraseña"
            value={password}
            onChange={e => setPassword(e.target.value)}
            style={{ width: '100%', padding: 10, margin: '5px 0', boxSizing: 'border-box' }}
          />
          <button onClick={register} style={{ padding: 10, margin: 5, width: '100%' }}>
            Registrarse
          </button>
          <button onClick={() => setView('login')} style={{ padding: 10, margin: 5, width: '100%' }}>
            Volver
          </button>
        </div>
      )}

      {view === 'login' && (
        <div>
          <h2>Login</h2>
          <input
            placeholder="Usuario"
            value={username}
            onChange={e => setUsername(e.target.value)}
            style={{ width: '100%', padding: 10, margin: '5px 0', boxSizing: 'border-box' }}
          />
          <input
            type="password"
            placeholder="Contraseña"
            value={password}
            onChange={e => setPassword(e.target.value)}
            style={{ width: '100%', padding: 10, margin: '5px 0', boxSizing: 'border-box' }}
          />
          <button onClick={login} style={{ padding: 10, margin: 5, width: '100%' }}>
            Iniciar Sesión
          </button>
          <button onClick={() => setView('register')} style={{ padding: 10, margin: 5, width: '100%' }}>
            Registrarse
          </button>
        </div>
      )}

      {view === 'chat' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 20 }}>
            <h2>Hola, {username}</h2>
            <button onClick={logout} style={{ padding: 10 }}>Cerrar Sesión</button>
          </div>

          <div style={{ marginBottom: 20 }}>
            <h3>Agregar Contacto</h3>
            <input
              placeholder="Username del contacto"
              value={contactUsername}
              onChange={e => setContactUsername(e.target.value)}
              style={{ width: '100%', padding: 10, margin: '5px 0', boxSizing: 'border-box' }}
            />
            <button onClick={addContactWithVerification} style={{ padding: 10, width: '100%' }}>Agregar</button>
            {contactResult && <p>{contactResult}</p>}
          </div>

          <div>
            <h3>Enviar Mensaje</h3>
            <input
              placeholder="ID del destinatario"
              value={recipientId}
              onChange={e => setRecipientId(e.target.value)}
              style={{ width: '100%', padding: 10, margin: '5px 0', boxSizing: 'border-box' }}
            />
            <textarea
              placeholder="Mensaje"
              value={message}
              onChange={e => setMessage(e.target.value)}
              style={{ width: '100%', height: 100, padding: 10, margin: '5px 0', boxSizing: 'border-box' }}
            />
            <button onClick={sendMessage} style={{ padding: 10, width: '100%' }}>Enviar</button>
          </div>
        </div>
      )}
    </div>
  );
}
export default App;