// index.js

import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// 1. JWT Creation
const jwtSecret = 'my_jwt_secret';
const payload = { userId: 123, role: 'student' };

// Generate JWT Token
const token = jwt.sign(payload, jwtSecret, { expiresIn: '1h' });
console.log('Original JWT:', token);

// 2. Encryption Setup (AES-256-CBC)
const encryptionKey = crypto.randomBytes(32); // 256-bit key
const iv = crypto.randomBytes(16); // 128-bit IV

// Encrypt the token
const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
let encrypted = cipher.update(token, 'utf8', 'hex');
encrypted += cipher.final('hex');
const encryptedToken = iv.toString('hex') + ':' + encrypted;
console.log('\nEncrypted JWT:', encryptedToken);

// 3. Decryption
const [ivHex, encryptedHex] = encryptedToken.split(':');
const ivBuffer = Buffer.from(ivHex, 'hex');
const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, ivBuffer);
let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
decrypted += decipher.final('utf8');
console.log('\nDecrypted JWT:', decrypted);

// 4. Verify JWT
try {
  const decoded = jwt.verify(decrypted, jwtSecret);
  console.log('\n✅ Decoded Payload:', decoded);
  console.log('✅ Success');
} catch (error) {
  console.error('\n❌ Token verification failed:', error.message);
}
