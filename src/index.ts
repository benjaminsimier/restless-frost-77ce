import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

// Define environment interface
interface Env {
  AUTH_STORAGE: KVNamespace;
  AUTH_DB: D1Database;
  JWT_SECRET: string;
}

// Create subjects for OpenAuth
const subjects = createSubjects({
  user: object({
    id: string(),
    username: string(),
  }),
});

// Helper function to handle JWT authentication using Web Crypto API
async function verifyJWT(token: string, secret: string): Promise<any> {
  try {
    // Split the JWT into parts
    const [headerB64, payloadB64, signatureB64] = token.split('.');
    
    // Decode the payload
    const payload = JSON.parse(atob(payloadB64));
    
    // Check token expiration
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      throw new Error('Token expired');
    }
    
    // For production, you should implement proper JWT verification with Web Crypto API
    // This is a simplified check using the secret as a basic verification step
    const data = `${headerB64}.${payloadB64}`;
    const textEncoder = new TextEncoder();
    const keyData = textEncoder.encode(secret);
    const messageData = textEncoder.encode(data);
    
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const signature = base64UrlToArrayBuffer(signatureB64);
    const isValid = await crypto.subtle.verify(
      'HMAC',
      key,
      signature,
      messageData
    );
    
    if (!isValid) {
      throw new Error('Invalid signature');
    }
    
    return payload;
  } catch (error) {
    throw new Error(`JWT verification failed: ${error.message}`);
  }
}

// Helper function to create JWT using Web Crypto API
async function createJWT(payload: any, secret: string, expiresIn: string = '1h'): Promise<string> {
  // Create header
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };
  
  // Add expiration to payload
  const now = Math.floor(Date.now() / 1000);
  let expiry = now;
  if (expiresIn.endsWith('h')) {
    expiry += parseInt(expiresIn.slice(0, -1)) * 3600;
  } else if (expiresIn.endsWith('m')) {
    expiry += parseInt(expiresIn.slice(0, -1)) * 60;
  } else if (expiresIn.endsWith('d')) {
    expiry += parseInt(expiresIn.slice(0, -1)) * 86400;
  }
  
  const fullPayload = {
    ...payload,
    iat: now,
    exp: expiry
  };
  
  // Encode header and payload to base64
  const headerB64 = btoa(JSON.stringify(header))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  
  const payloadB64 = btoa(JSON.stringify(fullPayload))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  
  // Create signature
  const textEncoder = new TextEncoder();
  const keyData = textEncoder.encode(secret);
  const messageData = textEncoder.encode(`${headerB64}.${payloadB64}`);
  
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    messageData
  );
  
  // Convert signature to base64 and create JWT
  const signatureB64 = arrayBufferToBase64Url(signature);
  
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

// Helper function for hashing passwords using Web Crypto API
async function hashPassword(password: string): Promise<string> {
  // Generate a random salt
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltBase64 = arrayBufferToBase64Url(salt);
  
  // Encode password
  const encoder = new TextEncoder();
  const passwordData = encoder.encode(password);
  
  // Combine salt and password
  const combined = new Uint8Array(salt.length + passwordData.length);
  combined.set(salt);
  combined.set(passwordData, salt.length);
  
  // Hash the combination
  const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
  const hashBase64 = arrayBufferToBase64Url(hashBuffer);
  
  // Return salt and hash, separated by a dot
  return `${saltBase64}.${hashBase64}`;
}

// Helper function to verify password
async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  const [saltBase64, hashBase64] = storedHash.split('.');
  const salt = base64UrlToArrayBuffer(saltBase64);
  
  // Encode password
  const encoder = new TextEncoder();
  const passwordData = encoder.encode(password);
  
  // Combine salt and password
  const combined = new Uint8Array(salt.length + passwordData.length);
  combined.set(salt);
  combined.set(passwordData, salt.length);
  
  // Hash the combination
  const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
  const newHashBase64 = arrayBufferToBase64Url(hashBuffer);
  
  // Compare the hashes
  return hashBase64 === newHashBase64;
}

// Utility functions for base64 conversion
function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlToArrayBuffer(base64Url: string): ArrayBuffer {
  // Convert base64url to base64
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  // Pad with '=' if needed
  const padded = base64.padEnd(base64.length + (4 - (base64.length % 4)) % 4, '=');
  // Decode to binary
  const binary = atob(padded);
  // Convert to ArrayBuffer
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    buffer[i] = binary.charCodeAt(i);
  }
  return buffer.buffer;
}

// Main worker event handler
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);
    
    // Handle CORS for API requests
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Max-Age': '86400'
        }
      });
    }
    
    // Route API requests
    if (url.pathname.startsWith('/api/')) {
      // Process API requests
      if (url.pathname === '/api/register' && request.method === 'POST') {
        try {
          const { username, password, email } = await request.json();
          
          // Create user in the database
          const userId = await getOrCreateUser(env, email, username);
          
          // Hash password and store it
          const hashedPassword = await hashPassword(password);
          
          // Store password in database
          await env.AUTH_DB.prepare(
            `UPDATE user SET password = ? WHERE id = ?`
          ).bind(hashedPassword, userId).run();
          
          // Generate JWT
          const token = await createJWT(
            { userId: userId, username }, 
            env.JWT_SECRET || 'your-secret-key', 
            '1h'
          );
          
          return new Response(JSON.stringify({
            message: 'User created successfully',
            token,
            redirectUrl: `http://your-frontend-app.com/login?token=${token}`
          }), {
            status: 201,
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        } catch (error) {
          return new Response(JSON.stringify({ 
            message: 'Error creating user', 
            error: error.message 
          }), {
            status: 500,
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
      } 
      else if (url.pathname === '/api/login' && request.method === 'POST') {
        try {
          const { username, password } = await request.json();
          
          // Find user
          const user = await env.AUTH_DB.prepare(
            `SELECT id, username, password FROM user WHERE username = ?`
          ).bind(username).first<{ id: string, username: string, password: string }>();
          
          if (!user) {
            return new Response(JSON.stringify({ message: 'Invalid credentials' }), {
              status: 401,
              headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
              }
            });
          }
          
          // Verify password
          const isValidPassword = await verifyPassword(password, user.password);
          if (!isValidPassword) {
            return new Response(JSON.stringify({ message: 'Invalid credentials' }), {
              status: 401,
              headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
              }
            });
          }
          
          // Generate JWT
          const token = await createJWT(
            { userId: user.id, username: user.username }, 
            env.JWT_SECRET || 'your-secret-key', 
            '1h'
          );
          
          return new Response(JSON.stringify({
            message: 'Login successful',
            token,
            redirectUrl: `http://your-frontend-app.com/dashboard?token=${token}`
          }), {
            status: 200,
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        } catch (error) {
          return new Response(JSON.stringify({ 
            message: 'Error logging in', 
            error: error.message 
          }), {
            status: 500,
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
      }
      else if (url.pathname === '/api/protected' && request.method === 'GET') {
        try {
          // Get token from Authorization header
          const authHeader = request.headers.get('Authorization');
          const token = authHeader && authHeader.split(' ')[1];
          
          if (!token) {
            return new Response(JSON.stringify({ message: 'No token provided' }), {
              status: 401,
              headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
              }
            });
          }
          
          // Verify token
          const payload = await verifyJWT(token, env.JWT_SECRET || 'your-secret-key');
          
          return new Response(JSON.stringify({ 
            message: 'Protected data', 
            userId: payload.userId,
            username: payload.username
          }), {
            status: 200,
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        } catch (error) {
          return new Response(JSON.stringify({ message: 'Invalid token' }), {
            status: 403,
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
      }
      
      // Default 404 for API
      return new Response(JSON.stringify({ message: 'API Not Found' }), {
        status: 404,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }
    
    // OpenAuth flow for web-based authentication
    // Demo redirect to start the OpenAuth flow
    if (url.pathname === "/") {
      url.searchParams.set("redirect_uri", url.origin + "/callback");
      url.searchParams.set("client_id", "your-client-id");
      url.searchParams.set("response_type", "code");
      url.pathname = "/authorize";
      return Response.redirect(url.toString());
    } else if (url.pathname === "/callback") {
      const redirectUri = url.searchParams.get('redirect_uri');
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      
      if (redirectUri) {
        const redirectUrl = new URL(redirectUri);
        redirectUrl.searchParams.set('code', code);
        if (state) redirectUrl.searchParams.set('state', state);
        return Response.redirect(redirectUrl.toString(), 302);
      }
      
      // Fall back to JSON response if no redirect_uri
      return Response.json({
        message: "OAuth flow complete!",
        params: Object.fromEntries(url.searchParams.entries()),
      });
    }

    // The OpenAuth server code for handling authentication pages
    return issuer({
      storage: CloudflareStorage({
        namespace: env.AUTH_STORAGE,
      }),
      subjects,
      providers: {
        password: PasswordProvider(
          PasswordUI({
            // eslint-disable-next-line @typescript-eslint/require-await
            sendCode: async (email, code) => {
              // This is where you would email the verification code to the user
              console.log(`Sending code ${code} to ${email}`);
            },
            copy: {
              input_code: "Code (check Worker logs)",
            },
          }),
        ),
      },
      theme: {
        title: "myAuth",
        primary: "#0051c3",
        favicon: "https://workers.cloudflare.com/favicon.ico",
        logo: {
          dark: "https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/db1e5c92-d3a6-4ea9-3e72-155844211f00/public",
          light: "https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/fa5a3023-7da9-466b-98a7-4ce01ee6c700/public",
        },
      },
      success: async (ctx, value) => {
        const userId = await getOrCreateUser(env, value.email);
        return ctx.subject("user", {
          id: userId,
          username: value.email.split('@')[0], // Default username from email
        });
      },
    }).fetch(request, env, ctx);
  },
};

async function getOrCreateUser(env: Env, email: string, username?: string): Promise<string> {
  // Create or update user based on email
  const result = await env.AUTH_DB.prepare(
    `
    INSERT INTO user (email, username)
    VALUES (?, ?)
    ON CONFLICT (email) DO UPDATE SET username = COALESCE(excluded.username, user.username)
    RETURNING id;
    `
  )
    .bind(email, username || email.split('@')[0])
    .first<{ id: string }>();
    
  if (!result) {
    throw new Error(`Unable to process user: ${email}`);
  }
  console.log(`Found or created user ${result.id} with email ${email}`);
  return result.id;
}