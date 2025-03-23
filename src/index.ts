import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";
import { Router } from 'itty-router';
import { verify, sign } from '@tsndr/cloudflare-worker-jwt';
import { compare, hash } from 'bcryptjs';

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

// Create router for API endpoints
const router = Router();

// Helper function to handle JWT authentication
const authenticateToken = async (request: Request, env: Env) => {
  const authHeader = request.headers.get('Authorization');
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return new Response(JSON.stringify({ message: 'No token provided' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  try {
    const isValid = await verify(token, env.JWT_SECRET || 'your-secret-key');
    if (!isValid) {
      throw new Error('Invalid token');
    }
    
    // Decode the token payload
    const tokenParts = token.split('.');
    const payload = JSON.parse(atob(tokenParts[1]));
    
    return payload;
  } catch (error) {
    return new Response(JSON.stringify({ message: 'Invalid token' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Register route (traditional JWT-based)
router.post('/api/register', async (request: Request, env: Env) => {
  try {
    const { username, password, email } = await request.json();
    
    // Create user in the database
    const userId = await getOrCreateUser(env, email, username);
    
    // Hash password and store it
    const hashedPassword = await hash(password, 10);
    
    // Store password in database
    await env.AUTH_DB.prepare(
      `UPDATE user SET password = ? WHERE id = ?`
    ).bind(hashedPassword, userId).run();
    
    // Generate JWT
    const token = await sign(
      { userId: userId, username }, 
      env.JWT_SECRET || 'your-secret-key', 
      { expiresIn: '1h' }
    );
    
    return new Response(JSON.stringify({
      message: 'User created successfully',
      token,
      redirectUrl: `http://your-frontend-app.com/login?token=${token}`
    }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ 
      message: 'Error creating user', 
      error: error.message 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// Login route (traditional JWT-based)
router.post('/api/login', async (request: Request, env: Env) => {
  try {
    const { username, password } = await request.json();
    
    // Find user
    const user = await env.AUTH_DB.prepare(
      `SELECT id, username, password FROM user WHERE username = ?`
    ).bind(username).first<{ id: string, username: string, password: string }>();
    
    if (!user) {
      return new Response(JSON.stringify({ message: 'Invalid credentials' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Verify password
    const isValidPassword = await compare(password, user.password);
    if (!isValidPassword) {
      return new Response(JSON.stringify({ message: 'Invalid credentials' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Generate JWT
    const token = await sign(
      { userId: user.id, username: user.username }, 
      env.JWT_SECRET || 'your-secret-key', 
      { expiresIn: '1h' }
    );
    
    return new Response(JSON.stringify({
      message: 'Login successful',
      token,
      redirectUrl: `http://your-frontend-app.com/dashboard?token=${token}`
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ 
      message: 'Error logging in', 
      error: error.message 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// Protected route example
router.get('/api/protected', async (request: Request, env: Env) => {
  const user = await authenticateToken(request, env);
  
  if (user instanceof Response) {
    return user; // Return the error response if authentication failed
  }
  
  return new Response(JSON.stringify({ 
    message: 'Protected data', 
    userId: user.userId,
    username: user.username
  }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  });
});

// 404 handler for API routes
router.all('/api/*', () => new Response('API Not Found', { status: 404 }));

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
    
    // Route API requests through our router
    if (url.pathname.startsWith('/api/')) {
      const response = await router.handle(request, env, ctx);
      const newResponse = new Response(response.body, response);
      newResponse.headers.set('Access-Control-Allow-Origin', '*');
      return newResponse;
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