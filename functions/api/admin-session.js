const COOKIE_NAME = "__Host-admin_session";
const SESSION_SECONDS = 7 * 24 * 60 * 60;

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  );

  return btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export async function onRequest({ request, env }) {
  if (request.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { Allow: "POST" }
    });
  }

  if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) {
    return Response.json(
      { error: "Admin session is not configured." },
      { status: 500 }
    );
  }

  try {
    const body = await request.json();

    if (
      typeof body.password !== "string" ||
      body.password !== env.ADMIN_PASSWORD
    ) {
      return Response.json(
        { error: "Incorrect password." },
        { status: 401 }
      );
    }

    const expires = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
    const payload = `${expires}`;
    const signature = await sign(payload, env.SESSION_SECRET);
    const cookieValue = `${payload}.${signature}`;

    return Response.json(
      { success: true, expires },
      {
        headers: {
          "Set-Cookie":
            `${COOKIE_NAME}=${cookieValue}; Max-Age=${SESSION_SECONDS}; Path=/; Secure; HttpOnly; SameSite=Strict`
        }
      }
    );
  } catch {
    return Response.json(
      { error: "Invalid request." },
      { status: 400 }
    );
  }
      }
