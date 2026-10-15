const COOKIE_NAME = "__Host-admin_session";
const SESSION_SECONDS = 7 * 24 * 60 * 60;

function encodeBase64Url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function decodeBase64Url(value) {
  return Uint8Array.from(
    atob(value.replace(/-/g, "+").replace(/_/g, "/")),
    char => char.charCodeAt(0)
  );
}

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

  return encodeBase64Url(signature);
}

async function verifySession(request, env) {
  if (!env.SESSION_SECRET) return false;

  const cookies = request.headers.get("Cookie") || "";
  const item = cookies.split(";")
    .map(value => value.trim())
    .find(value => value.startsWith(COOKIE_NAME + "="));

  if (!item) return false;

  const parts = item.slice(COOKIE_NAME.length + 1).split(".");
  if (parts.length !== 2) return false;

  const [expiresText, signature] = parts;
  const expires = Number(expiresText);

  if (
    !Number.isSafeInteger(expires) ||
    expires <= Math.floor(Date.now() / 1000)
  ) {
    return false;
  }

  const expected = await sign(expiresText, env.SESSION_SECRET);

  try {
    const actualBytes = decodeBase64Url(signature);
    const expectedBytes = decodeBase64Url(expected);

    if (actualBytes.length !== expectedBytes.length) return false;

    let difference = 0;

    for (let i = 0; i < actualBytes.length; i++) {
      difference |= actualBytes[i] ^ expectedBytes[i];
    }

    return difference === 0;
  } catch {
    return false;
  }
}

export async function onRequest({ request, env }) {
  const method = request.method;

  // Check whether the current login session is valid.
  if (method === "GET") {
    const valid = await verifySession(request, env);

    return Response.json(
      { authenticated: valid },
      { status: 200 }
    );
  }

  // Log out by clearing the session cookie.
  if (method === "DELETE") {
    return Response.json(
      { success: true },
      {
        headers: {
          "Set-Cookie":
            `${COOKIE_NAME}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict`
        }
      }
    );
  }

  if (method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { Allow: "GET, POST, DELETE" }
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

    const expires =
      Math.floor(Date.now() / 1000) + SESSION_SECONDS;

    const signature = await sign(
      String(expires),
      env.SESSION_SECRET
    );

    const token = `${expires}.${signature}`;

    return Response.json(
      { success: true, expires },
      {
        headers: {
          "Set-Cookie":
            `${COOKIE_NAME}=${token}; Max-Age=${SESSION_SECONDS}; Path=/; Secure; HttpOnly; SameSite=Strict`
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
