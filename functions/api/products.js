 const COOKIE_NAME = "__Host-admin_session";

function decodeBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(
    atob(base64),
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

  return btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function validSession(request, env) {
  if (!env.SESSION_SECRET) return false;

  const cookieHeader = request.headers.get("Cookie") || "";
  const cookie = cookieHeader
    .split(";")
    .map(item => item.trim())
    .find(item => item.startsWith(COOKIE_NAME + "="));

  if (!cookie) return false;

  const token = cookie.slice(COOKIE_NAME.length + 1);
  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const [expiresText, signature] = parts;
  const expires = Number(expiresText);

  if (!Number.isSafeInteger(expires) ||
      expires <= Math.floor(Date.now() / 1000)) {
    return false;
  }

  const expected = await sign(expiresText, env.SESSION_SECRET);

  try {
    const a = decodeBase64Url(signature);
    const b = decodeBase64Url(expected);

    if (a.length !== b.length) return false;

    let difference = 0;
    for (let i = 0; i < a.length; i++) {
      difference |= a[i] ^ b[i];
    }

    return difference === 0;
  } catch {
    return false;
  }
}

export async function onRequest({ request, env }) {
  const method = request.method;

  if (method === "GET") {
    try {
      const { results } = await env.DB
        .prepare("SELECT * FROM products ORDER BY id DESC")
        .all();

      return Response.json(results);
    } catch {
      return Response.json(
        { error: "Could not load products." },
        { status: 500 }
      );
    }
  }

  if (!["POST", "PUT", "DELETE"].includes(method)) {
    return new Response("Method not allowed", {
      status: 405,
      headers: { Allow: "GET, POST, PUT, DELETE" }
    });
  }

  if (!(await validSession(request, env))) {
    return Response.json(
      { error: "Your login session expired. Please log in again." },
      { status: 401 }
    );
  }

  if (method === "DELETE") {
    const id = Number(new URL(request.url).searchParams.get("id"));

    if (!Number.isInteger(id) || id <= 0) {
      return Response.json(
        { error: "Invalid product ID." },
        { status: 400 }
      );
    }

    try {
      const result = await env.DB
        .prepare("DELETE FROM products WHERE id = ?")
        .bind(id)
        .run();

      if (!result.meta.changes) {
        return Response.json(
          { error: "Product not found." },
          { status: 404 }
        );
      }

      return Response.json({ success: true });
    } catch {
      return Response.json(
        { error: "Could not delete product." },
        { status: 500 }
      );
    }
  }

  try {
    const product = await request.json();

    if (
      typeof product.name !== "string" ||
      !product.name.trim() ||
      typeof product.category !== "string" ||
      !product.category.trim()
    ) {
      return Response.json(
        { error: "Product name and category are required." },
        { status: 400 }
      );
    }

    const values = [
      product.name.trim(),
      product.category.trim(),
      typeof product.description === "string" ? product.description : "",
      typeof product.price === "string" ? product.price : "",
      typeof product.image === "string" ? product.image : ""
    ];

    if (method === "PUT") {
      const id = Number(product.id);

      if (!Number.isInteger(id) || id <= 0) {
        return Response.json(
          { error: "Invalid product ID." },
          { status: 400 }
        );
      }

      const result = await env.DB.prepare(
        `UPDATE products
         SET name = ?, category = ?, description = ?, price = ?, image = ?
         WHERE id = ?`
      ).bind(...values, id).run();

      if (!result.meta.changes) {
        return Response.json(
          { error: "Product not found." },
          { status: 404 }
        );
      }

      return Response.json({ success: true });
    }

    await env.DB.prepare(
      `INSERT INTO products
       (name, category, description, price, image)
       VALUES (?, ?, ?, ?, ?)`
    ).bind(...values).run();

    return Response.json({ success: true });
  } catch {
    return Response.json(
      { error: "Could not save product." },
      { status: 500 }
    );
  }
}
