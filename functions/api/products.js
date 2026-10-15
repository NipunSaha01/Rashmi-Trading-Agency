export async function onRequest(context) {
  const { request, env } = context;

  // Public visitors can view products
  if (request.method === "GET") {
    const { results } = await env.DB
      .prepare("SELECT * FROM products ORDER BY id DESC")
      .all();

    return Response.json(results);
  }

  // Only authorized users can add products
  if (request.method === "POST") {
    const password = request.headers.get("X-Admin-Password");

    if (!env.ADMIN_PASSWORD || password !== env.ADMIN_PASSWORD) {
      return Response.json(
        { error: "Unauthorized. Incorrect password." },
        { status: 401 }
      );
    }

    try {
      const product = await request.json();

      if (!product.name || !product.category) {
        return Response.json(
          { error: "Product name and category are required." },
          { status: 400 }
        );
      }

      await env.DB.prepare(
        `INSERT INTO products
        (name, category, description, price, image)
        VALUES (?, ?, ?, ?, ?)`
      ).bind(
        product.name,
        product.category,
        product.description || "",
        product.price || "",
        product.image || ""
      ).run();

      return Response.json({ success: true });
    } catch {
      return Response.json(
        { error: "Could not add product." },
        { status: 500 }
      );
    }
  }

  return new Response("Method not allowed", {
    status: 405,
    headers: { Allow: "GET, POST" }
  });
          }
