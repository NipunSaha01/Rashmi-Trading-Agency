export async function onRequest(context) {
  const { request, env } = context;
  const method = request.method;

  // GET: Display all products
  if (method === "GET") {
    const { results } = await env.DB
      .prepare("SELECT * FROM products ORDER BY id DESC")
      .all();

    return Response.json(results);
  }

  // Require the admin password for changes
  if (["POST", "PUT", "DELETE"].includes(method)) {
    const password = request.headers.get("X-Admin-Password");

    if (!env.ADMIN_PASSWORD || password !== env.ADMIN_PASSWORD) {
      return Response.json(
        { error: "Incorrect admin password." },
        { status: 401 }
      );
    }

    // DELETE: Remove a product
    if (method === "DELETE") {
      const id = Number(new URL(request.url).searchParams.get("id"));

      if (!Number.isInteger(id) || id <= 0) {
        return Response.json(
          { error: "Invalid product ID." },
          { status: 400 }
        );
      }

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
        product.description || "",
        product.price || "",
        product.image || ""
      ];

      // PUT: Update an existing product
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
           SET name = ?, category = ?, description = ?,
               price = ?, image = ?
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

      // POST: Add a new product
      await env.DB.prepare(
        `INSERT INTO products
         (name, category, description, price, image)
         VALUES (?, ?, ?, ?, ?)`
      ).bind(...values).run();

      return Response.json({ success: true });
    } catch {
      return Response.json(
        { error: "Could not save the product." },
        { status: 500 }
      );
    }
  }

  return new Response("Method not allowed", {
    status: 405,
    headers: { Allow: "GET, POST, PUT, DELETE" }
  });
      }
