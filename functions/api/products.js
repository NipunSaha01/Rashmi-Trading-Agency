export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "GET") {
    const { results } = await env.DB
      .prepare("SELECT * FROM products ORDER BY id DESC")
      .all();

    return Response.json(results);
  }

  if (request.method === "POST") {
    const product = await request.json();

    await env.DB.prepare(
      "INSERT INTO products (name, category, description, price, image) VALUES (?, ?, ?, ?, ?)"
    ).bind(
      product.name,
      product.category,
      product.description || "",
      product.price || "",
      product.image || ""
    ).run();

    return Response.json({ success: true });
  }

  return new Response("Method not allowed", { status: 405 });
}
