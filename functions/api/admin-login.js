export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { Allow: "POST" }
    });
  }

  if (!env.ADMIN_PASSWORD) {
    return Response.json(
      { error: "Admin password is not configured." },
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

    return Response.json({ success: true });
  } catch {
    return Response.json(
      { error: "Invalid request." },
      { status: 400 }
    );
  }
}
