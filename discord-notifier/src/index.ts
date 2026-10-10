import express from "express";

const app = express();

app.use(express.json());

app.post("/alertas", async (req, res) => {
  const { servico, chave, chaveMascarada } = req.body;
  const chaveFinal = typeof chave === "string" ? chave : chaveMascarada;

  if (typeof servico !== "string" || typeof chaveFinal !== "string") {
    res.status(400).json({ erro: "Dados inválidos." });
    return;
  }

  try {
    await enviarMensagem(
      `Possível exposição confirmada\nServiço: ${servico}\nChave: ${chaveFinal}`,
    );

    res.sendStatus(204);
  } catch (error) {
    console.error("Falha ao enviar o alerta:", error);

    res.status(502).json({
      erro: "Falha ao enviar o alerta.",
    });
  }
});

async function enviarMensagem(mensagem: string): Promise<void> {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;

  if (!webhookUrl) {
    throw new Error("Falta configurar DISCORD_WEBHOOK_URL.");
  }

  const resposta = await fetch(webhookUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      content: mensagem,
      allowed_mentions: { parse: [] },
    }),
  });

  if (!resposta.ok) {
    throw new Error(`O Discord respondeu com o erro ${resposta.status}.`);
  }

  console.log("Mensagem enviada!");
}

app.listen(3000, "0.0.0.0", () => {
  console.log("Servidor à escuta na porta 3000.");
});
