console.log("Auditor-AI: Sistema cargado correctamente");

/**
 * Función central para manejar envíos desde el chat.
 * Llama a esta función desde tu HTML usando: onclick="handleSend()"
 */
async function handleSend() {
    const inputField = document.getElementById('chat-input');
    const chatOutput = document.getElementById('chat-output');
    const input = inputField.value;

    if (!input) return;

    // Mostrar mensaje del usuario
    chatOutput.innerHTML += `<p><b>Tú:</b> ${input}</p>`;
    inputField.value = '';

    // Determinar si es URL o ruta (simple detección)
    const isUrl = input.startsWith('http');
    const endpoint = isUrl ? '/api/analyze/url' : '/api/analyze/path';
    const payload = isUrl ? { url: input } : { path: input };

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) throw new Error("Error en servidor: " + response.statusText);

        const reader = response.body.getReader();
        const decoder = new TextDecoder();

        chatOutput.innerHTML += `<p><b>Auditor-AI:</b> <span class="streaming-text"></span></p>`;
        const streamDisplay = chatOutput.lastElementChild.querySelector('.streaming-text');

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            const chunk = decoder.decode(value);
            // Procesamiento de datos en stream (SSE)
            const lines = chunk.split('\n\n');
            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    try {
                        const data = JSON.parse(line.replace('data: ', ''));
                        if (data.type === 'chunk') streamDisplay.innerText += data.content;
                        if (data.type === 'error') streamDisplay.innerHTML += `<br><b style="color:red">Error: ${data.content}</b>`;
                    } catch (e) { /* Ignorar errores de parseo parcial */ }
                }
            }
        }
    } catch (err) {
        chatOutput.innerHTML += `<p style="color:red">Error: ${err.message}</p>`;
    }
}