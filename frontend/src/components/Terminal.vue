<template>
  <div class="terminal">
    <div class="output" ref="outputContainer">
      <span v-html="output"></span>
      <span class="prompt">multims_</span><span class="blinking-cursor">|</span>
    </div>
    <div class="input-container">
      <input
        v-model="command"
        @keyup.enter="sendCommand"
        type="text"
        placeholder="Enter command here"
        class="command-input"
      />
      <button @click="sendCommand">Send</button>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, nextTick } from 'vue';

const output = ref('');
const command = ref('');
let socket = null;
const outputContainer = ref(null);

const connectWebSocket = () => {
  socket = new WebSocket(`ws://${window.location.hostname}:9000/ws`);

  socket.addEventListener('open', () => {
    console.log('WebSocket connection established');
  });

  socket.addEventListener('close', () => {
    console.log('WebSocket connection closed');
  });

  socket.addEventListener('message', async (event) => {
    output.value += event.data + '\n';
    await nextTick(); // Esperar a que el DOM se actualice
    scrollToBottom(); // Desplazar hacia abajo después de actualizar el DOM
  });

  socket.addEventListener('error', (error) => {
    console.error('WebSocket error:', error);
  });
};

const sendCommand = () => {
  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.send(command.value);
    output.value += `multims_ ${command.value}\n`; // Agregar el comando ingresado al output
    command.value = ''; // Clear the input after sending
    nextTick(() => {
      scrollToBottom(); // Desplazar hacia abajo después de actualizar el DOM
    });
  } else {
    console.error('WebSocket is not connected');
  }
};

const scrollToBottom = () => {
  if (outputContainer.value) {
    outputContainer.value.scrollTop = outputContainer.value.scrollHeight;
  }
};

onMounted(() => {
  connectWebSocket();
});
</script>

<style scoped>
.terminal {
  display: flex;
  flex-direction: column;
  height: 100%;
}

.output {
  flex: 1;
  padding: 10px;
  background-color: black;
  color: white;
  overflow-y: auto;
  white-space: pre-wrap;
  max-height: 80vh; /* Limitar la altura máxima del área de salida */
}

.input-container {
  display: flex;
}

input[type="text"].command-input {
  flex: 1;
  padding: 10px;
  border: none;
  border-top: 1px solid #ccc;
  color: white; /* Color del texto en el campo de entrada */
  background-color: #333; /* Fondo del campo de entrada */
}

button {
  padding: 10px;
  border: none;
  background-color: #007bff;
  color: white;
  cursor: pointer;
}

button:hover {
  background-color: #0056b3;
}

.prompt {
  color: #00ff00; /* Color del prompt */
}

.blinking-cursor {
  animation: blink 1s step-start infinite;
  color: #00ff00; /* Color del cursor titilante */
}

@keyframes blink {
  50% {
    opacity: 0;
  }
}
</style>
