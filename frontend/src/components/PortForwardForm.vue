<template>
  <div class="port-forward-form p-4">
    <h2 class="text-xl font-bold mb-4">Port Forward Setup</h2>
    <form @submit.prevent="setupPortForward">
      <div class="mb-4">
        <label for="namespace" class="block mb-2 font-bold">Namespace:</label>
        <input type="text" v-model="namespace" id="namespace" required class="w-full p-2 border rounded" />
      </div>
      <div class="mb-4">
        <label for="service" class="block mb-2 font-bold">Service:</label>
        <input type="text" v-model="service" id="service" required class="w-full p-2 border rounded" />
      </div>
      <div class="mb-4">
        <label for="port" class="block mb-2 font-bold">Port:</label>
        <input type="text" v-model="port" id="port" required class="w-full p-2 border rounded" />
      </div>
      <button type="submit" class="bg-blue-500 text-white p-2 rounded">Setup Port Forward</button>
    </form>
  </div>
</template>

<script setup>
import { ref } from 'vue';

const namespace = ref('');
const service = ref('');
const port = ref('');

const setupPortForward = async () => {
  try {
    const response = await fetch('/api/port-forward', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ namespace: namespace.value, service: service.value, port: port.value }),
    });
    const data = await response.json();
    if (data.success) {
      alert('Port forwarding setup successfully');
    } else {
      alert('Failed to setup port forwarding');
    }
  } catch (error) {
    console.error('Error setting up port forwarding:', error);
  }
};
</script>

<style scoped>
.port-forward-form {
  padding: 20px;
}

.port-forward-form form {
  display: flex;
  flex-direction: column;
}

.port-forward-form form div {
  margin-bottom: 10px;
}

.port-forward-form form label {
  margin-bottom: 5px;
  font-weight: bold;
}

.port-forward-form form input {
  padding: 10px;
  border: 1px solid #ccc;
  border-radius: 4px;
}

.port-forward-form form button {
  padding: 10px;
  background-color: #007bff;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.port-forward-form form button:hover {
  background-color: #0056b3;
}
</style>
