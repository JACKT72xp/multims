<template>
    <div class="execution-view">
      <!-- Consolas superiores -->
      <div class="top-consoles">
        <div class="console" ref="console1">
          <h3>Console 1</h3>
          <textarea v-model="output1" readonly></textarea>
          <input v-model="input1" @keyup.enter="executeCommand1" placeholder="Enter command for Console 1" />
        </div>
        <div class="console" ref="console2">
          <h3>Console 2</h3>
          <textarea v-model="output2" readonly></textarea>
          <input v-model="input2" @keyup.enter="executeCommand2" placeholder="Enter command for Console 2" />
        </div>
      </div>
      <!-- Consola inferior -->
      <div class="bottom-console">
        <h3>Console 3</h3>
        <textarea v-model="output3" readonly></textarea>
        <input v-model="input3" @keyup.enter="executeCommand3" placeholder="Enter command for Console 3" />
      </div>
    </div>
  </template>
  
  <script setup>
  import { ref } from 'vue';
  
  const output1 = ref('');
  const output2 = ref('');
  const output3 = ref('');
  
  const input1 = ref('');
  const input2 = ref('');
  const input3 = ref('');
  
  // Funciones para ejecutar comandos en cada consola
  const executeCommand1 = async () => {
    output1.value += `$ ${input1.value}\n`;
    // Lógica para ejecutar el comando en el backend
    input1.value = ''; // Limpia el input después de ejecutar el comando
  };
  
  const executeCommand2 = async () => {
    output2.value += `$ ${input2.value}\n`;
    // Lógica para ejecutar el comando en el backend
    input2.value = ''; // Limpia el input después de ejecutar el comando
  };
  
  const executeCommand3 = async () => {
    output3.value += `$ ${input3.value}\n`;
    // Lógica para ejecutar el comando en el backend
    input3.value = ''; // Limpia el input después de ejecutar el comando
  };
  </script>
  
  <style scoped>
  .execution-view {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }
  
  .top-consoles {
    display: flex;
    flex: 1;
    padding: 10px;
  }
  
  .console {
    flex: 1;
    margin: 5px;
    background: #1f1f1f;
    color: white;
    padding: 10px;
    border-radius: 5px;
    display: flex;
    flex-direction: column;
  }
  
  .console textarea {
    flex: 1;
    background: #2d2d2d;
    color: white;
    border: none;
    padding: 10px;
    border-radius: 5px;
    margin-bottom: 10px;
  }
  
  .console input {
    background: #2d2d2d;
    color: white;
    border: none;
    padding: 10px;
    border-radius: 5px;
  }
  
  .bottom-console {
    flex: 1;
    margin: 5px;
    background: #1f1f1f;
    color: white;
    padding: 10px;
    border-radius: 5px;
    display: flex;
    flex-direction: column;
  }
  
  .bottom-console textarea {
    flex: 1;
    background: #2d2d2d;
    color: white;
    border: none;
    padding: 10px;
    border-radius: 5px;
    margin-bottom: 10px;
  }
  
  .bottom-console input {
    background: #2d2d2d;
    color: white;
    border: none;
    padding: 10px;
    border-radius: 5px;
  }
  </style>