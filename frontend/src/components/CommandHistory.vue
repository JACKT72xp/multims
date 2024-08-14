<template>
  <div id="history-container">
    <h3>Command History</h3>
    <ul id="command-history">
      <li v-for="(command, index) in commands" :key="index">{{ command }}</li>
    </ul>
  </div>
</template>

<script setup>
import { ref } from 'vue'

const commands = ref([])

// Add logic to update commands history
</script>

<style scoped>
#history-container {
  width: 300px;
  background: #f8f9fa;
  padding: 1rem;
}

#command-history {
  list-style: none;
  padding: 0;
  margin: 0;
}

#command-history li {
  padding: 0.5rem 0;
  border-bottom: 1px solid #ddd;
}
</style>
