<template>
  <nav class="bg-gray-800 p-4 flex justify-between items-center text-white">
    <div class="text-lg font-bold">Multims Console</div>
    <div class="flex space-x-4">
      <RouterLink to="/" class="hover:underline">Home</RouterLink>
      <RouterLink to="/console" class="hover:underline">Console</RouterLink>
      <RouterLink to="/port-forward" class="hover:underline">Port Forward</RouterLink>
      <RouterLink to="/settings" class="hover:underline">Settings</RouterLink>
      <RouterLink to="/about" class="hover:underline">About</RouterLink>
    </div>
  </nav>
</template>

<script setup>
import { RouterLink } from 'vue-router';
</script>

<style scoped>
nav {
  background-color: #1a202c;
}
a {
  color: white;
  text-decoration: none;
}
a:hover {
  text-decoration: underline;
}
</style>
