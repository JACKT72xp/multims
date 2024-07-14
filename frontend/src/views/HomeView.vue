<template>
  <div class="bg-gradient-to-r from-gray-900 via-gray-800 to-gray-900 min-h-screen text-gray-300 pl-72 pt-24 relative">
    <div class="container mx-auto py-16 px-6">
      <h1 class="text-6xl font-extrabold mb-6 text-white leading-tight">Welcome to Multims Console</h1>
      <p class="mb-8 text-2xl text-gray-400">The ultimate CLI tool for Kubernetes developers.</p>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div class="bg-white p-6 rounded-lg shadow-xl hover:shadow-2xl transition-shadow duration-300">
          <h2 class="text-3xl font-bold mb-2 text-primary">Easy Initialization</h2>
          <p>Quickly set up your project with <code class="text-secondary">multims init</code>.</p>
        </div>
        <div class="bg-white p-6 rounded-lg shadow-xl hover:shadow-2xl transition-shadow duration-300">
          <h2 class="text-3xl font-bold mb-2 text-primary">Live Development</h2>
          <p>Use <code class="text-secondary">multims run</code> to develop in real-time.</p>
        </div>
        <div class="bg-white p-6 rounded-lg shadow-xl hover:shadow-2xl transition-shadow duration-300">
          <h2 class="text-3xl font-bold mb-2 text-primary">Seamless Integration</h2>
          <p>Easily integrates with your existing Kubernetes setup.</p>
        </div>
      </div>
    </div>
    <div class="absolute top-8 right-8">
      <img src="/kubernetes-icon.svg" alt="Kubernetes" class="w-12 h-12 animate-spin-slow">
    </div>
  </div>
</template>

<script setup lang="ts">
</script>

<style scoped>
</style>
