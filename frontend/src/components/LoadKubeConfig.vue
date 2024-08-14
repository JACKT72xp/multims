<template>
  <div class="load-kube-config">
    <h1>Load Kube Config</h1>
    <button @click="loadKubeConfig">Load ~/.kube/config</button>
  </div>
</template>

<script setup>
const loadKubeConfig = async () => {
  try {
    const response = await fetch('/api/load-kube-config', {
      method: 'POST',
    });
    const data = await response.json();
    if (data.success) {
      alert('Kube config loaded successfully');
      // Navigate to select cluster view
      router.push('/select-cluster');
    } else {
      alert('Failed to load kube config');
    }
  } catch (error) {
    console.error('Error loading kube config:', error);
  }
};
</script>

<style scoped>
.load-kube-config {
  padding: 20px;
  text-align: center;
}
</style>
