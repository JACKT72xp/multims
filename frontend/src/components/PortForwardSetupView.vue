<template>
  <div class="port-forward-setup">
    <div class="card">
      <h2 class="title">Port Forward Setup</h2>
      <div v-if="error" class="alert alert-error">
        {{ error }}
      </div>
      <KubeConfigSetup v-if="!configLoaded" @configLoaded="handleConfigLoaded" />
      <div v-else>
        <SelectCluster v-if="!clusterSelected" :clusters="clusters" @selected="handleClusterSelected" />
        <ForwardSessions v-else :cluster="selectedCluster" />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import KubeConfigSetup from '../components/KubeConfigSetup.vue';
import SelectCluster from '../components/SelectCluster.vue';
import ForwardSessions from '../components/ForwardSessions.vue';

const error = ref('');
const configLoaded = ref(false);
const clusterSelected = ref(false);
const clusters = ref([]);
const selectedCluster = ref(null);

const handleConfigLoaded = (loadedClusters) => {
  clusters.value = loadedClusters;
  configLoaded.value = true;
};

const handleClusterSelected = (cluster) => {
  selectedCluster.value = cluster;
  clusterSelected.value = true;
};
</script>

<style scoped>
:root {
  --color-primary: #0A84FF;
  --color-secondary: #FF9500;
  --color-dark: #1C1C1E;
  --color-light: #F2F2F7;
  --background-gradient: linear-gradient(135deg, #1f2937, #111827);
}

body {
  background: var(--background-gradient);
  color: var(--color-light);
  font-family: 'Inter', sans-serif;
}

.port-forward-setup {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100vh;
}

.card {
  background: #34495e;
  padding: 2rem;
  border-radius: 1rem;
  box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
  text-align: center;
  max-width: 800px;
  width: 100%;
}


.title {
  font-size: 2rem;
  font-weight: bold;
  margin-bottom: 1rem;
}

.alert {
  padding: 1rem;
  margin-bottom: 1rem;
  border: 1px solid transparent;
  border-radius: 0.25rem;
}

.alert-warning {
  color: #856404;
  background-color: #fff3cd;
  border-color: #ffeeba;
}

.alert-error {
  color: #f44336;
  background-color: #fddede;
  border-color: #f44336;
}
</style>
